"""
Entidades del contexto de ingesta.

Proposito
    Modelar el trabajo de escaneo como una entidad persistente con maquina
    de estados explicita, en lugar del estado en memoria del sistema de
    referencia (hallazgo H2).

Dependencias
    Solo `shared`.

Decision de diseño
    Las transiciones viven en la entidad (`marcar_en_ejecucion`,
    `completar`, `cancelar`) y validan el estado de origen. Si el cambio
    de estado fuera asignacion libre de un atributo, un reintento podria
    "completar" un trabajo ya cancelado y la auditoria dejaria de ser
    fiable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import StrEnum
from uuid import UUID

from mailauto.shared.errors import ConflictoDeEstado, ErrorDeValidacion
from mailauto.shared.types import ahora_utc, uuid7


class EstadoDeTrabajo(StrEnum):
    EN_COLA = "queued"
    EN_EJECUCION = "running"
    COMPLETADO = "succeeded"
    COMPLETADO_CON_ERRORES = "partial"
    FALLIDO = "failed"
    CANCELADO = "cancelled"

    @property
    def es_terminal(self) -> bool:
        return self in (
            EstadoDeTrabajo.COMPLETADO,
            EstadoDeTrabajo.COMPLETADO_CON_ERRORES,
            EstadoDeTrabajo.FALLIDO,
            EstadoDeTrabajo.CANCELADO,
        )


class FaseDeEscaneo(StrEnum):
    """Fase granular, para que la barra de progreso diga algo util."""

    EN_ESPERA = "waiting"
    AUTENTICANDO = "authenticating"
    LISTANDO_CORREOS = "listing"
    DESCARGANDO_ADJUNTOS = "downloading"
    FINALIZANDO = "finalizing"
    TERMINADO = "done"


class EtapaDeError(StrEnum):
    LISTADO = "fetch"
    DESCARGA = "download"
    VALIDACION = "validate"
    PERSISTENCIA = "persist"


@dataclass(frozen=True, slots=True)
class ParametrosDeEscaneo:
    """
    Parametros de un escaneo, validados al construirse.

    El rango de fechas tiene tope porque un escaneo sin acotar sobre un
    buzon de diez años agota la cuota del proveedor y bloquea al resto de
    tenants que comparten el worker.
    """

    desde: date | None = None
    hasta: date | None = None
    limite_de_mensajes: int = 100
    carpeta: str = "INBOX"

    def validar(self, *, maximo_mensajes: int, maximo_dias: int) -> None:
        if self.limite_de_mensajes < 1 or self.limite_de_mensajes > maximo_mensajes:
            raise ErrorDeValidacion(
                f"El limite debe estar entre 1 y {maximo_mensajes}.",
                campo="limite_de_mensajes",
            )
        if self.desde and self.hasta:
            if self.desde > self.hasta:
                raise ErrorDeValidacion(
                    "La fecha inicial no puede ser posterior a la final.", campo="desde"
                )
            if (self.hasta - self.desde).days > maximo_dias:
                raise ErrorDeValidacion(
                    f"El rango no puede superar {maximo_dias} dias.", campo="hasta"
                )


@dataclass(slots=True)
class ContadoresDeEscaneo:
    """Metricas acumuladas durante la ejecucion."""

    mensajes_revisados: int = 0
    mensajes_con_adjuntos: int = 0
    adjuntos_descargados: int = 0
    adjuntos_rechazados: int = 0
    adjuntos_duplicados: int = 0
    errores: int = 0

    def como_dict(self) -> dict[str, int]:
        return {
            "mensajes_revisados": self.mensajes_revisados,
            "mensajes_con_adjuntos": self.mensajes_con_adjuntos,
            "adjuntos_descargados": self.adjuntos_descargados,
            "adjuntos_rechazados": self.adjuntos_rechazados,
            "adjuntos_duplicados": self.adjuntos_duplicados,
            "errores": self.errores,
        }

    @classmethod
    def desde_dict(cls, datos: dict[str, int] | None) -> ContadoresDeEscaneo:
        return cls(**datos) if datos else cls()


@dataclass(slots=True)
class TrabajoDeEscaneo:
    """
    Una ejecucion del pipeline de ingesta.

    Persistente desde que se encola: sobrevive al reinicio del worker, que
    es justamente lo que el sistema de referencia no hacia.
    """

    id: UUID = field(default_factory=uuid7)
    tenant_id: UUID = field(default_factory=uuid7)
    solicitado_por: UUID = field(default_factory=uuid7)
    conexion_id: UUID = field(default_factory=uuid7)
    estado: EstadoDeTrabajo = EstadoDeTrabajo.EN_COLA
    fase: FaseDeEscaneo = FaseDeEscaneo.EN_ESPERA
    parametros: ParametrosDeEscaneo = field(default_factory=ParametrosDeEscaneo)
    contadores: ContadoresDeEscaneo = field(default_factory=ContadoresDeEscaneo)
    progreso_porcentaje: int = 0
    clave_de_idempotencia: str | None = None
    intento: int = 0
    codigo_de_error: str | None = None
    mensaje_de_error: str | None = None
    encolado_en: datetime = field(default_factory=ahora_utc)
    iniciado_en: datetime | None = None
    finalizado_en: datetime | None = None

    # ── Transiciones ─────────────────────────────────────────────────

    def marcar_en_ejecucion(self) -> None:
        if self.estado is not EstadoDeTrabajo.EN_COLA:
            raise ConflictoDeEstado(
                f"No se puede iniciar un trabajo en estado '{self.estado.value}'."
            )
        self.estado = EstadoDeTrabajo.EN_EJECUCION
        self.fase = FaseDeEscaneo.AUTENTICANDO
        self.iniciado_en = ahora_utc()
        self.intento += 1

    def avanzar(self, fase: FaseDeEscaneo, porcentaje: int) -> None:
        """
        Actualiza la fase. El porcentaje nunca retrocede: una barra que
        baja destruye la confianza del usuario en todo el indicador.
        """
        self.fase = fase
        self.progreso_porcentaje = max(self.progreso_porcentaje, min(100, max(0, porcentaje)))

    def completar(self) -> None:
        if self.estado is not EstadoDeTrabajo.EN_EJECUCION:
            raise ConflictoDeEstado("Solo un trabajo en ejecucion puede completarse.")
        self.estado = (
            EstadoDeTrabajo.COMPLETADO_CON_ERRORES
            if self.contadores.errores > 0
            else EstadoDeTrabajo.COMPLETADO
        )
        self.fase = FaseDeEscaneo.TERMINADO
        self.progreso_porcentaje = 100
        self.finalizado_en = ahora_utc()

    def fallar(self, *, codigo: str, mensaje: str) -> None:
        if self.estado.es_terminal:
            raise ConflictoDeEstado("El trabajo ya finalizo.")
        self.estado = EstadoDeTrabajo.FALLIDO
        self.fase = FaseDeEscaneo.TERMINADO
        self.codigo_de_error = codigo
        self.mensaje_de_error = mensaje
        self.finalizado_en = ahora_utc()

    def cancelar(self) -> None:
        if self.estado.es_terminal:
            raise ConflictoDeEstado("El trabajo ya finalizo; no puede cancelarse.")
        self.estado = EstadoDeTrabajo.CANCELADO
        self.fase = FaseDeEscaneo.TERMINADO
        self.finalizado_en = ahora_utc()

    @property
    def esta_activo(self) -> bool:
        return not self.estado.es_terminal


@dataclass(slots=True)
class MensajeDeCorreo:
    """
    Correo procesado. `id_del_proveedor` es la clave de idempotencia: su
    indice unico por tenant impide reprocesar lo mismo en dos escaneos.
    """

    id: UUID = field(default_factory=uuid7)
    tenant_id: UUID = field(default_factory=uuid7)
    trabajo_id: UUID = field(default_factory=uuid7)
    proveedor: str = ""
    id_del_proveedor: str = ""
    remitente: str = ""
    asunto: str = ""
    recibido_en: datetime | None = None


@dataclass(slots=True)
class Adjunto:
    """
    Adjunto descargado, validado y almacenado.

    `nombre_original` se conserva solo para mostrarlo. La ruta real es
    `clave_de_almacenamiento`, un UUID: asi un nombre como
    `../../etc/passwd` no puede influir en donde se escribe el fichero.
    """

    id: UUID = field(default_factory=uuid7)
    tenant_id: UUID = field(default_factory=uuid7)
    mensaje_id: UUID = field(default_factory=uuid7)
    nombre_original: str = ""
    clave_de_almacenamiento: str = ""
    tipo_mime: str = ""
    tamano_bytes: int = 0
    sha256: str = ""
    estado_antivirus: str = "skipped"


@dataclass(slots=True)
class ErrorDeProcesamiento:
    """Error registrado durante la ingesta, para la vista de diagnostico."""

    id: UUID = field(default_factory=uuid7)
    tenant_id: UUID = field(default_factory=uuid7)
    trabajo_id: UUID = field(default_factory=uuid7)
    etapa: EtapaDeError = EtapaDeError.DESCARGA
    codigo: str = ""
    mensaje: str = ""
    contexto: dict[str, str] = field(default_factory=dict)
    reintentable: bool = False
    ocurrido_en: datetime = field(default_factory=ahora_utc)
