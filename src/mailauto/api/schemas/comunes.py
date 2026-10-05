"""
DTOs de entrada y salida de la API.

Proposito
    Mantener separado el contrato publico de las entidades de dominio,
    para poder cambiar el modelo interno sin romper a los clientes y, al
    reves, no verse obligado a exponer todo lo que una entidad contiene.

Dependencias
    Pydantic v2.

Decision de diseño
    La salida se construye con fabricas explicitas (`desde_dominio`) en
    lugar de serializar la entidad. Asi cada campo que llega al cliente es
    una decision consciente: un atributo nuevo en el dominio no se filtra
    solo a la API.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class Respuesta(BaseModel, Generic[T]):
    """Envoltura uniforme de exito."""

    status: str = "ok"
    data: T
    meta: dict[str, Any] | None = None


class MetaDePagina(BaseModel):
    cursor: str | None = None
    hay_mas: bool = False


# ── Identidad ────────────────────────────────────────────────────────


class PerfilSalida(BaseModel):
    user_id: UUID
    tenant_id: UUID
    email: str
    rol: str
    permisos: list[str]


# ── Buzones ──────────────────────────────────────────────────────────


class IniciarVinculacionEntrada(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proveedor: Annotated[str, Field(pattern="^(google|microsoft)$")]
    # Se valida contra la allowlist del servidor; el patron solo descarta
    # lo obviamente malformado antes de llegar al caso de uso.
    redirect_uri: Annotated[str, Field(min_length=8, max_length=512)]


class UrlDeAutorizacionSalida(BaseModel):
    url_de_autorizacion: str


class CallbackEntrada(BaseModel):
    model_config = ConfigDict(extra="forbid")

    codigo: Annotated[str, Field(min_length=1, max_length=2048)]
    state: Annotated[str, Field(min_length=16, max_length=256)]


class BuzonSalida(BaseModel):
    id: UUID
    proveedor: str
    correo_de_la_cuenta: str
    estado: str
    expira_en: datetime
    verificada_en: datetime | None

    @classmethod
    def desde_dominio(cls, conexion: Any) -> BuzonSalida:
        # No se exponen ni los tokens ni los alcances concedidos: lo
        # primero es la credencial y lo segundo revela la configuracion
        # OAuth de la aplicacion.
        return cls(
            id=conexion.id,
            proveedor=conexion.proveedor.value,
            correo_de_la_cuenta=conexion.correo_de_la_cuenta,
            estado=conexion.estado.value,
            expira_en=conexion.expira_en,
            verificada_en=conexion.verificada_en,
        )


# ── Escaneos ─────────────────────────────────────────────────────────


class IniciarEscaneoEntrada(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conexion_id: UUID
    desde: date | None = None
    hasta: date | None = None
    limite_de_mensajes: Annotated[int, Field(ge=1, le=50_000)] = 100
    carpeta: Annotated[str, Field(max_length=120, pattern=r"^[\w\-/ ]+$")] = "INBOX"


class ContadoresSalida(BaseModel):
    mensajes_revisados: int = 0
    mensajes_con_adjuntos: int = 0
    adjuntos_descargados: int = 0
    adjuntos_rechazados: int = 0
    adjuntos_duplicados: int = 0
    errores: int = 0


class EscaneoSalida(BaseModel):
    id: UUID
    estado: str
    fase: str
    progreso_porcentaje: int
    contadores: ContadoresSalida
    codigo_de_error: str | None
    mensaje_de_error: str | None
    encolado_en: datetime
    iniciado_en: datetime | None
    finalizado_en: datetime | None

    @classmethod
    def desde_dominio(cls, trabajo: Any) -> EscaneoSalida:
        return cls(
            id=trabajo.id,
            estado=trabajo.estado.value,
            fase=trabajo.fase.value,
            progreso_porcentaje=trabajo.progreso_porcentaje,
            contadores=ContadoresSalida(**trabajo.contadores.como_dict()),
            codigo_de_error=trabajo.codigo_de_error,
            mensaje_de_error=trabajo.mensaje_de_error,
            encolado_en=trabajo.encolado_en,
            iniciado_en=trabajo.iniciado_en,
            finalizado_en=trabajo.finalizado_en,
        )


# ── Errores y auditoria ──────────────────────────────────────────────


class ErrorDeProcesamientoSalida(BaseModel):
    id: UUID
    trabajo_id: UUID
    etapa: str
    codigo: str
    mensaje: str
    reintentable: bool
    ocurrido_en: datetime

    @classmethod
    def desde_dominio(cls, error: Any) -> ErrorDeProcesamientoSalida:
        # `contexto` queda fuera: puede contener nombres de archivo y
        # otros datos del correo del usuario.
        return cls(
            id=error.id,
            trabajo_id=error.trabajo_id,
            etapa=error.etapa.value,
            codigo=error.codigo,
            mensaje=error.mensaje,
            reintentable=error.reintentable,
            ocurrido_en=error.ocurrido_en,
        )


class EntradaDeAuditoriaSalida(BaseModel):
    id: int | None
    accion: str
    tipo_de_recurso: str
    recurso_id: UUID | None
    actor_id: UUID | None
    ocurrido_en: datetime

    @classmethod
    def desde_dominio(cls, entrada: Any) -> EntradaDeAuditoriaSalida:
        return cls(
            id=entrada.id,
            accion=entrada.accion.value,
            tipo_de_recurso=entrada.tipo_de_recurso,
            recurso_id=entrada.recurso_id,
            actor_id=entrada.actor_id,
            ocurrido_en=entrada.ocurrido_en,
        )


# ── Salud ────────────────────────────────────────────────────────────


class SaludSalida(BaseModel):
    estado: str
    componentes: dict[str, bool] | None = None
