"""
Orquestador de la extraccion.

Proposito
    Sacar los datos de un adjunto probando los motores de lectura por
    orden de costo y parando en cuanto el resultado es suficiente.

Flujo
    adjunto -> motor 1 (texto nativo, gratis)
            -> ¿suficiente? -> si: fin
            -> motor 2 (tablas, gratis)
            -> motor 3 (OCR local, gratis)
            -> motor 4 (vision IA, de pago)
            -> combinar lo mejor de cada uno -> clasificar -> persistir

Dependencias
    Solo puertos del dominio. Se testea entero con dobles, sin abrir un
    solo PDF ni gastar un centimo.

Decisiones de diseño
    1. Se para en cuanto los campos imprescindibles estan presentes y
       son fiables. La diferencia de coste entre pararse en el primer
       motor y llegar al cuarto es de varios ordenes de magnitud, y en
       la mayoria de los documentos el primero ya basta.

    2. Aunque se llegue al final, se COMBINAN todos los resultados en
       vez de quedarse con el ultimo. Es habitual que el texto nativo
       lea el RUC perfecto y falle en un importe que esta dentro de una
       imagen incrustada, donde el OCR si acierta. Quedarse con un solo
       motor tiraria la mitad de lo que ya se leyo y se pago.

    3. El presupuesto de IA se comprueba ANTES de llamar, no despues.
       Un tenant que agoto su cupo degrada a los motores gratuitos en
       lugar de fallar: un resultado parcial que una persona puede
       corregir vale mas que ninguno.
"""

from __future__ import annotations

from collections.abc import Mapping
from uuid import UUID

from mailauto.modules.extraction.domain import policies
from mailauto.modules.extraction.domain.entities import (
    CampoExtraido,
    Completitud,
    Estrategia,
    RegistroTributario,
    ResultadoDeEstrategia,
)
from mailauto.modules.extraction.domain.ports import (
    DocumentoAExtraer,
    EstrategiaDeExtraccion,
    PerfilDeExtraccion,
    RepositorioDeRegistros,
)
from mailauto.shared.observability.logging import obtener_logger

logger = obtener_logger(__name__)


class ControlDePresupuesto:
    """
    Puerta de acceso a los motores de pago.

    Es una clase propia y no un parametro suelto porque la decision
    tiene matices (cupo por tenant, corte global, modo degradado) y
    conviene que esten en un sitio y no repartidas por el orquestador.
    """

    def __init__(self, *, ia_habilitada: bool, maximo_llamadas_por_trabajo: int) -> None:
        self._habilitada = ia_habilitada
        self._maximo = maximo_llamadas_por_trabajo
        self._consumidas: dict[UUID, int] = {}

    def permite_ia(self, trabajo_id: UUID) -> bool:
        if not self._habilitada:
            return False
        return self._consumidas.get(trabajo_id, 0) < self._maximo

    def registrar_llamada(self, trabajo_id: UUID) -> None:
        self._consumidas[trabajo_id] = self._consumidas.get(trabajo_id, 0) + 1

    def consumidas(self, trabajo_id: UUID) -> int:
        return self._consumidas.get(trabajo_id, 0)


class ExtraerDocumento:
    """Pipeline de extraccion de un adjunto."""

    def __init__(
        self,
        *,
        estrategias: list[EstrategiaDeExtraccion],
        perfil: PerfilDeExtraccion,
        repositorio: RepositorioDeRegistros,
        presupuesto: ControlDePresupuesto,
    ) -> None:
        # Se ordenan por costo al construir, no en cada ejecucion: el
        # orden es una propiedad del pipeline, no de cada documento.
        self._estrategias = sorted(estrategias, key=lambda e: e.costo_relativo)
        self._perfil = perfil
        self._repositorio = repositorio
        self._presupuesto = presupuesto

    async def ejecutar(self, documento: DocumentoAExtraer) -> RegistroTributario | None:
        """
        Extrae y persiste. Devuelve None si el adjunto ya se habia
        procesado o si ningun motor pudo abrirlo.
        """
        if await self._repositorio.existe_para_adjunto(documento.tenant_id, documento.adjunto_id):
            # Reentrega del job: el adjunto ya tiene registro. Volver a
            # extraer costaria lo mismo y produciria un duplicado.
            logger.info("adjunto_ya_extraido", adjunto_id=str(documento.adjunto_id))
            return None

        resultados = await self._recorrer_estrategias(documento)
        if not resultados:
            logger.warning("ningun_motor_admitio_el_documento", tipo=documento.tipo_mime)
            return None

        return await self._construir_y_guardar(documento, resultados)

    # ── Recorrido de motores ─────────────────────────────────────────

    async def _recorrer_estrategias(
        self, documento: DocumentoAExtraer
    ) -> list[ResultadoDeEstrategia]:
        resultados: list[ResultadoDeEstrategia] = []

        for estrategia in self._estrategias:
            if not estrategia.admite(documento):
                continue

            if estrategia.nombre is Estrategia.VISION_IA and not self._presupuesto.permite_ia(
                documento.trabajo_id
            ):
                logger.info("ia_omitida_por_presupuesto", trabajo_id=str(documento.trabajo_id))
                continue

            resultado = await estrategia.leer(documento, self._perfil)
            resultados.append(resultado)

            if estrategia.nombre is Estrategia.VISION_IA:
                self._presupuesto.registrar_llamada(documento.trabajo_id)

            if resultado.tuvo_exito and policies.es_suficiente_para_detenerse(resultado):
                # Los campos imprescindibles estan y son fiables: seguir
                # solo añadiria coste sin cambiar el resultado.
                logger.info(
                    "extraccion_suficiente",
                    estrategia=estrategia.nombre.value,
                    duracion_ms=resultado.duracion_ms,
                )
                break

        return resultados

    # ── Construccion del registro ────────────────────────────────────

    async def _construir_y_guardar(
        self, documento: DocumentoAExtraer, resultados: list[ResultadoDeEstrategia]
    ) -> RegistroTributario:
        campos = policies.combinar(resultados)
        completitud = policies.clasificar(campos)

        registro = self._perfil.a_registro(campos, documento)
        registro.completitud = completitud
        registro.estado_de_revision = policies.decidir_revision(completitud, campos)
        registro.duracion_ms = sum(r.duracion_ms for r in resultados)
        registro.estrategia_usada = self._estrategia_dominante(campos)

        guardado = await self._repositorio.guardar(documento.tenant_id, registro)

        logger.info(
            "registro_extraido",
            completitud=completitud.value,
            revision=registro.estado_de_revision.value,
            motores_usados=len(resultados),
            confianza=round(policies.confianza_global(campos), 3),
            campos_dudosos=registro.campos_dudosos(),
        )
        return guardado

    @staticmethod
    def _estrategia_dominante(
        campos: Mapping[str, CampoExtraido],
    ) -> Estrategia | None:
        """
        Motor que aporto mas campos al resultado final.

        Es la metrica que permite responder "¿merece la pena seguir
        pagando IA?" con datos en vez de con intuicion.
        """
        if not campos:
            return None

        conteo: dict[Estrategia, int] = {}
        for campo in campos.values():
            conteo[campo.estrategia] = conteo.get(campo.estrategia, 0) + 1
        return max(conteo, key=lambda k: conteo[k])


def resumen_de_calidad(registros: list[RegistroTributario]) -> dict[str, int]:
    """
    Conteo por completitud, para el panel de estadisticas.

    Vive aqui y no en el modulo de reportes porque la nocion de
    completitud pertenece a la extraccion; reportes solo la presenta.
    """
    resumen = {estado.value: 0 for estado in Completitud}
    for registro in registros:
        resumen[registro.completitud.value] += 1
    return resumen
