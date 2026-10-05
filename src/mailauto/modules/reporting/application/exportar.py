"""
Casos de uso de exportacion de reportes.

Proposito
    Entregar un fichero con los registros extraidos sin bloquear la
    peticion HTTP mientras se genera.

Flujo
    SolicitarExportacion -> fila en cola -> 202 con el id
    GenerarExportacion   -> worker: consulta, genera, sube, marca lista
    ConsultarExportacion -> estado y, cuando esta lista, URL prefirmada

Dependencias
    Puertos del propio modulo.

Decision de diseño
    Asincrono desde el principio, no "sincrono y ya veremos". Un
    reporte de treinta mil filas tarda mas de lo que un navegador o un
    balanceador esperan, y convertir despues una descarga directa en
    un flujo encolado obliga a cambiar la API, el cliente y los
    permisos a la vez. El coste de hacerlo bien ahora es una tabla y
    un job.
"""

from __future__ import annotations

from uuid import UUID

from mailauto.modules.reporting.domain.ports import (
    DestinoDeReportes,
    EstadoDeExportacion,
    Exportacion,
    FormatoDeReporte,
    FuenteDeFilas,
    GeneradorDeReporte,
    RepositorioDeExportaciones,
)
from mailauto.shared.errors import ConflictoDeEstado, RecursoNoEncontrado
from mailauto.shared.observability.logging import obtener_logger
from mailauto.shared.security.context import Permiso, TenantContext

logger = obtener_logger(__name__)

# Vida de la URL de descarga. Corta a proposito: el enlace lleva los
# datos tributarios del cliente y suele acabar pegado en un chat.
TTL_DE_DESCARGA_SEGUNDOS = 300


class SolicitarExportacion:
    """Encola la generacion de un reporte."""

    def __init__(
        self,
        repositorio: RepositorioDeExportaciones,
        encolar: object,
    ) -> None:
        self._repositorio = repositorio
        self._encolar = encolar

    async def ejecutar(
        self,
        ctx: TenantContext,
        *,
        formato: FormatoDeReporte,
        filtros: dict[str, str],
    ) -> Exportacion:
        ctx.exigir(Permiso.REPORT_READ)

        exportacion = Exportacion(
            tenant_id=ctx.tenant_id,
            solicitado_por=ctx.user_id,
            formato=formato,
            filtros=filtros,
        )
        creada = await self._repositorio.crear(exportacion)

        # Se encola despues de persistir, igual que los escaneos: si
        # fallara la cola queda una fila visible que el cron reintenta.
        await self._encolar(tenant_id=ctx.tenant_id, exportacion_id=creada.id)  # type: ignore[operator]
        return creada


class ConsultarExportacion:
    """Estado de una exportacion y, si esta lista, su URL de descarga."""

    def __init__(
        self,
        repositorio: RepositorioDeExportaciones,
        destino: DestinoDeReportes,
    ) -> None:
        self._repositorio = repositorio
        self._destino = destino

    async def ejecutar(
        self, ctx: TenantContext, exportacion_id: UUID
    ) -> tuple[Exportacion, str | None]:
        ctx.exigir(Permiso.REPORT_READ)

        exportacion = await self._repositorio.obtener(ctx.tenant_id, exportacion_id)
        if exportacion is None:
            raise RecursoNoEncontrado("La exportacion no existe.")
        ctx.exigir_mismo_tenant(exportacion.tenant_id)

        if (
            exportacion.estado is not EstadoDeExportacion.LISTA
            or not exportacion.clave_de_almacenamiento
        ):
            return exportacion, None

        url = await self._destino.url_de_descarga(
            exportacion.clave_de_almacenamiento, ttl_segundos=TTL_DE_DESCARGA_SEGUNDOS
        )
        return exportacion, url


class GenerarExportacion:
    """
    Produce el fichero. Lo ejecuta el worker, nunca la API.

    No lanza al llamante: un fallo se registra en la propia
    exportacion, que es donde el usuario lo va a buscar. Propagar la
    excepcion dejaria la fila en "generando" para siempre.
    """

    def __init__(
        self,
        *,
        repositorio: RepositorioDeExportaciones,
        fuente: FuenteDeFilas,
        generadores: dict[FormatoDeReporte, GeneradorDeReporte],
        destino: DestinoDeReportes,
        limite_de_filas: int,
    ) -> None:
        self._repositorio = repositorio
        self._fuente = fuente
        self._generadores = generadores
        self._destino = destino
        self._limite = limite_de_filas

    async def ejecutar(self, *, tenant_id: UUID, exportacion_id: UUID) -> None:
        exportacion = await self._repositorio.obtener(tenant_id, exportacion_id)
        if exportacion is None:
            logger.warning("exportacion_inexistente", exportacion_id=str(exportacion_id))
            return

        if exportacion.estado.es_terminal:
            # Reentrega del job sobre algo ya resuelto: se ignora en
            # lugar de regenerar y volver a cobrar el trabajo.
            return

        try:
            exportacion.marcar_generando()
            await self._repositorio.actualizar(exportacion)

            generador = self._generadores.get(exportacion.formato)
            if generador is None:
                raise ConflictoDeEstado(f"Formato no soportado: {exportacion.formato.value}")

            filas = await self._fuente.obtener(tenant_id, exportacion.filtros, self._limite)
            contenido = generador.generar(filas, titulo="Registros SUNAT")

            clave = f"{tenant_id}/reportes/{exportacion.id}.{exportacion.formato.value}"
            await self._destino.guardar(clave, contenido, exportacion.formato.tipo_mime)

            exportacion.completar(clave=clave, total_filas=len(filas))
            logger.info(
                "exportacion_lista",
                exportacion_id=str(exportacion.id),
                filas=len(filas),
                bytes=len(contenido),
            )

        except Exception as exc:
            logger.exception("exportacion_fallida", exportacion_id=str(exportacion.id))
            # Mensaje generico: el detalle va al log. Quien pidio el
            # reporte no necesita el nombre de la excepcion.
            exportacion.fallar("No fue posible generar el reporte.")
            _ = exc

        finally:
            await self._repositorio.actualizar(exportacion)
