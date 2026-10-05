"""
Traduccion de errores a respuestas RFC 9457 (Problem Details).

Proposito
    Que el cliente reciba siempre un error con la misma forma, y que
    ningun detalle interno (stack trace, SQL, nombre de tabla) salga
    nunca de la aplicacion.

Flujo
    excepcion -> handler -> {type, title, status, detail, trace_id} -> JSON

Dependencias
    FastAPI/Starlette.

Decision de diseño
    Los errores no previstos devuelven siempre el mismo texto generico y
    un `trace_id`. El detalle real va al log. Asi el soporte puede
    diagnosticar con el identificador que le da el usuario, sin que el
    mensaje de error sea una fuente de informacion para quien sondea la
    aplicacion (OWASP A05).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from mailauto.shared.errors import ErrorDeDominio, ErrorDeValidacion, LimiteExcedido
from mailauto.shared.observability.logging import obtener_logger

logger = obtener_logger(__name__)

_BASE_DE_TIPOS = "urn:mailauto:error"

_TITULOS: dict[int, str] = {
    400: "Solicitud incorrecta",
    401: "No autenticado",
    402: "Cuota agotada",
    403: "Acceso denegado",
    404: "No encontrado",
    409: "Conflicto",
    422: "Datos invalidos",
    429: "Demasiadas solicitudes",
    500: "Error interno",
    502: "Error de proveedor externo",
    503: "Servicio no disponible",
}


def _problema(
    *,
    codigo: str,
    estado: int,
    detalle: str,
    request: Request,
    errores: list[dict[str, Any]] | None = None,
    cabeceras: dict[str, str] | None = None,
) -> JSONResponse:
    cuerpo: dict[str, Any] = {
        "type": f"{_BASE_DE_TIPOS}:{codigo.replace('_', '-')}",
        "title": _TITULOS.get(estado, "Error"),
        "status": estado,
        "detail": detalle,
        "instance": request.url.path,
        "trace_id": getattr(request.state, "request_id", None),
    }
    if errores:
        cuerpo["errors"] = errores
    return JSONResponse(status_code=estado, content=cuerpo, headers=cabeceras)


def registrar_manejadores(app: FastAPI) -> None:
    """Instala los handlers. Lo llama el composition root."""

    @app.exception_handler(ErrorDeDominio)
    async def _dominio(request: Request, exc: ErrorDeDominio) -> JSONResponse:
        # El contexto del error va al log, nunca a la respuesta: puede
        # contener identificadores internos o datos del tenant.
        registrar = logger.warning if exc.estado_http < 500 else logger.error
        registrar("error_de_dominio", codigo=exc.codigo, **exc.contexto)

        cabeceras = None
        if isinstance(exc, LimiteExcedido) and exc.reintentar_en_segundos:
            cabeceras = {"Retry-After": str(exc.reintentar_en_segundos)}

        errores = None
        if isinstance(exc, ErrorDeValidacion) and exc.campo:
            errores = [{"field": exc.campo, "code": exc.codigo}]

        return _problema(
            codigo=exc.codigo,
            estado=exc.estado_http,
            detalle=exc.mensaje_publico,
            request=request,
            errores=errores,
            cabeceras=cabeceras,
        )

    @app.exception_handler(RequestValidationError)
    async def _validacion(request: Request, exc: RequestValidationError) -> JSONResponse:
        """
        Errores de Pydantic normalizados.

        Se reexpone solo la ruta del campo y el tipo de error, nunca el
        valor recibido: podria ser un token o un dato personal que
        acabaria replicado en los logs del cliente.
        """
        errores = [
            {
                "field": ".".join(str(p) for p in error.get("loc", ())[1:]),
                "code": error.get("type", "invalid"),
            }
            for error in exc.errors()
        ]
        return _problema(
            codigo="validacion_fallida",
            estado=422,
            detalle="Los datos enviados no son validos.",
            request=request,
            errores=errores,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _problema(
            codigo="error_http",
            estado=exc.status_code,
            detalle=str(exc.detail),
            request=request,
        )

    @app.exception_handler(Exception)
    async def _inesperado(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("error_no_controlado", tipo=type(exc).__name__)
        return _problema(
            codigo="error_interno",
            estado=500,
            detalle="Ocurrio un error procesando la solicitud.",
            request=request,
        )
