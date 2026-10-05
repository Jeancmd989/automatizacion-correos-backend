"""
Middlewares transversales: correlacion, cabeceras de seguridad y rate limiting.

Proposito
    Aplicar en el borde los controles que deben valer para toda la API,
    sin repetirlos en cada router.

Flujo
    peticion -> request_id -> rate limit -> ruta -> cabeceras de seguridad
    -> respuesta

Dependencias
    Starlette, Redis (contador distribuido), structlog.

Decision de diseño
    El rate limiting cuenta en Redis y no en memoria del proceso. Con N
    replicas, un contador local multiplica el limite real por N, que es
    tanto como no tener limite.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Final

import structlog
from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from mailauto.shared.observability.logging import obtener_logger

logger = obtener_logger(__name__)

_CABECERA_REQUEST_ID: Final = "X-Request-ID"
_CABECERA_TENANT: Final = "X-Tenant-Id"

Siguiente = Callable[[Request], Awaitable[Response]]


class MiddlewareDeCorrelacion(BaseHTTPMiddleware):
    """
    Asigna un identificador a cada peticion y lo propaga al log y a la
    respuesta, para poder reconstruir un incidente de punta a punta.
    """

    async def dispatch(self, request: Request, call_next: Siguiente) -> Response:
        entrante = request.headers.get(_CABECERA_REQUEST_ID, "")
        # El valor del cliente se acepta solo si parece un UUID: si no, se
        # genera uno. Un identificador controlado por el cliente podria
        # usarse para inyectar contenido en los logs.
        request_id = entrante if _parece_uuid(entrante) else str(uuid.uuid4())
        request.state.request_id = request_id

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            metodo=request.method,
            ruta=request.url.path,
        )

        inicio = time.perf_counter()
        respuesta = await call_next(request)
        duracion_ms = int((time.perf_counter() - inicio) * 1000)

        respuesta.headers[_CABECERA_REQUEST_ID] = request_id
        logger.info("peticion_atendida", status=respuesta.status_code, duracion_ms=duracion_ms)
        return respuesta


class MiddlewareDeCabecerasDeSeguridad(BaseHTTPMiddleware):
    """
    Cabeceras de endurecimiento HTTP.

    La API devuelve JSON, no HTML, asi que la CSP es la mas restrictiva
    posible: no hay nada legitimo que cargar desde una respuesta de API.
    Si `/docs` esta habilitado (solo fuera de produccion), se relaja para
    esa ruta concreta, que si necesita cargar Swagger UI.
    """

    _CSP_API = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    _CSP_DOCS = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
        "frame-ancestors 'none'; base-uri 'none'"
    )

    def __init__(self, app: object, *, hsts: bool) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._hsts = hsts

    async def dispatch(self, request: Request, call_next: Siguiente) -> Response:
        respuesta = await call_next(request)
        es_docs = request.url.path in ("/docs", "/redoc", "/openapi.json")

        respuesta.headers["Content-Security-Policy"] = self._CSP_DOCS if es_docs else self._CSP_API
        respuesta.headers["X-Content-Type-Options"] = "nosniff"
        respuesta.headers["X-Frame-Options"] = "DENY"
        respuesta.headers["Referrer-Policy"] = "no-referrer"
        respuesta.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )
        respuesta.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        respuesta.headers["Cross-Origin-Resource-Policy"] = "same-site"
        # Sin esto, una respuesta con datos de un tenant podria quedar
        # cacheada en un proxy intermedio y servirse a otro.
        respuesta.headers.setdefault("Cache-Control", "no-store")

        if self._hsts:
            respuesta.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        return respuesta


class MiddlewareDeRateLimit(BaseHTTPMiddleware):
    """
    Limitador por ventana fija sobre Redis.

    Se identifica por usuario autenticado cuando se conoce, y por IP en
    caso contrario. La clave incluye la ventana temporal, de modo que el
    propio TTL limpia los contadores sin necesidad de barrido.
    """

    _RUTAS_EXENTAS: Final = frozenset({"/health/live", "/health/ready", "/metrics"})

    def __init__(
        self,
        app: object,
        *,
        redis: Redis,
        limite_por_minuto: int,
        limites_por_prefijo: dict[str, tuple[int, int]] | None = None,
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        # Opcional porque la subclase perezosa de `bootstrap/app.py` se
        # construye antes de que el lifespan abra las conexiones y
        # resuelve el cliente en la primera peticion.
        self._redis: Redis | None = redis
        self._limite = limite_por_minuto
        # prefijo -> (maximo, ventana_en_segundos)
        self._especificos = limites_por_prefijo or {}

    async def dispatch(self, request: Request, call_next: Siguiente) -> Response:
        if request.url.path in self._RUTAS_EXENTAS or self._redis is None:
            # Sin cliente de Redis no hay contador posible. Ocurre solo en
            # las primeras peticiones, antes de que el lifespan abra las
            # conexiones; se deja pasar en lugar de rechazar trafico
            # legitimo por un detalle de arranque.
            return await call_next(request)

        limite, ventana = self._resolver_limite(request.url.path)
        identidad = self._identificar(request)
        clave = f"rl:{identidad}:{request.url.path}:{int(time.time() // ventana)}"

        try:
            pipeline = self._redis.pipeline()
            pipeline.incr(clave)
            pipeline.expire(clave, ventana)
            actual, _ = await pipeline.execute()
        except Exception:  # noqa: BLE001 - el limitador degrada a pasante si Redis cae
            # Si Redis no responde se deja pasar. Es una decision
            # consciente: convertir una caida del limitador en una caida
            # total del servicio seria peor que admitir trafico sin limitar
            # durante unos minutos. El fallo queda registrado y alertado.
            logger.error("rate_limit_no_disponible")
            return await call_next(request)

        if int(actual) > limite:
            logger.warning("rate_limit_excedido", identidad=identidad, limite=limite)
            return JSONResponse(
                status_code=429,
                content={
                    "type": "urn:mailauto:error:limite-excedido",
                    "title": "Demasiadas solicitudes",
                    "status": 429,
                    "detail": "Se excedio el limite de solicitudes. Reintenta mas tarde.",
                },
                headers={"Retry-After": str(ventana)},
            )

        return await call_next(request)

    def _resolver_limite(self, ruta: str) -> tuple[int, int]:
        for prefijo, (maximo, ventana) in self._especificos.items():
            if ruta.startswith(prefijo):
                return maximo, ventana
        return self._limite, 60

    @staticmethod
    def _identificar(request: Request) -> str:
        """
        Prefiere el sujeto autenticado sobre la IP.

        Limitar solo por IP castiga a oficinas detras de un NAT compartido
        y no detiene a quien rota direcciones.
        """
        contexto = getattr(request.state, "tenant_context", None)
        if contexto is not None:
            return f"u:{contexto.user_id}"

        tenant = request.headers.get(_CABECERA_TENANT, "")
        cliente = request.client.host if request.client else "desconocido"
        return f"ip:{cliente}:{tenant[:36]}"


def _parece_uuid(valor: str) -> bool:
    try:
        uuid.UUID(valor)
        return True
    except (ValueError, AttributeError):
        return False
