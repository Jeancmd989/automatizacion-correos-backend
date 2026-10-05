"""
Fabrica de la aplicacion FastAPI.

Proposito
    Montar la aplicacion completa: configuracion, observabilidad,
    middlewares, routers y ciclo de vida de los recursos.

Flujo
    create_app() -> lifespan abre recursos -> la app sirve -> lifespan
    los cierra ordenadamente.

Dependencias
    Todas las capas. Forma parte del composition root.

Decision de diseño
    El orden de los middlewares importa y no es arbitrario. Starlette los
    ejecuta en orden inverso al de registro, asi que se registran de mas
    interno a mas externo: correlacion queda por fuera (todo lo demas ya
    tiene `request_id` disponible) y las cabeceras de seguridad por
    dentro, para que se apliquen tambien a las respuestas de error que
    genera el rate limiter.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from starlette.responses import Response

from mailauto.api.middleware.errores import registrar_manejadores
from mailauto.api.middleware.seguridad import (
    MiddlewareDeCabecerasDeSeguridad,
    MiddlewareDeCorrelacion,
    MiddlewareDeRateLimit,
    Siguiente,
)
from mailauto.api.v1.routers import buzones, escaneos, perfil, registros, salud
from mailauto.bootstrap.container import construir_contenedor
from mailauto.bootstrap.settings import Settings, get_settings
from mailauto.shared.observability.logging import configurar_logging, obtener_logger

logger = obtener_logger(__name__)


def crear_app(settings: Settings | None = None) -> FastAPI:
    ajustes = settings or get_settings()

    configurar_logging(
        nivel=ajustes.log_level,
        formato_json=ajustes.environment.es_productivo,
    )

    @asynccontextmanager
    async def ciclo_de_vida(app: FastAPI) -> AsyncIterator[None]:
        logger.info("arrancando", entorno=ajustes.environment.value)
        contenedor = await construir_contenedor(ajustes)
        app.state.contenedor = contenedor

        if not ajustes.environment.es_productivo:
            # En desarrollo, MinIO arranca sin buckets. En produccion el
            # bucket lo provisiona la infraestructura con sus politicas.
            await contenedor.almacen.asegurar_bucket()

        try:
            yield
        finally:
            logger.info("apagando")
            await contenedor.cerrar()

    app = FastAPI(
        title="Automatizacion de Correos API",
        version="0.1.0",
        description=(
            "Ingesta de adjuntos de correo y extraccion de datos tributarios. "
            "Todas las rutas requieren un token OIDC salvo las sondas de salud."
        ),
        lifespan=ciclo_de_vida,
        # En produccion no se publica el esquema: es un mapa completo de
        # la superficie de ataque y no aporta nada a un cliente legitimo,
        # que ya tiene el cliente generado.
        docs_url="/docs" if ajustes.docs_enabled else None,
        redoc_url="/redoc" if ajustes.docs_enabled else None,
        openapi_url="/openapi.json" if ajustes.docs_enabled else None,
    )

    _montar_middlewares(app, ajustes)
    registrar_manejadores(app)
    _montar_routers(app, ajustes)

    return app


def _montar_middlewares(app: FastAPI, ajustes: Settings) -> None:
    # Registrados de mas interno a mas externo (Starlette los aplica al reves).
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    app.add_middleware(MiddlewareDeCabecerasDeSeguridad, hsts=ajustes.environment.es_productivo)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=ajustes.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Tenant-Id",
            "X-Request-ID",
            "Idempotency-Key",
        ],
        expose_headers=["X-Request-ID", "Location", "Retry-After"],
        max_age=600,
    )

    # El rate limit necesita Redis, que vive en el contenedor y solo
    # existe tras el lifespan. Se resuelve con un envoltorio perezoso que
    # toma el cliente de `app.state` en la primera peticion.
    app.add_middleware(
        _RateLimitPerezoso,
        limite_por_minuto=ajustes.rate_limit_default_per_minute,
        limites_por_prefijo={
            # Los endpoints que lanzan trabajo o inician OAuth son los
            # mas caros y los mas interesantes de abusar: limite propio.
            "/api/v1/scans": (ajustes.rate_limit_scan_per_hour, 3600),
            "/api/v1/mailboxes/authorize": (ajustes.rate_limit_oauth_per_hour, 3600),
            "/api/v1/mailboxes/callback": (ajustes.rate_limit_oauth_per_hour, 3600),
        },
    )

    app.add_middleware(MiddlewareDeCorrelacion)


def _montar_routers(app: FastAPI, ajustes: Settings) -> None:
    app.include_router(salud.router)
    app.include_router(perfil.router, prefix=ajustes.api_prefix)
    app.include_router(buzones.router, prefix=ajustes.api_prefix)
    app.include_router(escaneos.router, prefix=ajustes.api_prefix)
    app.include_router(registros.router, prefix=ajustes.api_prefix)


class _RateLimitPerezoso(MiddlewareDeRateLimit):
    """
    Variante que resuelve el cliente de Redis en la primera peticion.

    Existe porque los middlewares se construyen al crear la app, antes de
    que el lifespan abra las conexiones. La alternativa (crear Redis dos
    veces) duplicaria el pool sin necesidad.
    """

    def __init__(
        self,
        app: object,
        *,
        limite_por_minuto: int,
        limites_por_prefijo: dict[str, tuple[int, int]],
    ) -> None:
        # Arranca sin cliente; `dispatch` lo toma de app.state en la
        # primera peticion, cuando el lifespan ya abrio las conexiones.
        super().__init__(
            app,
            redis=None,
            limite_por_minuto=limite_por_minuto,
            limites_por_prefijo=limites_por_prefijo,
        )

    async def dispatch(self, request: Request, call_next: Siguiente) -> Response:
        if self._redis is None:
            contenedor = getattr(request.app.state, "contenedor", None)
            if contenedor is None:
                return await call_next(request)
            self._redis = contenedor.redis
        return await super().dispatch(request, call_next)


# Punto de entrada:  uvicorn mailauto.bootstrap.app:crear_app --factory
#
# Se expone la fabrica y no una instancia a nivel de modulo porque crear
# la app valida la configuracion: con una instancia global, importar este
# modulo en un test sin variables de entorno fallaria en el import.
