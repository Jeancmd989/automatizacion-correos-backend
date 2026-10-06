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
from fastapi.routing import APIRoute
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from starlette.responses import Response

from mailauto.api.middleware.errores import registrar_manejadores
from mailauto.api.middleware.seguridad import (
    MiddlewareDeCabecerasDeSeguridad,
    MiddlewareDeCorrelacion,
    MiddlewareDeMetricas,
    MiddlewareDeRateLimit,
    Siguiente,
)
from mailauto.api.v1.routers import buzones, escaneos, perfil, registros, salud
from mailauto.bootstrap.container import construir_contenedor
from mailauto.bootstrap.settings import Settings, get_settings
from mailauto.shared.observability.logging import configurar_logging, obtener_logger
from mailauto.shared.observability.trazas import (
    configurar_trazas,
    instrumentar_api,
    instrumentar_base_de_datos,
)

logger = obtener_logger(__name__)

_VERSION = "0.1.0"


def _identificador_de_operacion(ruta: APIRoute) -> str:
    """
    Nombre estable y legible para cada operacion del OpenAPI.

    Por defecto FastAPI genera algo como
    `aprobar_registro_api_v1_records__registro_id__approve_post`, y de
    ahi el generador de cliente saca
    `useAprobarRegistroApiV1RecordsRegistroIdApprovePost`. Nadie quiere
    escribir eso, y ademas cambia en cuanto se mueve la ruta: el
    identificador deja de ser estable y el diff del cliente generado
    se llena de renombrados.

    Con `<tag>_<funcion>` queda `registros_aprobar_registro`, que
    sobrevive a un cambio de ruta y produce `useRegistrosAprobarRegistro`.
    """
    etiqueta = ruta.tags[0] if ruta.tags else "api"
    return f"{etiqueta}_{ruta.name}"


def crear_app(settings: Settings | None = None) -> FastAPI:
    ajustes = settings or get_settings()

    configurar_logging(
        nivel=ajustes.log_level,
        formato_json=ajustes.environment.es_productivo,
    )

    trazas_activas = configurar_trazas(
        endpoint=ajustes.otel_exporter_endpoint,
        nombre_del_servicio="mailauto-api",
        entorno=ajustes.environment.value,
        version=_VERSION,
    )

    @asynccontextmanager
    async def ciclo_de_vida(app: FastAPI) -> AsyncIterator[None]:
        logger.info("arrancando", entorno=ajustes.environment.value)
        contenedor = await construir_contenedor(ajustes)
        app.state.contenedor = contenedor

        if trazas_activas:
            # Se instrumenta aqui y no al crear la app: el engine no existe
            # hasta que el contenedor esta construido.
            instrumentar_base_de_datos(contenedor.sesiones.engine)

        if not ajustes.environment.es_productivo:
            # En desarrollo el almacen arranca sin buckets. En produccion el
            # bucket lo provisiona la infraestructura con sus politicas.
            await contenedor.almacen.asegurar_bucket()

        try:
            yield
        finally:
            logger.info("apagando")
            await contenedor.cerrar()

    app = FastAPI(
        title="Automatizacion de Correos API",
        version=_VERSION,
        description=(
            "Ingesta de adjuntos de correo y extraccion de datos tributarios. "
            "Todas las rutas requieren un token OIDC salvo las sondas de salud."
        ),
        lifespan=ciclo_de_vida,
        generate_unique_id_function=_identificador_de_operacion,
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

    if trazas_activas:
        instrumentar_api(app)

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
    # Limite unico y por minuto: es un cortafuegos contra avalanchas, no
    # una cuota. Las cuotas de los endpoints caros (escaneos y
    # vinculaciones OAuth) se aplican por tenant con `limita_por_tenant`,
    # que corre despues de autenticar; aqui solo se puede contar por IP, y
    # una cuota horaria contada por IP antes de autenticar la agota
    # cualquiera sin credenciales para todo el que comparta esa salida.
    app.add_middleware(
        _RateLimitPerezoso,
        limite_por_minuto=ajustes.rate_limit_default_per_minute,
    )

    # Lo mas externo junto a la correlacion: asi mide tambien la latencia
    # de lo que el limitador rechaza, que es parte de la experiencia del
    # cliente aunque no llegue a ninguna ruta.
    app.add_middleware(MiddlewareDeMetricas)

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

    def __init__(self, app: object, *, limite_por_minuto: int) -> None:
        # Arranca sin cliente; `dispatch` lo toma de app.state en la
        # primera peticion, cuando el lifespan ya abrio las conexiones.
        super().__init__(app, redis=None, limite_por_minuto=limite_por_minuto)

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
