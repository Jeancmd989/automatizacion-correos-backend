"""
Trazas distribuidas con OpenTelemetry.

Proposito
    Seguir una peticion desde el borde HTTP hasta la consulta SQL que
    provoca, y desde el job encolado hasta la llamada al proveedor de
    correo. Es lo unico que responde "¿por que este escaneo tardo cuatro
    minutos?" sin reconstruirlo a mano desde los logs.

Dependencias
    `opentelemetry-sdk`, el exportador OTLP/HTTP y las instrumentaciones de
    FastAPI y SQLAlchemy. Ya estaban declaradas en el proyecto.

Decisiones de diseño
    1. **Sin endpoint configurado, no se instala nada.** El exportador OTLP
       reintenta contra un colector ausente y escribe un error por intento;
       en desarrollo sin Jaeger eso llena la consola y tapa lo que importa.

    2. **Las rutas de salud quedan excluidas.** Las sondas del balanceador
       se llaman cada pocos segundos y producirian la inmensa mayoria de
       las trazas, con un coste de almacenamiento real y ningun valor.

    3. **`enable_commenter` desactivado en SQLAlchemy.** Esa opcion
       incrusta el contexto de traza como comentario dentro del SQL. Es
       comodo para correlacionar, pero cambia el texto de cada sentencia y
       por tanto arruina la cache de planes y el agrupamiento de
       `pg_stat_statements`.

    4. **Los nombres de span no llevan datos.** Las instrumentaciones usan
       el patron de ruta, no la URL con identificadores, por el mismo
       motivo que las metricas: un nombre por recurso hace inservible
       cualquier agregacion.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = structlog.get_logger(__name__)

# Rutas que no generan traza. Las sondas se consultan constantemente.
_RUTAS_EXCLUIDAS = "health/live,health/ready,metrics"


def configurar_trazas(
    *,
    endpoint: str | None,
    nombre_del_servicio: str,
    entorno: str,
    version: str,
) -> bool:
    """
    Instala el proveedor de trazas. Devuelve si quedo activo.

    Es idempotente en la practica: OpenTelemetry ignora un segundo
    `set_tracer_provider` con un aviso, de modo que llamar a esto dos veces
    (API y worker en el mismo proceso, en un test) no rompe nada.
    """
    if not endpoint:
        logger.info("trazas_desactivadas", motivo="sin OTEL_EXPORTER_ENDPOINT")
        return False

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    recurso = Resource.create(
        {
            "service.name": nombre_del_servicio,
            "service.version": version,
            "deployment.environment": entorno,
        }
    )
    proveedor = TracerProvider(resource=recurso)
    # Por lotes y no sincrono: un exportador sincrono añade la latencia de
    # la red del colector a cada peticion que termina.
    proveedor.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces"))
    )
    trace.set_tracer_provider(proveedor)

    logger.info("trazas_activadas", servicio=nombre_del_servicio)
    return True


def instrumentar_api(app: FastAPI) -> None:
    """Instrumenta la aplicacion FastAPI. Solo tiene efecto si hay proveedor."""
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    FastAPIInstrumentor.instrument_app(app, excluded_urls=_RUTAS_EXCLUIDAS)


def instrumentar_base_de_datos(engine: Any) -> None:  # noqa: ANN401 - AsyncEngine o su sync_engine
    """
    Instrumenta SQLAlchemy.

    Recibe el `AsyncEngine` y usa su motor sincrono interno, que es lo que
    la instrumentacion sabe envolver.
    """
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

    objetivo = getattr(engine, "sync_engine", engine)
    SQLAlchemyInstrumentor().instrument(engine=objetivo, enable_commenter=False)
