"""
Sondas de salud y endpoint de metricas.

Proposito
    Distinguir "el proceso esta vivo" de "el proceso puede atender
    trafico", que son dos preguntas distintas y requieren dos endpoints.

Dependencias
    FastAPI y el contenedor.

Decision de diseño
    `/health/live` no toca dependencias externas. Si la sonda de vida
    comprobara la base de datos, una caida de PostgreSQL haria que el
    orquestador reiniciara en bucle unos contenedores que estan
    perfectamente sanos y que volverian a servir en cuanto la base de
    datos se recupere. La sonda de preparacion si las comprueba: retira la
    replica del balanceador sin matarla.
"""

from __future__ import annotations

import asyncio
from hmac import compare_digest
from typing import Annotated

from fastapi import APIRouter, Header, Response, status

from mailauto.api.deps import ContenedorDep
from mailauto.api.schemas.comunes import Respuesta, SaludSalida
from mailauto.shared.errors import ErrorDeAutenticacion
from mailauto.shared.observability import metricas
from mailauto.shared.observability.logging import obtener_logger

router = APIRouter(tags=["salud"])

logger = obtener_logger(__name__)


@router.get("/health/live", response_model=Respuesta[SaludSalida])
async def vivo() -> Respuesta[SaludSalida]:
    """Responde si el proceso esta en pie. Sin dependencias externas."""
    return Respuesta(data=SaludSalida(estado="vivo"))


@router.get("/health/ready", response_model=Respuesta[SaludSalida])
async def preparado(contenedor: ContenedorDep, respuesta: Response) -> Respuesta[SaludSalida]:
    """Comprueba base de datos, Redis y almacenamiento, en paralelo."""
    bd, cola, almacen = await asyncio.gather(
        contenedor.sesiones.esta_disponible(),
        contenedor.cola.esta_disponible(),
        contenedor.almacen.esta_disponible(),
    )
    componentes = {"base_de_datos": bd, "cola": cola, "almacenamiento": almacen}
    todo_bien = all(componentes.values())

    if not todo_bien:
        respuesta.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return Respuesta(
        data=SaludSalida(estado="preparado" if todo_bien else "degradado", componentes=componentes)
    )


# `include_in_schema=False`: el formato de exposicion de Prometheus no es
# JSON y no tiene nada que hacer en el contrato que consume el frontend.
@router.get("/metrics", include_in_schema=False)
async def exponer_metricas(
    contenedor: ContenedorDep,
    authorization: Annotated[str | None, Header()] = None,
) -> Response:
    """
    Metricas en formato Prometheus.

    Protegido con un token compartido cuando `METRICS_TOKEN` esta definido,
    y obligatorio en produccion: aunque no exponga datos de ningun cliente,
    este endpoint revela el mapa de rutas internas, las tasas de error y el
    volumen de uso, que es reconocimiento gratuito para quien prepara un
    ataque. No se usa el JWT del usuario porque quien raspa esto es un
    recolector, no una persona con sesion.
    """
    esperado = contenedor.settings.metrics_token
    if esperado:
        recibido = (authorization or "").removeprefix("Bearer ").strip()
        # Comparacion en tiempo constante: una comparacion normal filtra la
        # longitud del prefijo coincidente por el tiempo que tarda.
        if not compare_digest(recibido, esperado):
            raise ErrorDeAutenticacion()

    # Los medidores de la cola se leen en el momento del raspado y no se
    # mantienen al dia por un bucle aparte: un Gauge vive en la memoria del
    # proceso, y con varias replicas el que lo actualizara no seria
    # necesariamente el que responde a Prometheus.
    try:
        profundidad, antiguedad = await contenedor.cola.estado()
        metricas.profundidad_de_cola.labels(cola="ingesta").set(profundidad)
        metricas.antiguedad_de_cola.labels(cola="ingesta").set(antiguedad)
    except Exception:  # noqa: BLE001 - el raspado no debe fallar por la cola
        logger.warning("no_se_pudo_leer_el_estado_de_la_cola")

    cuerpo, tipo = metricas.exponer()
    return Response(content=cuerpo, media_type=tipo)
