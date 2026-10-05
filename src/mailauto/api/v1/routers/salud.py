"""
Sondas de salud.

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

from fastapi import APIRouter, Response, status

from mailauto.api.deps import ContenedorDep
from mailauto.api.schemas.comunes import Respuesta, SaludSalida

router = APIRouter(tags=["salud"])


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
