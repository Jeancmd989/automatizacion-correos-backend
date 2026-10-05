"""
Cola de trabajos y canal de progreso sobre Redis.

Proposito
    Sacar la ejecucion del pipeline fuera del proceso web (hallazgo H3) y
    permitir que cualquier replica de la API sirva el progreso en vivo de
    un trabajo que corre en otro worker.

Dependencias
    arq (encolado) y redis.asyncio (señales y pub/sub).

Decisiones de diseño
    1. La cancelacion es una clave en Redis con TTL, no una señal al
       proceso. El worker la consulta entre mensajes y se detiene
       ordenadamente: cierra la transaccion, guarda contadores y publica
       el estado final. Un `kill` dejaria el trabajo "en ejecucion" para
       siempre.

    2. Pub/sub y no una lista. El progreso es informacion efimera: si
       nadie mira la pantalla, no hay que guardarlo. El estado duradero
       ya esta en PostgreSQL, que es de donde se recupera al reconectar.

    3. El `_job_id` de ARQ se deriva del `trabajo_id`. ARQ descarta un
       job con un id que ya esta en la cola, asi que una doble publicacion
       por un reintento de red no produce dos ejecuciones.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from uuid import UUID

from arq import ArqRedis
from redis.asyncio import Redis

from mailauto.modules.ingestion.domain.ports import CanalDeProgreso, ColaDeTrabajos
from mailauto.shared.observability.logging import obtener_logger

logger = obtener_logger(__name__)

NOMBRE_DEL_JOB_DE_ESCANEO = "ejecutar_escaneo"

_PREFIJO_CANCELACION = "scan:cancel:"
_PREFIJO_CANAL = "scan:progress:"
# La señal de cancelacion vive algo mas que el timeout maximo de un job:
# asi no desaparece antes de que el worker pueda leerla.
_TTL_CANCELACION_SEGUNDOS = 7200


class ColaDeTrabajosRedis(ColaDeTrabajos):
    def __init__(self, arq: ArqRedis, redis: Redis) -> None:
        self._arq = arq
        self._redis = redis

    async def encolar_escaneo(self, *, tenant_id: UUID, trabajo_id: UUID) -> str:
        job = await self._arq.enqueue_job(
            NOMBRE_DEL_JOB_DE_ESCANEO,
            str(tenant_id),
            str(trabajo_id),
            _job_id=f"scan:{trabajo_id}",
        )
        if job is None:
            # ARQ devuelve None cuando el `_job_id` ya existe. No es un
            # error: es la idempotencia funcionando.
            logger.info("job_ya_encolado", trabajo_id=str(trabajo_id))
            return f"scan:{trabajo_id}"
        return job.job_id

    async def solicitar_cancelacion(self, trabajo_id: UUID) -> None:
        await self._redis.set(
            f"{_PREFIJO_CANCELACION}{trabajo_id}", "1", ex=_TTL_CANCELACION_SEGUNDOS
        )

    async def cancelacion_solicitada(self, trabajo_id: UUID) -> bool:
        return bool(await self._redis.exists(f"{_PREFIJO_CANCELACION}{trabajo_id}"))

    async def esta_disponible(self) -> bool:
        try:
            await self._redis.ping()
            return True
        except Exception:
            return False


class CanalDeProgresoRedis(CanalDeProgreso):
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def publicar(self, trabajo_id: UUID, evento: dict[str, object]) -> None:
        try:
            await self._redis.publish(
                f"{_PREFIJO_CANAL}{trabajo_id}", json.dumps(evento, default=str)
            )
        except Exception:
            # El progreso es cosmetico: que falle su publicacion no puede
            # tumbar un escaneo que por lo demas va bien. El estado real
            # queda en PostgreSQL.
            logger.warning("fallo_al_publicar_progreso", trabajo_id=str(trabajo_id))

    async def suscribirse(self, trabajo_id: UUID) -> AsyncIterator[dict[str, object]]:
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(f"{_PREFIJO_CANAL}{trabajo_id}")
        try:
            async for mensaje in pubsub.listen():
                if mensaje.get("type") != "message":
                    continue
                try:
                    datos = json.loads(mensaje["data"])
                except (ValueError, TypeError):
                    continue
                if isinstance(datos, dict):
                    yield datos
        finally:
            # Sin este cierre, cada cliente SSE que se desconecta deja una
            # suscripcion viva y Redis acaba con miles de canales abiertos.
            await pubsub.unsubscribe(f"{_PREFIJO_CANAL}{trabajo_id}")
            await pubsub.aclose()
