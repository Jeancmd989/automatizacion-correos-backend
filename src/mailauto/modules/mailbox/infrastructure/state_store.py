"""
Almacen temporal del estado OAuth (state + code_verifier) en Redis.

Proposito
    Custodiar entre la redireccion y el callback dos secretos de vida
    corta que, si se reutilizan, permiten secuestrar la vinculacion.

Dependencias
    redis.asyncio.

Decisiones de diseño
    1. Consumo atomico con `GETDEL` (Redis >= 6.2). Un `GET` seguido de
       `DELETE` deja una ventana en la que dos callbacks concurrentes con
       el mismo `state` leen ambos el valor antes de que ninguno borre.
       `GETDEL` elimina esa condicion de carrera en una sola operacion.

    2. TTL obligatorio. Si el usuario abandona el consentimiento, el
       secreto desaparece solo; sin TTL, Redis acumularia estados vivos
       indefinidamente y cada uno seria una ventana de ataque abierta.

    3. El `code_verifier` nunca sale del servidor. Vive aqui y se usa una
       sola vez en el canje. Esa es precisamente la garantia de PKCE.
"""

from __future__ import annotations

import json
from uuid import UUID

from redis.asyncio import Redis

from mailauto.modules.mailbox.domain.entities import Proveedor
from mailauto.modules.mailbox.domain.ports import AlmacenDeEstadoOAuth

_PREFIJO = "oauth:state:"


class AlmacenDeEstadoOAuthRedis(AlmacenDeEstadoOAuth):
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def guardar(
        self,
        *,
        state: str,
        code_verifier: str,
        tenant_id: UUID,
        user_id: UUID,
        proveedor: Proveedor,
        redirect_uri: str,
        ttl_segundos: int,
    ) -> None:
        carga = json.dumps(
            {
                "code_verifier": code_verifier,
                "tenant_id": str(tenant_id),
                "user_id": str(user_id),
                "proveedor": proveedor.value,
                "redirect_uri": redirect_uri,
            },
            separators=(",", ":"),
        )
        # `nx=True`: si por un fallo del generador de aleatorios se repitiera
        # un `state`, la segunda escritura no pisa la primera.
        await self._redis.set(f"{_PREFIJO}{state}", carga, ex=ttl_segundos, nx=True)

    async def consumir(self, state: str) -> dict[str, str] | None:
        crudo = await self._redis.getdel(f"{_PREFIJO}{state}")
        if crudo is None:
            return None
        try:
            datos = json.loads(crudo)
            return datos if isinstance(datos, dict) else None
        except (ValueError, TypeError):
            return None
