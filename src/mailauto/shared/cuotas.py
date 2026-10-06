"""
Cuotas de uso por tenant.

Proposito
    Contar operaciones caras —lanzar un escaneo, iniciar una vinculacion
    OAuth— por tenant y por ventana de tiempo, para que un cliente no
    pueda consumir la capacidad de los demas.

Por que no vale el middleware de rate limit
    Son dos controles distintos aunque se parezcan, y confundirlos tuvo
    consecuencias reales:

    · El middleware es un cortafuegos contra avalanchas. Corre antes de
      autenticar —que es el orden correcto: no tiene sentido verificar la
      firma de un token de trafico que se va a rechazar— y por tanto solo
      puede identificar al cliente por su direccion IP.

    · Una cuota de negocio pertenece al tenant, no a una direccion IP. Y
      si se cuenta por IP antes de autenticar, cualquiera sin credenciales
      agota la cuota horaria de todos los que comparten esa salida a
      internet: con veintiuna peticiones anonimas se deja una oficina
      entera sin poder lanzar escaneos durante una hora.

    De ahi que esto se aplique como dependencia de FastAPI, que corre
    DESPUES de resolver la identidad.

Decision de diseño
    Si Redis no responde, la cuota deja pasar. Es la misma eleccion que
    hace el middleware y por la misma razon: convertir una caida del
    contador en una caida del servicio seria peor. Queda registrado como
    error para que se alerte.

    Ventana fija y no deslizante. La deslizante es mas justa en el borde
    del periodo, pero exige un conjunto ordenado por peticion; la fija se
    resuelve con un INCR y un EXPIRE, y para una cuota horaria la
    diferencia no la nota nadie.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from uuid import UUID

import structlog
from redis.asyncio import Redis

logger = structlog.get_logger(__name__)


class ControlDeCuotas(ABC):
    """Puerto del contador de cuotas."""

    @abstractmethod
    async def consumir(
        self,
        *,
        recurso: str,
        tenant_id: UUID,
        maximo: int,
        ventana_segundos: int,
    ) -> bool:
        """
        Registra un uso y dice si estaba permitido.

        Devuelve `False` cuando el uso excede la cuota. El uso se cuenta
        igualmente: no interesa premiar a quien insiste.
        """


class CuotasEnRedis(ControlDeCuotas):
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def consumir(
        self,
        *,
        recurso: str,
        tenant_id: UUID,
        maximo: int,
        ventana_segundos: int,
    ) -> bool:
        # La ventana forma parte de la clave, asi que el propio TTL limpia
        # los contadores y no hace falta ningun barrido.
        periodo = int(time.time() // ventana_segundos)
        clave = f"cuota:{recurso}:{tenant_id}:{periodo}"

        try:
            pipeline = self._redis.pipeline()
            pipeline.incr(clave)
            pipeline.expire(clave, ventana_segundos)
            actual, _ = await pipeline.execute()
        except Exception:  # noqa: BLE001 - degrada a pasante, igual que el middleware
            logger.error("cuota_no_disponible", recurso=recurso)
            return True

        return int(actual) <= maximo
