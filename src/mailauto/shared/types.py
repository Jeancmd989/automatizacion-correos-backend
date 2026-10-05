"""
Tipos base compartidos por todo el sistema.

Proposito
    Ofrecer identificadores y utilidades de tiempo consistentes, para que
    ningun modulo tenga que decidir por su cuenta como generar un id o
    como obtener "ahora".

Dependencias
    Solo la biblioteca estandar.

Decision de diseño
    UUIDv7 en lugar de UUIDv4 como clave primaria. Un v4 es aleatorio puro:
    cada insercion cae en una pagina distinta del indice B-tree y lo
    fragmenta. El v7 lleva el timestamp en los bits altos, asi que las
    inserciones son casi secuenciales (localidad de escritura) y ordenar
    por id equivale a ordenar por fecha de creacion, sin perder la
    imposibilidad de enumerar recursos ajenos que da un id opaco.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import UTC, datetime

_MASCARA_12_BITS = 0x0FFF
_MASCARA_62_BITS = (1 << 62) - 1


def uuid7() -> uuid.UUID:
    """
    Genera un UUID version 7 (RFC 9562): 48 bits de timestamp en milisegundos
    seguidos de 74 bits aleatorios.

    Layout:
        [ 48 bits unix_ts_ms ][ 4 bits version ][ 12 bits rand_a ]
        [ 2 bits variant ][ 62 bits rand_b ]
    """
    unix_ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    aleatorio = int.from_bytes(os.urandom(10), "big")

    rand_a = (aleatorio >> 62) & _MASCARA_12_BITS
    rand_b = aleatorio & _MASCARA_62_BITS

    valor = unix_ts_ms << 80
    valor |= 0x7 << 76  # version 7
    valor |= rand_a << 64
    valor |= 0b10 << 62  # variant RFC 4122
    valor |= rand_b

    return uuid.UUID(int=valor)


def ahora_utc() -> datetime:
    """
    Instante actual con zona horaria explicita.

    Nunca usar `datetime.now()` sin tz: produce datetimes ingenuos que
    PostgreSQL interpreta en la zona del servidor y generan desfases que
    solo aparecen en produccion. La regla DTZ de ruff lo impide en CI.
    """
    return datetime.now(tz=UTC)


def asegurar_utc(momento: datetime) -> datetime:
    """Normaliza a UTC un datetime que puede venir ingenuo de un cliente externo."""
    if momento.tzinfo is None:
        return momento.replace(tzinfo=UTC)
    return momento.astimezone(UTC)
