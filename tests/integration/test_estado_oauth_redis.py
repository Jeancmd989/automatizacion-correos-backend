"""
Estado OAuth contra un Redis real.

Proposito
    Comprobar que el `state` de la vinculacion se consume una sola vez y
    que caduca. Son las dos propiedades que impiden secuestrar una
    vinculacion, y las dos dependen de comandos concretos del servidor.

Por que hace falta Redis
    `GETDEL` es atomico en Redis y no en un doble `fake`. Un doble que
    implemente `getdel` como un `get` seguido de un `del` pasa el test de
    reutilizacion y oculta justo la condicion de carrera que el comando
    existe para evitar. El TTL, igual: solo el servidor lo aplica.

Dependencias
    Redis >= 6.2 (GETDEL).
"""

from __future__ import annotations

import asyncio
import secrets
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from mailauto.modules.mailbox.domain.entities import Proveedor
from mailauto.modules.mailbox.infrastructure.state_store import AlmacenDeEstadoOAuthRedis

pytestmark = [pytest.mark.integration, pytest.mark.security]

_REDIRECT_URI = "http://localhost:3000/oauth/callback"


async def _guardar(almacen: AlmacenDeEstadoOAuthRedis, *, ttl: int = 600) -> tuple[str, str]:
    state = secrets.token_urlsafe(32)
    verificador = secrets.token_urlsafe(64)
    await almacen.guardar(
        state=state,
        code_verifier=verificador,
        tenant_id=uuid4(),
        user_id=uuid4(),
        proveedor=Proveedor.GOOGLE,
        redirect_uri=_REDIRECT_URI,
        ttl_segundos=ttl,
    )
    return state, verificador


async def test_el_estado_se_recupera_completo(redis: Redis) -> None:
    almacen = AlmacenDeEstadoOAuthRedis(redis)
    state, verificador = await _guardar(almacen)

    datos = await almacen.consumir(state)

    assert datos is not None
    assert datos["code_verifier"] == verificador
    assert datos["redirect_uri"] == _REDIRECT_URI
    assert datos["proveedor"] == Proveedor.GOOGLE.value


async def test_el_estado_solo_sirve_una_vez(redis: Redis) -> None:
    """
    Un `state` reutilizable permite completar dos veces la misma
    vinculacion: el atacante que consiga el codigo de autorizacion de
    la victima lo canjea contra la sesion legitima.
    """
    almacen = AlmacenDeEstadoOAuthRedis(redis)
    state, _ = await _guardar(almacen)

    assert await almacen.consumir(state) is not None
    assert await almacen.consumir(state) is None


async def test_dos_callbacks_simultaneos_solo_uno_gana(redis: Redis) -> None:
    """
    La razon de usar `GETDEL` y no `GET` + `DELETE`.

    Con dos operaciones separadas existe una ventana en la que ambas
    lecturas ven el valor antes de que ninguna borre, y los dos
    callbacks se consideran validos. Con `GETDEL` el servidor serializa
    y exactamente uno recibe los datos.
    """
    almacen = AlmacenDeEstadoOAuthRedis(redis)
    state, _ = await _guardar(almacen)

    resultados = await asyncio.gather(*(almacen.consumir(state) for _ in range(10)))

    ganadores = [r for r in resultados if r is not None]
    assert len(ganadores) == 1, f"{len(ganadores)} callbacks se consideraron validos"


async def test_el_estado_lleva_ttl_y_no_se_queda_para_siempre(redis: Redis) -> None:
    """
    Sin TTL, un consentimiento abandonado deja el secreto vivo
    indefinidamente y Redis acumula ventanas de ataque abiertas.
    """
    almacen = AlmacenDeEstadoOAuthRedis(redis)
    _state, _ = await _guardar(almacen, ttl=600)

    claves = await redis.keys("oauth:state:*")
    assert len(claves) == 1
    restante = await redis.ttl(claves[0])
    assert 0 < restante <= 600


async def test_el_estado_caducado_no_se_puede_consumir(redis: Redis) -> None:
    almacen = AlmacenDeEstadoOAuthRedis(redis)
    state, _ = await _guardar(almacen, ttl=1)

    # Se fuerza la caducidad en lugar de esperar: un `sleep` real haria
    # el test lento y dependiente del reloj.
    await redis.expire(f"oauth:state:{state}", 0)

    assert await almacen.consumir(state) is None


async def test_un_state_repetido_no_pisa_el_anterior(redis: Redis) -> None:
    """
    El `nx=True` del guardado. Si el generador de aleatorios repitiera un
    valor, la segunda escritura no debe sustituir el `code_verifier` de
    la vinculacion que ya estaba en curso.
    """
    almacen = AlmacenDeEstadoOAuthRedis(redis)
    state = secrets.token_urlsafe(32)
    comun = {
        "state": state,
        "tenant_id": uuid4(),
        "user_id": uuid4(),
        "proveedor": Proveedor.GOOGLE,
        "redirect_uri": _REDIRECT_URI,
        "ttl_segundos": 600,
    }

    await almacen.guardar(code_verifier="el-primero", **comun)
    await almacen.guardar(code_verifier="el-segundo", **comun)

    datos = await almacen.consumir(state)
    assert datos is not None
    assert datos["code_verifier"] == "el-primero"


async def test_una_carga_corrupta_no_se_acepta_como_estado(redis: Redis) -> None:
    """
    Si alguien escribiera basura en la clave, `consumir` debe tratarla
    como ausencia y no propagar una excepcion al borde HTTP.
    """
    almacen = AlmacenDeEstadoOAuthRedis(redis)
    state = secrets.token_urlsafe(32)
    await redis.set(f"oauth:state:{state}", "{esto no es json", ex=60)

    assert await almacen.consumir(state) is None


async def test_el_verificador_no_queda_en_redis_tras_el_canje(redis: Redis) -> None:
    """La garantia de PKCE: el verificador se usa una vez y desaparece."""
    almacen = AlmacenDeEstadoOAuthRedis(redis)
    state, verificador = await _guardar(almacen)

    await almacen.consumir(state)

    assert await redis.keys("oauth:state:*") == []
    # Y no ha quedado copiado en ninguna otra clave.
    for clave in await redis.keys("*"):
        valor = await redis.get(clave)
        assert verificador not in str(valor)
