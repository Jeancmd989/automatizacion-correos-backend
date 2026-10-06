"""
Fixtures de los tests de integracion.

Proposito
    Dar a los tests una base de datos, un Redis y un almacen de objetos
    reales. Hay comportamientos que no se pueden verificar con dobles:
    Row Level Security es el principal: una politica puede estar escrita,
    declarada y activa, y no filtrar nada.

Dependencias
    Los servicios de `docker compose`: PostgreSQL, Redis y el almacen
    de objetos compatible con S3.

Decisiones de diseño
    1. Sin `testcontainers`. El proyecto ya trae un `docker-compose.yml`
       con los tres servicios, y en CI los runners de GitHub ofrecen
       `services:` nativos. Añadir una libreria que arranque contenedores
       desde dentro del proceso de pytest significa otra dependencia de
       desarrollo, Docker accesible desde el propio test y un segundo
       lugar donde se declaran las versiones de PostgreSQL y Redis. Los
       tests leen URLs de conexion del entorno y se saltan solos si no
       hay nada escuchando.

    2. Dos conexiones a la misma base: una como propietario y otra como
       rol de aplicacion. La del propietario solo siembra datos; todas
       las aserciones van por la de aplicacion, que es la que debe estar
       sometida a RLS. Mezclarlas invalidaria los tests sin que se note.

    3. Cada test usa tenants nuevos con identificadores aleatorios. Asi
       dos ejecuciones simultaneas no se pisan y el borrado en cascada
       limpia sin dejar residuo.
"""

from __future__ import annotations

import os
import socket
from collections.abc import AsyncIterator
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import pytest
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from mailauto.shared.db.session import FabricaDeSesiones, crear_engine

URL_PROPIETARIO = os.getenv(
    "TEST_DATABASE_URL_OWNER",
    "postgresql+asyncpg://mailauto_owner:desarrollo@localhost:5432/mailauto",
)
URL_APLICACION = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://mailauto_app:desarrollo@localhost:5432/mailauto",
)
# Base 15: las pruebas hacen FLUSHDB, y la 0 es la de desarrollo.
URL_REDIS = os.getenv("TEST_REDIS_URL", "redis://localhost:6379/15")
ENDPOINT_ALMACEN = os.getenv("TEST_STORAGE_ENDPOINT_URL", "http://localhost:4566")
CLAVE_ALMACEN = os.getenv("TEST_STORAGE_ACCESS_KEY", "desarrollo")
SECRETO_ALMACEN = os.getenv("TEST_STORAGE_SECRET_KEY", "desarrollo-secreto")

_AVISO = (
    "{servicio} no responde en {destino}. Levanta los servicios con "
    "`docker compose up -d postgres redis almacen`."
)


def _destino(url: str, puerto_por_defecto: int) -> tuple[str, int]:
    partes = urlsplit(url)
    return partes.hostname or "localhost", partes.port or puerto_por_defecto


def _escucha(host: str, puerto: int) -> bool:
    """Comprueba el puerto con un socket: no necesita bucle de eventos."""
    with socket.socket() as conector:
        conector.settimeout(1.0)
        return conector.connect_ex((host, puerto)) == 0


def exigir_servicio(servicio: str, url: str, puerto_por_defecto: int) -> None:
    host, puerto = _destino(url, puerto_por_defecto)
    if not _escucha(host, puerto):
        pytest.skip(_AVISO.format(servicio=servicio, destino=f"{host}:{puerto}"))


@dataclass(frozen=True, slots=True)
class DosTenants:
    """Dos tenants sembrados, cada uno con un usuario propio."""

    a: UUID
    b: UUID
    usuario_a: UUID
    usuario_b: UUID


@pytest.fixture
def _postgres_en_marcha() -> None:
    exigir_servicio("PostgreSQL", URL_APLICACION, 5432)


@pytest.fixture
async def motor_propietario(_postgres_en_marcha: None) -> AsyncIterator[AsyncEngine]:
    """Conexion con privilegios de propietario. Solo para sembrar y aserciones de esquema."""
    motor = create_async_engine(URL_PROPIETARIO, poolclass=NullPool)
    try:
        yield motor
    finally:
        await motor.dispose()


@pytest.fixture
async def motor_de_aplicacion(_postgres_en_marcha: None) -> AsyncIterator[AsyncEngine]:
    """
    Motor construido con la misma funcion que usa la aplicacion.

    Importa que sea `crear_engine` y no un `create_async_engine` suelto:
    si esa funcion introdujera un ajuste que rompiera el aislamiento, el
    test debe verlo.
    """
    motor = crear_engine(
        URL_APLICACION,
        pool_size=2,
        max_overflow=0,
        command_timeout=10,
        echo=False,
    )
    try:
        yield motor
    finally:
        await motor.dispose()


@pytest.fixture
def fabrica(motor_de_aplicacion: AsyncEngine) -> FabricaDeSesiones:
    return FabricaDeSesiones(motor_de_aplicacion)


@pytest.fixture
async def tenants(motor_propietario: AsyncEngine) -> AsyncIterator[DosTenants]:
    """Siembra dos tenants aislados y los borra al terminar."""
    datos = DosTenants(a=uuid4(), b=uuid4(), usuario_a=uuid4(), usuario_b=uuid4())
    sufijo = datos.a.hex[:8]

    async with motor_propietario.begin() as conexion:
        for etiqueta, tenant_id, user_id in (
            ("a", datos.a, datos.usuario_a),
            ("b", datos.b, datos.usuario_b),
        ):
            await conexion.execute(
                text("INSERT INTO tenants (id, nombre, slug) VALUES (:id, :nombre, :slug)"),
                {
                    "id": tenant_id,
                    "nombre": f"Prueba {etiqueta} {sufijo}",
                    "slug": f"prueba-{etiqueta}-{sufijo}",
                },
            )
            await conexion.execute(
                text(
                    "INSERT INTO users (id, external_id, email, nombre_visible) "
                    "VALUES (:id, :externo, :email, :nombre)"
                ),
                {
                    "id": user_id,
                    "externo": f"auth0|{user_id.hex}",
                    "email": f"{etiqueta}-{sufijo}@ejemplo.test",
                    "nombre": f"Usuario {etiqueta}",
                },
            )

    try:
        yield datos
    finally:
        # El borrado en cascada de `tenants` arrastra las filas de negocio.
        async with motor_propietario.begin() as conexion:
            await conexion.execute(
                text("DELETE FROM tenants WHERE id = ANY(:ids)"),
                {"ids": [datos.a, datos.b]},
            )
            await conexion.execute(
                text("DELETE FROM users WHERE id = ANY(:ids)"),
                {"ids": [datos.usuario_a, datos.usuario_b]},
            )


async def sembrar_escaneo(motor: AsyncEngine, tenant_id: UUID, usuario_id: UUID) -> UUID:
    """
    Inserta un `scan_jobs` como propietario y devuelve su identificador.

    Se siembra con el rol propietario a proposito: el test necesita que la
    fila exista con independencia de RLS para luego comprobar que el rol
    de aplicacion no la ve.
    """
    trabajo_id = uuid4()
    async with motor.begin() as conexion:
        await conexion.execute(
            text(
                "INSERT INTO scan_jobs "
                "(id, tenant_id, solicitado_por, conexion_id, encolado_en) "
                "VALUES (:id, :tenant, :usuario, :conexion, now())"
            ),
            {
                "id": trabajo_id,
                "tenant": tenant_id,
                "usuario": usuario_id,
                "conexion": uuid4(),
            },
        )
    return trabajo_id


@pytest.fixture
async def redis() -> AsyncIterator[Redis]:
    exigir_servicio("Redis", URL_REDIS, 6379)
    cliente: Redis = Redis.from_url(URL_REDIS, decode_responses=True)
    try:
        await cliente.flushdb()
        yield cliente
    finally:
        await cliente.flushdb()
        await cliente.aclose()
