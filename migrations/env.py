"""
Entorno de Alembic.

Proposito
    Ejecutar migraciones contra la base de datos configurada, con la
    metadata completa de la aplicacion para que el autogenerate sea fiable.

Dependencias
    Alembic, SQLAlchemy y la configuracion de la aplicacion.

Decision de diseño
    Los modelos se importan explicitamente aqui. Sin esos imports, su
    metadata no esta registrada y `alembic revision --autogenerate`
    generaria un DROP TABLE de cada tabla que no "ve". Es el fallo
    clasico de Alembic y la razon de que estos imports no sean codigo
    muerto, aunque el linter lo parezca.

    Las migraciones corren sobre el mismo driver que la aplicacion
    (asyncpg) en lugar de sobre un driver sincrono aparte. Alembic no es
    async, asi que el puente lo hace `connection.run_sync`. La
    alternativa —reescribir la URL a `postgresql://`— exige un segundo
    driver (SQLAlchemy 2.1 resuelve ese prefijo a psycopg 3) y haria que
    un problema de conexion o de TLS se comportara distinto en las
    migraciones que en la aplicacion.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, pool
from sqlalchemy.ext.asyncio import create_async_engine

from mailauto.bootstrap.settings import get_settings

# Importaciones con efecto de registro en Base.metadata. No eliminar.
from mailauto.modules.audit.infrastructure import repository as _audit  # noqa: F401
from mailauto.modules.extraction.infrastructure.persistence import (  # noqa: F401
    models as _extraction,
)
from mailauto.modules.identity.infrastructure import models as _identity  # noqa: F401
from mailauto.modules.ingestion.infrastructure import models as _ingestion  # noqa: F401
from mailauto.modules.mailbox.infrastructure import models as _mailbox  # noqa: F401
from mailauto.modules.reporting.infrastructure import models as _reporting  # noqa: F401
from mailauto.shared.db.base import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# La URL no se escribe en `config` con `set_main_option`: ese fichero lo
# lee ConfigParser, que interpreta `%` como interpolacion. Una
# contraseña con `%` —habitual cuando viene percent-encoded de un
# gestor de secretos— reventaria antes de intentar conectar.
_URL_DE_BASE_DE_DATOS = str(get_settings().database_url)


def run_migrations_offline() -> None:
    """Genera el SQL sin conectar. Util para revisarlo antes de aplicarlo."""
    context.configure(
        url=_URL_DE_BASE_DE_DATOS,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _ejecutar(conexion: Connection) -> None:
    """Cuerpo sincrono de la migracion, invocado desde `run_sync`."""
    context.configure(
        connection=conexion,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        # Una migracion que falla a medias deja el esquema en un estado
        # que nadie sabe describir. En PostgreSQL el DDL es
        # transaccional, asi que se aprovecha.
        transaction_per_migration=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _aplicar_migraciones() -> None:
    # NullPool: el proceso aplica las migraciones y termina. Un pool con
    # conexiones vivas solo retrasaria la salida.
    motor = create_async_engine(_URL_DE_BASE_DE_DATOS, poolclass=pool.NullPool)
    try:
        async with motor.connect() as conexion:
            await conexion.run_sync(_ejecutar)
    finally:
        await motor.dispose()


def run_migrations_online() -> None:
    """Aplica las migraciones contra la base de datos."""
    asyncio.run(_aplicar_migraciones())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
