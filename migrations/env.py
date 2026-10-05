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
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

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

config.set_main_option("sqlalchemy.url", get_settings().database_url_sync)


def run_migrations_offline() -> None:
    """Genera el SQL sin conectar. Util para revisarlo antes de aplicarlo."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Aplica las migraciones contra la base de datos."""
    conexion_config = config.get_section(config.config_ini_section, {})
    engine = engine_from_config(conexion_config, prefix="sqlalchemy.", poolclass=pool.NullPool)

    with engine.connect() as conexion:
        context.configure(
            connection=conexion,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            # Una migracion que falla a medias deja el esquema en un
            # estado que nadie sabe describir. En PostgreSQL el DDL es
            # transaccional, asi que se aprovecha.
            transaction_per_migration=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
