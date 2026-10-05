"""
Base declarativa y mixins de persistencia.

Proposito
    Dar a todas las tablas la misma forma: tipos coherentes, marcas de
    tiempo automaticas y columna de tenant donde corresponde.

Dependencias
    SQLAlchemy 2.0 (API declarativa tipada).

Decision de diseño
    `MixinDeTenant` no es opcional en las tablas de negocio: aporta la
    columna sobre la que opera RLS. Una tabla de negocio sin este mixin es
    un fallo de aislamiento, y el test de integracion
    `test_todas_las_tablas_de_negocio_tienen_rls` lo detecta.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, MetaData, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Convencion de nombres explicita: sin ella, Alembic genera constraints con
# nombres autogenerados por PostgreSQL que cambian entre entornos y hacen
# que las migraciones de rollback fallen.
CONVENCION_DE_NOMBRES = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base declarativa comun."""

    metadata = MetaData(naming_convention=CONVENCION_DE_NOMBRES)


class MixinDeTimestamps:
    """
    Marcas de creacion y actualizacion gestionadas por la base de datos.

    `server_default=func.now()` en lugar de un default de Python: el reloj
    de la BD es la unica referencia consistente cuando hay varias replicas
    de API con desfase de reloj entre si.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class MixinDeTenant:
    """
    Columna de tenant sobre la que actuan las politicas RLS.

    `ondelete="CASCADE"`: al eliminar un tenant (derecho de supresion),
    sus datos se van con el, sin dejar filas huerfanas que RLS ya no
    filtraria por no tener dueño.
    """

    tenant_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
