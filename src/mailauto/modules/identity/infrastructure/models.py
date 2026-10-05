"""
Modelos de persistencia del contexto de identidad.

Proposito
    Mapear tenants, usuarios y membresias a tablas, manteniendo el mapeo
    separado de las entidades de dominio.

Dependencias
    SQLAlchemy y el `Base` compartido.

Decision de diseño
    Modelos de persistencia distintos de las entidades de dominio, aunque
    al principio se parezcan. Fusionarlos ata el dominio al ORM: cualquier
    cambio de esquema (una columna desnormalizada por rendimiento, una
    tabla partida en dos) se propagaria a las reglas de negocio. El coste
    es un mapeo explicito en el repositorio; la ventaja es que el dominio
    se puede testear sin base de datos.

    Estas tres tablas NO llevan `tenant_id` ni RLS: son las que deciden a
    que tenant pertenece cada usuario, asi que no pueden filtrarse por el.
    Su proteccion es que solo el modulo de identidad las consulta, siempre
    partiendo del `sub` de un token ya verificado.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from mailauto.shared.db.base import Base, MixinDeTimestamps


class TenantORM(MixinDeTimestamps, Base):
    __tablename__ = "tenants"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    nombre: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True, index=True)
    estado: Mapped[str] = mapped_column(String(20), nullable=False, default="active")


class UsuarioORM(MixinDeTimestamps, Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    # `external_id` es el 'sub' del IdP: el indice unico es la via de
    # busqueda en cada peticion autenticada, asi que debe ser instantaneo.
    external_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    nombre_visible: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    estado: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    ultimo_acceso_en: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class MembresiaORM(MixinDeTimestamps, Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id", name="uq_memberships_tenant_user"),)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    rol: Mapped[str] = mapped_column(String(20), nullable=False, default="viewer")
