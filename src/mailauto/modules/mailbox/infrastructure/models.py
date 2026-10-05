"""
Modelos de persistencia de buzones y claves de cifrado.

Proposito
    Guardar las conexiones OAuth con los tokens cifrados y las DEK
    envueltas por tenant.

Dependencias
    SQLAlchemy y el `Base` compartido.

Decision de diseño
    Los tokens se almacenan como `LargeBinary`, no como texto. Un BYTEA
    deja claro en el propio esquema que ese contenido es opaco y no debe
    leerse ni indexarse; una columna TEXT invita a que alguien la consulte
    "para depurar".
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    ARRAY,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from mailauto.shared.db.base import Base, MixinDeTenant, MixinDeTimestamps


class ClaveDeCifradoORM(MixinDeTenant, MixinDeTimestamps, Base):
    """
    DEK por tenant, almacenada envuelta por la KEK.

    Destruir esta fila inutiliza criptograficamente todos los datos
    cifrados de ese tenant: es el mecanismo de borrado inmediato ante una
    solicitud de supresion, sin esperar a que la purga fisica recorra
    todas las tablas.
    """

    __tablename__ = "encryption_keys"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    dek_envuelta: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    version_kek: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    estado: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    rotada_en: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ConexionDeBuzonORM(MixinDeTenant, MixinDeTimestamps, Base):
    __tablename__ = "mailbox_connections"
    __table_args__ = (
        # Un usuario tiene como mucho una conexion viva por proveedor.
        # Reconectar actualiza la fila en lugar de acumular credenciales
        # antiguas que seguirian siendo validas.
        UniqueConstraint(
            "tenant_id", "user_id", "proveedor", name="uq_mailbox_tenant_user_provider"
        ),
        Index("ix_mailbox_tenant_estado", "tenant_id", "estado"),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    proveedor: Mapped[str] = mapped_column(String(20), nullable=False)
    correo_de_la_cuenta: Mapped[str] = mapped_column(String(320), nullable=False, default="")

    access_token_ct: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    refresh_token_ct: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    dek_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("encryption_keys.id", ondelete="RESTRICT"), nullable=False
    )

    alcances_concedidos: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    expira_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    estado: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    verificada_en: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
