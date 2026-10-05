"""
Modelos de persistencia del contexto de ingesta.

Proposito
    Mapear trabajos, correos, adjuntos y errores, con los indices y las
    restricciones que sostienen la idempotencia y la deduplicacion.

Dependencias
    SQLAlchemy y el `Base` compartido.

Decision de diseño
    Las restricciones de unicidad incluyen siempre `tenant_id`. Dos
    tenants distintos pueden recibir el mismo correo reenviado o el mismo
    PDF: una unicidad global los haria colisionar y uno de los dos
    perderia su dato.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from mailauto.shared.db.base import Base, MixinDeTenant, MixinDeTimestamps


class TrabajoDeEscaneoORM(MixinDeTenant, MixinDeTimestamps, Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "clave_de_idempotencia", name="uq_scan_jobs_tenant_idempotency"
        ),
        # Indice del panel de trabajos y del conteo de activos: ambas
        # consultas filtran por tenant + estado y ordenan por fecha.
        Index("ix_scan_jobs_tenant_estado_encolado", "tenant_id", "estado", "encolado_en"),
        Index("ix_scan_jobs_tenant_created", "tenant_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    solicitado_por: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    conexion_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)

    estado: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    fase: Mapped[str] = mapped_column(String(20), nullable=False, default="waiting")
    progreso_porcentaje: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    parametros: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    contadores: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    clave_de_idempotencia: Mapped[str | None] = mapped_column(String(128), nullable=True)
    intento: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    codigo_de_error: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mensaje_de_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    encolado_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    iniciado_en: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finalizado_en: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MensajeDeCorreoORM(MixinDeTenant, MixinDeTimestamps, Base):
    __tablename__ = "email_messages"
    __table_args__ = (
        # Clave de idempotencia de la ingesta: el mismo correo nunca se
        # procesa dos veces para un mismo tenant, aunque se lancen
        # escaneos solapados.
        UniqueConstraint(
            "tenant_id", "proveedor", "id_del_proveedor", name="uq_messages_tenant_provider_id"
        ),
        Index("ix_messages_trabajo", "tenant_id", "trabajo_id"),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    trabajo_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    proveedor: Mapped[str] = mapped_column(String(20), nullable=False)
    id_del_proveedor: Mapped[str] = mapped_column(String(255), nullable=False)
    remitente: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    asunto: Mapped[str] = mapped_column(Text, nullable=False, default="")
    recibido_en: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AdjuntoORM(MixinDeTenant, MixinDeTimestamps, Base):
    __tablename__ = "attachments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "sha256", name="uq_attachments_tenant_sha"),
        Index("ix_attachments_mensaje", "tenant_id", "mensaje_id"),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    mensaje_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("email_messages.id", ondelete="CASCADE"), nullable=False
    )
    # Solo para mostrar. La ruta real es `clave_de_almacenamiento`.
    nombre_original: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    clave_de_almacenamiento: Mapped[str] = mapped_column(String(512), nullable=False)
    tipo_mime: Mapped[str] = mapped_column(String(100), nullable=False)
    tamano_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    estado_antivirus: Mapped[str] = mapped_column(String(20), nullable=False, default="skipped")


class ErrorDeProcesamientoORM(MixinDeTenant, MixinDeTimestamps, Base):
    __tablename__ = "processing_errors"
    __table_args__ = (
        Index("ix_errors_tenant_created", "tenant_id", "created_at"),
        Index("ix_errors_trabajo", "tenant_id", "trabajo_id"),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    trabajo_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    etapa: Mapped[str] = mapped_column(String(20), nullable=False)
    codigo: Mapped[str] = mapped_column(String(64), nullable=False)
    mensaje: Mapped[str] = mapped_column(Text, nullable=False, default="")
    contexto: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    reintentable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
