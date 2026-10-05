"""
Modelo de persistencia de las exportaciones.

Proposito
    Registrar cada reporte solicitado y su resultado, para poder
    consultarlo despues sin regenerarlo.

Dependencias
    SQLAlchemy y el `Base` compartido.

Decision de diseño
    Una exportacion es una entidad persistida y no una descarga
    directa. Un reporte de miles de filas tarda mas de lo que un
    navegador o un balanceador esperan, asi que se encola, la genera
    un worker y se entrega por URL prefirmada. La fila es tambien lo
    que permite reintentar una generacion fallida sin que el usuario
    repita la solicitud.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from mailauto.shared.db.base import Base, MixinDeTenant, MixinDeTimestamps


class ExportacionORM(MixinDeTenant, MixinDeTimestamps, Base):
    __tablename__ = "report_exports"
    __table_args__ = (Index("ix_exports_tenant_created", "tenant_id", "created_at"),)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    solicitado_por: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    formato: Mapped[str] = mapped_column(String(10), nullable=False, default="xlsx")
    estado: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    filtros: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    total_filas: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    clave_de_almacenamiento: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Mensaje generico para el usuario. El detalle del fallo va al log,
    # no a una columna que la interfaz muestra.
    mensaje_de_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    finalizado_en: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
