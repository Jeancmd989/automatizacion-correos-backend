"""Registros extraidos y exportaciones de reporte.

Revision ID: 0002_extraccion
Revises: 0001_inicial
Create Date: 2026-01-05

Añade las dos tablas de las fases 4 y 5, con las mismas dos barreras de
aislamiento que el resto: columna `tenant_id` y politica RLS. Olvidar
la politica en una tabla nueva es la forma habitual de abrir un agujero
en un esquema que por lo demas esta bien protegido, asi que el test de
integracion `test_todas_las_tablas_de_negocio_tienen_rls` recorre el
catalogo y falla si aparece una tabla con `tenant_id` y sin politica.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_extraccion"
down_revision = "0001_inicial"
branch_labels = None
depends_on = None

# Ver la nota sobre el nombre de esta constante en la migracion 0001:
# el test de cobertura de RLS la lee de cada migracion.
TABLAS_CON_RLS = ("extracted_records", "report_exports")


def upgrade() -> None:
    _crear_registros()
    _crear_exportaciones()
    _activar_rls()


def downgrade() -> None:
    for tabla in TABLAS_CON_RLS:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {tabla}")
    op.drop_table("report_exports")
    op.drop_table("extracted_records")


def _crear_registros() -> None:
    op.create_table(
        "extracted_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "adjunto_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attachments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "trabajo_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("perfil", sa.String(64), nullable=False),
        sa.Column("ruc_contribuyente", sa.String(11), nullable=True),
        sa.Column("nombre_contribuyente", sa.String(120), nullable=False, server_default=""),
        sa.Column("ruc_inquilino", sa.String(11), nullable=True),
        sa.Column("nombre_inquilino", sa.String(120), nullable=False, server_default=""),
        # YYYYMM: ordenar alfabeticamente equivale a ordenar en el tiempo.
        sa.Column("periodo", sa.String(6), nullable=True),
        sa.Column("fecha_de_pago", sa.Date(), nullable=True),
        sa.Column("numero_de_operacion", sa.String(40), nullable=True),
        # Numeric y no float: un reporte tributario cuadra al centimo.
        sa.Column("importe", sa.Numeric(14, 2), nullable=True),
        sa.Column("moneda", sa.String(3), nullable=False, server_default="PEN"),
        sa.Column("campos_crudos", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("confianza_por_campo", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("completitud", sa.String(20), nullable=False, server_default="empty"),
        sa.Column(
            "estado_de_revision", sa.String(20), nullable=False, server_default="not_required"
        ),
        sa.Column("revisado_por", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("revisado_en", sa.DateTime(timezone=True), nullable=True),
        sa.Column("estrategia_usada", sa.String(32), nullable=True),
        sa.Column("duracion_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        # Un adjunto produce como mucho un registro: es lo que hace
        # idempotente la reentrega de un job de extraccion.
        sa.UniqueConstraint("tenant_id", "adjunto_id", name="uq_records_tenant_adjunto"),
        sa.CheckConstraint(
            "importe IS NULL OR importe >= 0", name="ck_records_importe_no_negativo"
        ),
    )

    op.create_index("ix_records_tenant_created", "extracted_records", ["tenant_id", "created_at"])
    op.create_index(
        "ix_records_ruc_periodo", "extracted_records", ["tenant_id", "ruc_contribuyente", "periodo"]
    )
    op.create_index("ix_records_trabajo", "extracted_records", ["tenant_id", "trabajo_id"])

    # Indice PARCIAL para la cola de revision: solo indexa lo
    # pendiente, que es una fraccion minima de la tabla. Uno completo
    # sobre `estado_de_revision` ocuparia tanto como la tabla para
    # responder siempre la misma consulta.
    op.execute(
        "CREATE INDEX ix_records_revision_pendiente "
        "ON extracted_records (tenant_id, created_at) "
        "WHERE estado_de_revision = 'pending'"
    )


def _crear_exportaciones() -> None:
    op.create_table(
        "report_exports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "solicitado_por",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("formato", sa.String(10), nullable=False, server_default="xlsx"),
        sa.Column("estado", sa.String(20), nullable=False, server_default="queued"),
        sa.Column("filtros", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("total_filas", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("clave_de_almacenamiento", sa.String(512), nullable=True),
        sa.Column("mensaje_de_error", sa.Text(), nullable=True),
        sa.Column("finalizado_en", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_exports_tenant_created", "report_exports", ["tenant_id", "created_at"])


def _activar_rls() -> None:
    """
    Misma proteccion que las tablas de la migracion inicial.

    `FORCE` es imprescindible: sin el, PostgreSQL exime al propietario
    de la tabla de sus propias politicas, y RLS apareceria activo sin
    filtrar nada.
    """
    for tabla in TABLAS_CON_RLS:
        op.execute(f"ALTER TABLE {tabla} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {tabla} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {tabla}
                USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid)
            """
        )
