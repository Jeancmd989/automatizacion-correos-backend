"""Esquema inicial con aislamiento multi-tenant por Row Level Security.

Revision ID: 0001_inicial
Revises:
Create Date: 2026-01-05

Esta migracion crea las tablas y, sobre todo, activa RLS en todas las que
llevan `tenant_id`. El aislamiento vive aqui, en la base de datos, y no
solo en el codigo de los repositorios: es la segunda barrera que convierte
un WHERE olvidado en cero filas en lugar de una fuga de datos (hallazgo H1
del sistema de referencia).

Requisito operativo: la aplicacion debe conectarse con un rol que NO sea
superusuario ni propietario de las tablas. PostgreSQL omite RLS para
ambos, asi que con un rol privilegiado las politicas no se aplican y el
aislamiento desaparece sin ningun aviso. El test de integracion
`test_rls_bloquea_acceso_cruzado` verifica que esto se cumple.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_inicial"
down_revision = None
branch_labels = None
depends_on = None

# Tablas de negocio: todas llevan tenant_id y todas reciben politica RLS.
_TABLAS_CON_TENANT = (
    "encryption_keys",
    "mailbox_connections",
    "scan_jobs",
    "email_messages",
    "attachments",
    "processing_errors",
    "audit_log",
)


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "citext"')

    _crear_tablas_de_identidad()
    _crear_tablas_de_buzones()
    _crear_tablas_de_ingesta()
    _crear_tabla_de_auditoria()
    _activar_rls()


def downgrade() -> None:
    for tabla in _TABLAS_CON_TENANT:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {tabla}")
    op.execute("DROP POLICY IF EXISTS audit_insert_only ON audit_log")

    for tabla in (
        "audit_log",
        "processing_errors",
        "attachments",
        "email_messages",
        "scan_jobs",
        "mailbox_connections",
        "encryption_keys",
        "memberships",
        "users",
        "tenants",
    ):
        op.drop_table(tabla)


# ─────────────────────────────────────────────────────────────────────
# Identidad
# ─────────────────────────────────────────────────────────────────────


def _crear_tablas_de_identidad() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("nombre", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False, unique=True),
        sa.Column("estado", sa.String(20), nullable=False, server_default="active"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"])

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("external_id", sa.String(255), nullable=False, unique=True),
        sa.Column("email", sa.String(320), nullable=False, server_default=""),
        sa.Column("nombre_visible", sa.String(200), nullable=False, server_default=""),
        sa.Column("estado", sa.String(20), nullable=False, server_default="active"),
        sa.Column("ultimo_acceso_en", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_users_external_id", "users", ["external_id"])

    op.create_table(
        "memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rol", sa.String(20), nullable=False, server_default="viewer"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("tenant_id", "user_id", name="uq_memberships_tenant_user"),
    )
    op.create_index("ix_memberships_user", "memberships", ["user_id"])


# ─────────────────────────────────────────────────────────────────────
# Buzones
# ─────────────────────────────────────────────────────────────────────


def _crear_tablas_de_buzones() -> None:
    op.create_table(
        "encryption_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("dek_envuelta", sa.LargeBinary(), nullable=False),
        sa.Column("version_kek", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("estado", sa.String(20), nullable=False, server_default="active"),
        sa.Column("rotada_en", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    # Indice parcial: solo hay una clave activa por tenant y es la unica
    # que se busca en el camino caliente.
    op.execute(
        "CREATE UNIQUE INDEX ix_encryption_keys_tenant_activa "
        "ON encryption_keys (tenant_id) WHERE estado = 'active'"
    )

    op.create_table(
        "mailbox_connections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("proveedor", sa.String(20), nullable=False),
        sa.Column("correo_de_la_cuenta", sa.String(320), nullable=False, server_default=""),
        sa.Column("access_token_ct", sa.LargeBinary(), nullable=False),
        sa.Column("refresh_token_ct", sa.LargeBinary(), nullable=True),
        sa.Column(
            "dek_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("encryption_keys.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "alcances_concedidos",
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("expira_en", sa.DateTime(timezone=True), nullable=False),
        sa.Column("estado", sa.String(20), nullable=False, server_default="active"),
        sa.Column("verificada_en", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint(
            "tenant_id", "user_id", "proveedor", name="uq_mailbox_tenant_user_provider"
        ),
    )
    op.create_index("ix_mailbox_tenant_estado", "mailbox_connections", ["tenant_id", "estado"])


# ─────────────────────────────────────────────────────────────────────
# Ingesta
# ─────────────────────────────────────────────────────────────────────


def _crear_tablas_de_ingesta() -> None:
    op.create_table(
        "scan_jobs",
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
        sa.Column("conexion_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("estado", sa.String(20), nullable=False, server_default="queued"),
        sa.Column("fase", sa.String(20), nullable=False, server_default="waiting"),
        sa.Column("progreso_porcentaje", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("parametros", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("contadores", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("clave_de_idempotencia", sa.String(128), nullable=True),
        sa.Column("intento", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("codigo_de_error", sa.String(64), nullable=True),
        sa.Column("mensaje_de_error", sa.Text(), nullable=True),
        sa.Column("encolado_en", sa.DateTime(timezone=True), nullable=False),
        sa.Column("iniciado_en", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finalizado_en", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint(
            "tenant_id", "clave_de_idempotencia", name="uq_scan_jobs_tenant_idempotency"
        ),
    )
    op.create_index(
        "ix_scan_jobs_tenant_estado_encolado", "scan_jobs", ["tenant_id", "estado", "encolado_en"]
    )
    op.create_index("ix_scan_jobs_tenant_created", "scan_jobs", ["tenant_id", "created_at"])

    op.create_table(
        "email_messages",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "trabajo_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("proveedor", sa.String(20), nullable=False),
        sa.Column("id_del_proveedor", sa.String(255), nullable=False),
        sa.Column("remitente", sa.String(320), nullable=False, server_default=""),
        sa.Column("asunto", sa.Text(), nullable=False, server_default=""),
        sa.Column("recibido_en", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint(
            "tenant_id", "proveedor", "id_del_proveedor", name="uq_messages_tenant_provider_id"
        ),
    )
    op.create_index("ix_messages_trabajo", "email_messages", ["tenant_id", "trabajo_id"])

    op.create_table(
        "attachments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "mensaje_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("email_messages.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("nombre_original", sa.String(255), nullable=False, server_default=""),
        sa.Column("clave_de_almacenamiento", sa.String(512), nullable=False),
        sa.Column("tipo_mime", sa.String(100), nullable=False),
        sa.Column("tamano_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("estado_antivirus", sa.String(20), nullable=False, server_default="skipped"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("tenant_id", "sha256", name="uq_attachments_tenant_sha"),
    )
    op.create_index("ix_attachments_mensaje", "attachments", ["tenant_id", "mensaje_id"])

    op.create_table(
        "processing_errors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "trabajo_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("etapa", sa.String(20), nullable=False),
        sa.Column("codigo", sa.String(64), nullable=False),
        sa.Column("mensaje", sa.Text(), nullable=False, server_default=""),
        sa.Column("contexto", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("reintentable", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_errors_tenant_created", "processing_errors", ["tenant_id", "created_at"])
    op.create_index("ix_errors_trabajo", "processing_errors", ["tenant_id", "trabajo_id"])


def _crear_tabla_de_auditoria() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_ip", postgresql.INET(), nullable=True),
        sa.Column("accion", sa.String(64), nullable=False),
        sa.Column("tipo_de_recurso", sa.String(64), nullable=False, server_default=""),
        sa.Column("recurso_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("metadatos", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "ocurrido_en", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_audit_tenant_ocurrido", "audit_log", ["tenant_id", "ocurrido_en"])


# ─────────────────────────────────────────────────────────────────────
# Row Level Security
# ─────────────────────────────────────────────────────────────────────


def _activar_rls() -> None:
    """
    Activa el aislamiento por tenant en la base de datos.

    `FORCE ROW LEVEL SECURITY` es imprescindible: sin el, PostgreSQL
    exime al propietario de la tabla de sus propias politicas. Si la
    aplicacion y el propietario coincidieran (algo habitual en un montaje
    descuidado), RLS estaria activo y no filtraria nada.

    La politica compara contra `current_setting('app.current_tenant',
    true)`. El segundo argumento `true` hace que devuelva NULL en lugar
    de error cuando la variable no esta fijada, y entonces la comparacion
    es NULL: no se ve ninguna fila. Ese es el comportamiento deseado,
    porque una consulta sin tenant declarado es un error de programacion
    y debe devolver vacio, no todo.
    """
    for tabla in _TABLAS_CON_TENANT:
        op.execute(f"ALTER TABLE {tabla} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {tabla} FORCE ROW LEVEL SECURITY")

    # Politica general: lectura y escritura solo dentro del propio tenant.
    # `WITH CHECK` cubre INSERT y UPDATE: impide escribir una fila con el
    # tenant_id de otro, que seria la forma de inyectar datos ajenos.
    for tabla in (t for t in _TABLAS_CON_TENANT if t != "audit_log"):
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {tabla}
                USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid)
            """
        )

    # La bitacora es append-only: se puede insertar y leer dentro del
    # tenant, pero no actualizar ni borrar. Una auditoria que el propio
    # sistema puede reescribir no sirve como evidencia.
    op.execute(
        """
        CREATE POLICY tenant_isolation ON audit_log
            FOR SELECT
            USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
        """
    )
    op.execute(
        """
        CREATE POLICY audit_insert_only ON audit_log
            FOR INSERT
            WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid)
        """
    )
