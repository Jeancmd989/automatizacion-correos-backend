"""Endurecer el aislamiento: tolerar la variable vacia y blindar la bitacora.

Revision ID: 0003_endurecer_aislamiento
Revises: 0002_extraccion
Create Date: 2026-10-05

Dos defectos que solo aparecen ejecutando contra PostgreSQL y que los
tests de integracion de la fase 7 destaparon.

1. `current_setting('app.current_tenant', true)` devuelve NULL solo
   mientras la variable NUNCA se ha fijado en esa conexion. En cuanto
   una transaccion hace `SET LOCAL`, al terminar la variable no vuelve a
   estar indefinida: queda como CADENA VACIA. El cast `''::uuid` lanza
   `invalid input syntax for type uuid: ""`.

   Como las conexiones se reciclan en un pool, basta que una conexion
   haya servido a un tenant para que la siguiente consulta sin tenant
   declarado sobre una tabla de negocio falle con un 500 en lugar de
   devolver cero filas. Se rompe la garantia de "fallar cerrado": no
   filtra mal, pero deja de funcionar, y el diagnostico es oscuro
   porque el error habla de un UUID que nadie escribio.

   `nullif(..., '')` devuelve NULL tanto si la variable no existe como
   si esta vacia. La comparacion vuelve a ser NULL, no se ve ninguna
   fila, y no hay excepcion.

2. La bitacora de auditoria solo tiene politicas de SELECT e INSERT, asi
   que un UPDATE o un DELETE no encuentran ninguna fila que tocar. Es
   correcto, pero silencioso: la sentencia termina con exito y cero
   filas afectadas. Ademas depende por completo de que RLS siga activo.
   Retirar los privilegios UPDATE y DELETE sobre `audit_log` convierte
   el intento en un error explicito de permisos, independiente de RLS, y
   deja rastro en el log de PostgreSQL.
"""

from __future__ import annotations

from alembic import op

revision = "0003_endurecer_aislamiento"
down_revision = "0002_extraccion"
branch_labels = None
depends_on = None

# Esta migracion no crea tablas nuevas, solo rehace las politicas de las
# que ya estan protegidas. La constante se mantiene por el contrato que
# leen los tests: una lista vacia es la respuesta correcta aqui.
TABLAS_CON_RLS: tuple[str, ...] = ()

# Todas las tablas cuyas politicas se reescriben. Se enumeran de forma
# explicita y no importando las migraciones anteriores: una migracion
# debe seguir aplicandose igual aunque mañana alguien reorganice las
# constantes de otro fichero.
_TABLAS_DE_NEGOCIO: tuple[str, ...] = (
    "attachments",
    "email_messages",
    "encryption_keys",
    "extracted_records",
    "mailbox_connections",
    "processing_errors",
    "report_exports",
    "scan_jobs",
)

_TENANT_ACTUAL_TOLERANTE = "nullif(current_setting('app.current_tenant', true), '')::uuid"
_TENANT_ACTUAL_ESTRICTO = "current_setting('app.current_tenant', true)::uuid"

# Retira la escritura sobre la bitacora de cualquier rol que la tenga,
# salvo el propietario que ejecuta la migracion.
#
# El nombre del rol de aplicacion no se escribe aqui a proposito: lo
# decide la infraestructura de cada entorno y una migracion que lo
# hardcodease solo funcionaria en desarrollo. Se consulta quien tiene
# hoy el privilegio y se le retira.
_BLINDAR_BITACORA = """
DO $$
DECLARE
    rol text;
BEGIN
    FOR rol IN
        SELECT DISTINCT grantee
        FROM information_schema.role_table_grants
        WHERE table_schema = 'public'
          AND table_name = 'audit_log'
          AND privilege_type IN ('UPDATE', 'DELETE')
          AND grantee <> current_user
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE ON audit_log FROM %I', rol);
    END LOOP;
END
$$;
"""


def _rehacer_politicas(expresion_de_tenant: str) -> None:
    """
    Reemplaza las politicas con la expresion indicada.

    Se borra y se crea en lugar de usar `ALTER POLICY` porque la version
    anterior del esquema pudo quedar a medias si una migracion fallo, y
    `DROP POLICY IF EXISTS` es la unica forma de partir de un estado
    conocido.
    """
    for tabla in _TABLAS_DE_NEGOCIO:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {tabla}")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {tabla}
                USING (tenant_id = {expresion_de_tenant})
                WITH CHECK (tenant_id = {expresion_de_tenant})
            """
        )

    op.execute("DROP POLICY IF EXISTS tenant_isolation ON audit_log")
    op.execute(
        f"""
        CREATE POLICY tenant_isolation ON audit_log
            FOR SELECT
            USING (tenant_id = {expresion_de_tenant})
        """
    )
    op.execute("DROP POLICY IF EXISTS audit_insert_only ON audit_log")
    op.execute(
        f"""
        CREATE POLICY audit_insert_only ON audit_log
            FOR INSERT
            WITH CHECK (tenant_id = {expresion_de_tenant})
        """
    )


def upgrade() -> None:
    _rehacer_politicas(_TENANT_ACTUAL_TOLERANTE)
    op.execute(_BLINDAR_BITACORA)


def downgrade() -> None:
    # Se devuelven los privilegios de escritura sobre la bitacora porque
    # el estado anterior los tenia; quien revierta esta migracion vuelve
    # tambien a su nivel de proteccion.
    op.execute(
        """
        DO $$
        DECLARE
            rol text;
        BEGIN
            FOR rol IN
                SELECT DISTINCT grantee
                FROM information_schema.role_table_grants
                WHERE table_schema = 'public'
                  AND table_name = 'audit_log'
                  AND privilege_type = 'SELECT'
                  AND grantee <> current_user
            LOOP
                EXECUTE format('GRANT UPDATE, DELETE ON audit_log TO %I', rol);
            END LOOP;
        END
        $$;
        """
    )
    _rehacer_politicas(_TENANT_ACTUAL_ESTRICTO)
