"""
Tests de autorizacion y aislamiento entre tenants.

Son los tests que cierran el hallazgo H1 del sistema de referencia, donde
cualquier usuario autenticado podia descargar los datos tributarios de
todos. Aqui se comprueba la barrera de aplicacion; la de base de datos
(RLS) se verifica en tests/integration.
"""

from __future__ import annotations

import pytest

from mailauto.shared.errors import ErrorDeAutorizacion
from mailauto.shared.security.context import Permiso, Rol, TenantContext, permisos_de

pytestmark = pytest.mark.security


# ── Matriz de permisos por rol ───────────────────────────────────────


def test_viewer_no_puede_lanzar_escaneos() -> None:
    assert Permiso.SCAN_RUN not in permisos_de(Rol.VIEWER)


def test_viewer_no_puede_escribir_buzones() -> None:
    assert Permiso.MAILBOX_WRITE not in permisos_de(Rol.VIEWER)


def test_operator_no_tiene_permisos_administrativos() -> None:
    """La escalada mas probable: un operador que accede a la purga o a la auditoria."""
    permisos = permisos_de(Rol.OPERATOR)
    assert Permiso.ADMIN_WRITE not in permisos
    assert Permiso.ADMIN_READ not in permisos


def test_admin_no_hereda_todo_por_accidente() -> None:
    """ADMIN es explicito, no "todos los permisos": OWNER si lo es."""
    assert permisos_de(Rol.ADMIN) != permisos_de(Rol.OWNER)


def test_owner_tiene_todos_los_permisos() -> None:
    assert permisos_de(Rol.OWNER) == frozenset(Permiso)


@pytest.mark.parametrize("rol", list(Rol))
def test_todo_rol_puede_leer_registros_pero_no_todos_escribir(rol: Rol) -> None:
    permisos = permisos_de(rol)
    assert Permiso.RECORD_READ in permisos
    if rol is Rol.VIEWER:
        assert Permiso.RECORD_REVIEW not in permisos


# ── exigir() ─────────────────────────────────────────────────────────


def test_exigir_lanza_cuando_falta_el_permiso(contexto_a: TenantContext) -> None:
    with pytest.raises(ErrorDeAutorizacion) as excinfo:
        contexto_a.exigir(Permiso.ADMIN_WRITE)
    assert excinfo.value.estado_http == 403


def test_exigir_pasa_cuando_el_permiso_existe(contexto_a: TenantContext) -> None:
    contexto_a.exigir(Permiso.SCAN_RUN)  # no debe lanzar


def test_el_detalle_del_rechazo_no_llega_al_cliente(contexto_a: TenantContext) -> None:
    """
    El contexto de diagnostico (que permiso falto, con que rol) va al log,
    no al mensaje publico: convertirlo en respuesta le dice al atacante
    exactamente que necesita conseguir.
    """
    with pytest.raises(ErrorDeAutorizacion) as excinfo:
        contexto_a.exigir(Permiso.ADMIN_WRITE)

    publico = excinfo.value.mensaje_publico
    assert "admin:write" not in publico
    assert "operator" not in publico
    assert "admin:write" in excinfo.value.contexto["permiso_requerido"]


# ── Aislamiento entre tenants ────────────────────────────────────────


def test_un_contexto_no_accede_a_recursos_de_otro_tenant(
    contexto_a: TenantContext, contexto_b: TenantContext
) -> None:
    with pytest.raises(ErrorDeAutorizacion):
        contexto_a.exigir_mismo_tenant(contexto_b.tenant_id)


def test_un_contexto_accede_a_sus_propios_recursos(contexto_a: TenantContext) -> None:
    contexto_a.exigir_mismo_tenant(contexto_a.tenant_id)  # no debe lanzar


def test_el_contexto_es_inmutable(contexto_a: TenantContext) -> None:
    """
    Nadie puede cambiar de tenant a mitad de la operacion. Si el contexto
    fuera mutable, un bug (o una llamada maliciosa a una funcion interna)
    podria reapuntarlo despues de que la autorizacion ya paso.
    """
    with pytest.raises((AttributeError, TypeError)):
        contexto_a.tenant_id = contexto_a.user_id  # type: ignore[misc]


def test_el_log_del_contexto_no_expone_datos_personales(
    contexto_a: TenantContext,
) -> None:
    campos = contexto_a.para_log()
    assert set(campos) == {"tenant_id", "user_id", "rol"}
    assert "external_id" not in campos
    assert "ip_origen" not in campos
