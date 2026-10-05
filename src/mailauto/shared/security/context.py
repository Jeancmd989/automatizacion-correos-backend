"""
Contexto de seguridad de la peticion.

Proposito
    Transportar la identidad verificada y el tenant activo desde el borde
    HTTP hasta el repositorio, de forma que sea imposible ejecutar una
    consulta sin saber a quien pertenece.

Dependencias
    Solo biblioteca estandar.

Decision de diseño
    `TenantContext` es un parametro explicito y obligatorio en la firma de
    todo repositorio, no una variable de contexto implicita. Una ContextVar
    se puede olvidar de propagar (y se pierde al cruzar a un worker); un
    parametro obligatorio lo detecta mypy antes de que llegue a ejecutarse.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from mailauto.shared.errors import ErrorDeAutorizacion


class Rol(StrEnum):
    """
    Roles dentro de un tenant, en orden creciente de privilegio.

    Un rol agrupa permisos; la autorizacion se evalua siempre sobre
    permisos concretos, nunca comparando roles con `==` disperso por el
    codigo (eso convierte cada endpoint en una regla de negocio oculta).
    """

    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"
    OWNER = "owner"


class Permiso(StrEnum):
    """Permisos atomicos. Son el vocabulario que usan los endpoints."""

    MAILBOX_READ = "mailbox:read"
    MAILBOX_WRITE = "mailbox:write"
    SCAN_READ = "scan:read"
    SCAN_RUN = "scan:run"
    RECORD_READ = "record:read"
    RECORD_REVIEW = "record:review"
    REPORT_READ = "report:read"
    ADMIN_READ = "admin:read"
    ADMIN_WRITE = "admin:write"
    # Exclusivo de OWNER: gestionar membresias y roles, transferir la
    # propiedad y eliminar el espacio de trabajo. Separarlo de
    # ADMIN_WRITE impide que un administrador se autoconceda la
    # propiedad o expulse al dueño, que es la escalada de privilegio
    # mas obvia dentro de un mismo tenant.
    TENANT_MANAGE = "tenant:manage"


# Mapa rol -> permisos. Es acumulativo y explicito a proposito: leer esta
# tabla responde "que puede hacer un operador" sin rastrear herencias.
_PERMISOS_POR_ROL: dict[Rol, frozenset[Permiso]] = {
    Rol.VIEWER: frozenset(
        {
            Permiso.MAILBOX_READ,
            Permiso.SCAN_READ,
            Permiso.RECORD_READ,
            Permiso.REPORT_READ,
        }
    ),
    Rol.OPERATOR: frozenset(
        {
            Permiso.MAILBOX_READ,
            Permiso.MAILBOX_WRITE,
            Permiso.SCAN_READ,
            Permiso.SCAN_RUN,
            Permiso.RECORD_READ,
            Permiso.RECORD_REVIEW,
            Permiso.REPORT_READ,
        }
    ),
    Rol.ADMIN: frozenset(
        {
            Permiso.MAILBOX_READ,
            Permiso.MAILBOX_WRITE,
            Permiso.SCAN_READ,
            Permiso.SCAN_RUN,
            Permiso.RECORD_READ,
            Permiso.RECORD_REVIEW,
            Permiso.REPORT_READ,
            Permiso.ADMIN_READ,
            Permiso.ADMIN_WRITE,
        }
    ),
    Rol.OWNER: frozenset(Permiso),
}


def permisos_de(rol: Rol) -> frozenset[Permiso]:
    return _PERMISOS_POR_ROL[rol]


@dataclass(frozen=True, slots=True)
class TenantContext:
    """
    Identidad verificada y tenant activo de la peticion en curso.

    Inmutable: una vez resuelto en el borde, ninguna capa posterior puede
    cambiar de tenant a mitad de la operacion.
    """

    tenant_id: UUID
    user_id: UUID
    external_id: str  # 'sub' del proveedor de identidad
    rol: Rol
    permisos: frozenset[Permiso]
    ip_origen: str | None = None
    request_id: str | None = None

    @classmethod
    def construir(
        cls,
        *,
        tenant_id: UUID,
        user_id: UUID,
        external_id: str,
        rol: Rol,
        ip_origen: str | None = None,
        request_id: str | None = None,
    ) -> TenantContext:
        return cls(
            tenant_id=tenant_id,
            user_id=user_id,
            external_id=external_id,
            rol=rol,
            permisos=permisos_de(rol),
            ip_origen=ip_origen,
            request_id=request_id,
        )

    def puede(self, permiso: Permiso) -> bool:
        return permiso in self.permisos

    def exigir(self, permiso: Permiso) -> None:
        """
        Lanza si falta el permiso.

        Se invoca al inicio del caso de uso, no solo en el router: asi el
        control sigue vigente cuando el mismo caso de uso se llama desde
        un worker o desde otro punto de entrada.
        """
        if not self.puede(permiso):
            raise ErrorDeAutorizacion(
                contexto={
                    "permiso_requerido": permiso.value,
                    "rol": self.rol.value,
                    "user_id": str(self.user_id),
                }
            )

    def exigir_mismo_tenant(self, tenant_id_del_recurso: UUID) -> None:
        """
        Verificacion explicita de pertenencia.

        Redundante con RLS por diseño: si una consulta se escribio sin
        pasar por la sesion con `app.current_tenant`, esta comprobacion la
        detiene igual. Defensa en profundidad.
        """
        if tenant_id_del_recurso != self.tenant_id:
            raise ErrorDeAutorizacion(
                contexto={
                    "tenant_del_contexto": str(self.tenant_id),
                    "tenant_del_recurso": str(tenant_id_del_recurso),
                }
            )

    def para_log(self) -> dict[str, str]:
        """Campos seguros para registrar. No incluye nada que identifique a la persona."""
        return {
            "tenant_id": str(self.tenant_id),
            "user_id": str(self.user_id),
            "rol": self.rol.value,
        }
