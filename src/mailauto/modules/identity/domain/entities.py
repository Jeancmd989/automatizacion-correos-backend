"""
Entidades del contexto de identidad.

Proposito
    Representar quien usa el sistema y bajo que tenant, que es la base
    sobre la que se apoya todo el aislamiento de datos.

Dependencias
    Solo `shared` (tipos y rol). No importa SQLAlchemy ni FastAPI: estas
    entidades deben poder instanciarse en un test unitario sin base de
    datos (contrato `dominio-puro` de importlinter).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from mailauto.shared.security.context import Rol
from mailauto.shared.types import ahora_utc, uuid7


class EstadoDeCuenta(StrEnum):
    ACTIVA = "active"
    SUSPENDIDA = "suspended"


@dataclass(slots=True)
class Tenant:
    """
    Unidad de aislamiento: un estudio contable, una empresa, un equipo.

    Todo dato de negocio pertenece a exactamente un tenant. No existe el
    concepto de dato "global" fuera de esta frontera.
    """

    id: UUID = field(default_factory=uuid7)
    nombre: str = ""
    slug: str = ""
    estado: EstadoDeCuenta = EstadoDeCuenta.ACTIVA
    creado_en: datetime = field(default_factory=ahora_utc)

    @property
    def esta_activo(self) -> bool:
        return self.estado is EstadoDeCuenta.ACTIVA


@dataclass(slots=True)
class Usuario:
    """
    Persona autenticada por el proveedor de identidad.

    `external_id` es el `sub` del IdP y es la clave de correlacion: el
    sistema nunca almacena contraseñas, de modo que no hay credenciales
    propias que robar.
    """

    id: UUID = field(default_factory=uuid7)
    external_id: str = ""
    email: str = ""
    nombre_visible: str = ""
    estado: EstadoDeCuenta = EstadoDeCuenta.ACTIVA
    ultimo_acceso_en: datetime | None = None

    @property
    def esta_activo(self) -> bool:
        return self.estado is EstadoDeCuenta.ACTIVA


@dataclass(slots=True)
class Membresia:
    """
    Vinculo usuario-tenant con un rol. Es lo que convierte "estas
    autenticado" en "puedes hacer esto, aqui".

    Un usuario puede pertenecer a varios tenants con roles distintos; el
    tenant activo se resuelve en cada peticion.
    """

    id: UUID = field(default_factory=uuid7)
    tenant_id: UUID = field(default_factory=uuid7)
    user_id: UUID = field(default_factory=uuid7)
    rol: Rol = Rol.VIEWER
    creado_en: datetime = field(default_factory=ahora_utc)


@dataclass(frozen=True, slots=True)
class IdentidadResuelta:
    """Resultado de traducir un token verificado a usuario, tenant y rol."""

    usuario: Usuario
    tenant: Tenant
    rol: Rol
