"""
Puertos del contexto de buzones.

Proposito
    Abstraer el proveedor OAuth, la persistencia cifrada de conexiones y
    el almacen temporal del estado PKCE.

Dependencias
    Solo entidades del propio dominio y `shared`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from mailauto.modules.mailbox.domain.entities import (
    ConexionDeBuzon,
    Proveedor,
    SolicitudDeAutorizacion,
    TokensDelProveedor,
)
from mailauto.shared.security.context import TenantContext


class ProveedorOAuth(ABC):
    """
    Un proveedor de identidad de correo (Google, Microsoft).

    Cada implementacion encapsula las particularidades del proveedor
    (endpoints, forma de los alcances, como se revoca) detras de estas
    cuatro operaciones.
    """

    @property
    @abstractmethod
    def nombre(self) -> Proveedor: ...

    @abstractmethod
    def construir_autorizacion(self, *, redirect_uri: str) -> SolicitudDeAutorizacion:
        """Genera la URL de consentimiento con PKCE S256 y un `state` aleatorio."""

    @abstractmethod
    async def canjear_codigo(
        self, *, codigo: str, code_verifier: str, redirect_uri: str
    ) -> TokensDelProveedor:
        """Intercambia el codigo de autorizacion por tokens."""

    @abstractmethod
    async def refrescar(self, refresh_token: str) -> TokensDelProveedor:
        """Obtiene un access token nuevo. Puede devolver un refresh token rotado."""

    @abstractmethod
    async def revocar(self, token: str) -> None:
        """
        Invalida el token en el proveedor.

        Borrar la fila local no basta: el consentimiento seguiria vigente
        y el token robado funcionaria hasta vencer.
        """


class AlmacenDeEstadoOAuth(ABC):
    """
    Custodia temporal del `state` y el `code_verifier` entre la redireccion
    y el callback.

    Debe ser de un solo uso y con TTL corto. Sin el consumo unico, un
    `state` capturado permite reproducir el callback; sin TTL, la ventana
    de ataque queda abierta indefinidamente.
    """

    @abstractmethod
    async def guardar(
        self,
        *,
        state: str,
        code_verifier: str,
        tenant_id: UUID,
        user_id: UUID,
        proveedor: Proveedor,
        redirect_uri: str,
        ttl_segundos: int,
    ) -> None: ...

    @abstractmethod
    async def consumir(self, state: str) -> dict[str, str] | None:
        """
        Recupera y elimina atomicamente el estado.

        La atomicidad importa: sin ella, dos callbacks simultaneos con el
        mismo `state` podrian ambos tener exito.
        """


class RepositorioDeBuzones(ABC):
    """Persistencia de conexiones. Cifra y descifra los tokens en el borde."""

    @abstractmethod
    async def guardar(self, ctx: TenantContext, conexion: ConexionDeBuzon) -> ConexionDeBuzon:
        """Alta o actualizacion. Los tokens se cifran antes de tocar disco."""

    @abstractmethod
    async def listar(self, ctx: TenantContext) -> list[ConexionDeBuzon]:
        """Conexiones del tenant. NO incluye los tokens descifrados."""

    @abstractmethod
    async def obtener(self, ctx: TenantContext, conexion_id: UUID) -> ConexionDeBuzon | None:
        """Conexion con sus tokens ya descifrados, lista para operar."""

    @abstractmethod
    async def obtener_por_id_y_tenant(
        self, tenant_id: UUID, conexion_id: UUID
    ) -> ConexionDeBuzon | None:
        """
        Variante para workers, que tienen el tenant_id de la carga del job
        pero no un TenantContext de una peticion HTTP.
        """

    @abstractmethod
    async def eliminar(self, ctx: TenantContext, conexion_id: UUID) -> bool:
        """Elimina la conexion. Devuelve False si no existia."""
