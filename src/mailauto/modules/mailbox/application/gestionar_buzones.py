"""
Casos de uso: consultar y desvincular buzones, y obtener un token vigente.

Proposito
    Cubrir el resto del ciclo de vida de una conexion: verla, eliminarla
    y garantizar que quien va a usarla recibe un access token valido.

Dependencias
    Puertos del dominio.

Decision de diseño
    `ObtenerTokenVigente` existe como caso de uso y no como utilidad del
    worker porque el refresco tiene efectos persistentes (rota y guarda el
    refresh token) y reglas de negocio (que hacer cuando el usuario revoco
    el acceso). Dejarlo en el worker lo haria intestable sin red.
"""

from __future__ import annotations

from uuid import UUID

from mailauto.modules.mailbox.domain.entities import (
    ConexionDeBuzon,
    EstadoDeConexion,
    Proveedor,
)
from mailauto.modules.mailbox.domain.ports import ProveedorOAuth, RepositorioDeBuzones
from mailauto.shared.errors import CredencialesRevocadas, RecursoNoEncontrado
from mailauto.shared.security.context import Permiso, TenantContext


class ListarBuzones:
    """Conexiones del tenant, sin tokens."""

    def __init__(self, repositorio: RepositorioDeBuzones) -> None:
        self._repositorio = repositorio

    async def ejecutar(self, ctx: TenantContext) -> list[ConexionDeBuzon]:
        ctx.exigir(Permiso.MAILBOX_READ)
        return await self._repositorio.listar(ctx)


class DesvincularBuzon:
    """
    Elimina la conexion y revoca el consentimiento en el proveedor.

    El orden importa: primero se revoca remotamente y despues se borra en
    local. Si se borrase primero y la revocacion fallara, el token
    quedaria vivo en el proveedor sin que el sistema guarde rastro para
    reintentarlo.
    """

    def __init__(
        self,
        repositorio: RepositorioDeBuzones,
        proveedores: dict[Proveedor, ProveedorOAuth],
    ) -> None:
        self._repositorio = repositorio
        self._proveedores = proveedores

    async def ejecutar(self, ctx: TenantContext, conexion_id: UUID) -> None:
        ctx.exigir(Permiso.MAILBOX_WRITE)

        conexion = await self._repositorio.obtener(ctx, conexion_id)
        if conexion is None:
            raise RecursoNoEncontrado("La conexion no existe.")
        ctx.exigir_mismo_tenant(conexion.tenant_id)

        adaptador = self._proveedores.get(conexion.proveedor)
        if adaptador is not None:
            # Se revoca el refresh token si existe: en Google invalida
            # tambien los access token derivados, que es lo que de verdad
            # cierra el acceso.
            token_a_revocar = conexion.refresh_token or conexion.access_token
            if token_a_revocar:
                await adaptador.revocar(token_a_revocar)

        await self._repositorio.eliminar(ctx, conexion_id)


class ObtenerTokenVigente:
    """
    Devuelve una conexion con access token valido, refrescando si hace falta.

    Lo usan los workers antes de hablar con el proveedor.
    """

    def __init__(
        self,
        repositorio: RepositorioDeBuzones,
        proveedores: dict[Proveedor, ProveedorOAuth],
    ) -> None:
        self._repositorio = repositorio
        self._proveedores = proveedores

    async def ejecutar(self, ctx: TenantContext, conexion_id: UUID) -> ConexionDeBuzon:
        conexion = await self._repositorio.obtener(ctx, conexion_id)
        if conexion is None:
            raise RecursoNoEncontrado("La conexion no existe.")
        ctx.exigir_mismo_tenant(conexion.tenant_id)
        return await self._asegurar_vigencia(ctx, conexion)

    async def por_tenant(self, tenant_id: UUID, conexion_id: UUID) -> ConexionDeBuzon:
        """Variante para workers, que no tienen TenantContext completo."""
        conexion = await self._repositorio.obtener_por_id_y_tenant(tenant_id, conexion_id)
        if conexion is None:
            raise RecursoNoEncontrado("La conexion no existe.")
        return await self._asegurar_vigencia(None, conexion)

    async def _asegurar_vigencia(
        self, ctx: TenantContext | None, conexion: ConexionDeBuzon
    ) -> ConexionDeBuzon:
        if not conexion.necesita_refresco():
            return conexion

        if not conexion.puede_refrescarse():
            conexion.marcar_revocada()
            await self._persistir(ctx, conexion)
            raise CredencialesRevocadas(proveedor=conexion.proveedor.value)

        adaptador = self._proveedores[conexion.proveedor]
        refresh_token = conexion.refresh_token
        if refresh_token is None:  # pragma: no cover - garantizado arriba
            # `puede_refrescarse()` ya lo garantiza. Se comprueba igual
            # porque un `assert` desaparece bajo `python -O` y dejaria el
            # control sin efecto justo en produccion.
            conexion.marcar_revocada()
            await self._persistir(ctx, conexion)
            raise CredencialesRevocadas(proveedor=conexion.proveedor.value)

        try:
            tokens = await adaptador.refrescar(refresh_token)
        except CredencialesRevocadas:
            # El usuario revoco el acceso desde la consola del proveedor.
            # Se marca para que la UI pida reconectar en vez de reintentar
            # en bucle un refresco que nunca va a funcionar.
            conexion.marcar_revocada()
            await self._persistir(ctx, conexion)
            raise

        conexion.aplicar_tokens_renovados(
            access_token=tokens.access_token,
            expira_en=tokens.expira_en,
            refresh_token=tokens.refresh_token,
        )
        if tokens.alcances:
            conexion.alcances_concedidos = tokens.alcances
        conexion.estado = EstadoDeConexion.ACTIVA

        await self._persistir(ctx, conexion)
        return conexion

    async def _persistir(self, ctx: TenantContext | None, conexion: ConexionDeBuzon) -> None:
        if ctx is not None:
            await self._repositorio.guardar(ctx, conexion)
            return
        # Desde un worker se reconstruye un contexto minimo con el dueño de
        # la conexion: suficiente para que la sesion fije `app.current_tenant`.
        from mailauto.shared.security.context import Rol
        from mailauto.shared.security.context import TenantContext as Contexto

        await self._repositorio.guardar(
            Contexto.construir(
                tenant_id=conexion.tenant_id,
                user_id=conexion.user_id,
                external_id="worker",
                rol=Rol.OPERATOR,
            ),
            conexion,
        )
