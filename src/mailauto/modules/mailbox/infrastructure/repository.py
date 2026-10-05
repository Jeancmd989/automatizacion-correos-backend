"""
Repositorio de buzones con cifrado transparente.

Proposito
    Que ninguna capa superior tenga que acordarse de cifrar: los tokens
    entran en claro y salen de disco cifrados, siempre, sin excepcion.

Flujo
    guardar()  -> DEK del tenant -> cifrar con AAD -> INSERT/UPDATE
    obtener()  -> SELECT -> DEK del tenant -> descifrar con AAD -> entidad

Dependencias
    SQLAlchemy, `ServicioDeCifrado`, modelos del modulo.

Decision de diseño
    `listar()` devuelve las conexiones con los tokens vacios y `obtener()`
    los descifra. La mayoria de las lecturas son para mostrar en pantalla
    "tienes Gmail conectado": descifrar ahi seria exponer credenciales sin
    necesidad. Solo el camino que va a usar el token paga ese coste.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import delete, select

from mailauto.modules.mailbox.domain.entities import (
    ConexionDeBuzon,
    EstadoDeConexion,
    Proveedor,
)
from mailauto.modules.mailbox.domain.ports import RepositorioDeBuzones
from mailauto.modules.mailbox.infrastructure.models import (
    ClaveDeCifradoORM,
    ConexionDeBuzonORM,
)
from mailauto.shared.crypto.envelope import (
    ContextoCripto,
    DekEnvuelta,
    ServicioDeCifrado,
)
from mailauto.shared.db.session import FabricaDeSesiones
from mailauto.shared.security.context import TenantContext
from mailauto.shared.types import uuid7

_PROPOSITO_ACCESS = "oauth_access_token"
_PROPOSITO_REFRESH = "oauth_refresh_token"


class RepositorioDeBuzonesPostgres(RepositorioDeBuzones):
    def __init__(self, sesiones: FabricaDeSesiones, cifrado: ServicioDeCifrado) -> None:
        self._sesiones = sesiones
        self._cifrado = cifrado

    # ── Escritura ────────────────────────────────────────────────────

    async def guardar(self, ctx: TenantContext, conexion: ConexionDeBuzon) -> ConexionDeBuzon:
        async with self._sesiones.sesion_de_tenant(ctx) as sesion:
            dek_id, dek = await self._obtener_o_crear_dek(sesion, ctx.tenant_id)
            contexto_base = _contexto(ctx.tenant_id, conexion)

            access_ct = self._cifrado.cifrar_texto(
                dek, conexion.access_token, contexto_base(_PROPOSITO_ACCESS)
            )
            refresh_ct = (
                self._cifrado.cifrar_texto(
                    dek, conexion.refresh_token, contexto_base(_PROPOSITO_REFRESH)
                )
                if conexion.refresh_token
                else None
            )

            existente = await sesion.scalar(
                select(ConexionDeBuzonORM).where(
                    ConexionDeBuzonORM.tenant_id == ctx.tenant_id,
                    ConexionDeBuzonORM.user_id == conexion.user_id,
                    ConexionDeBuzonORM.proveedor == conexion.proveedor.value,
                )
            )

            if existente is None:
                existente = ConexionDeBuzonORM(
                    id=conexion.id,
                    tenant_id=ctx.tenant_id,
                    user_id=conexion.user_id,
                    proveedor=conexion.proveedor.value,
                    dek_id=dek_id,
                )
                sesion.add(existente)
            else:
                conexion.id = existente.id
                existente.dek_id = dek_id

            existente.correo_de_la_cuenta = conexion.correo_de_la_cuenta
            existente.access_token_ct = access_ct
            existente.refresh_token_ct = refresh_ct
            existente.alcances_concedidos = list(conexion.alcances_concedidos)
            existente.expira_en = conexion.expira_en
            existente.estado = conexion.estado.value
            existente.verificada_en = conexion.verificada_en

            await sesion.flush()
            return conexion

    async def eliminar(self, ctx: TenantContext, conexion_id: UUID) -> bool:
        async with self._sesiones.sesion_de_tenant(ctx) as sesion:
            # RETURNING en lugar de `rowcount`: deja tipado el resultado
            # y hace explicito en la propia sentencia que interesa saber
            # si existia la fila.
            eliminado = await sesion.scalar(
                delete(ConexionDeBuzonORM)
                .where(ConexionDeBuzonORM.id == conexion_id)
                .returning(ConexionDeBuzonORM.id)
            )
            return eliminado is not None

    # ── Lectura ──────────────────────────────────────────────────────

    async def listar(self, ctx: TenantContext) -> list[ConexionDeBuzon]:
        """Sin descifrar: para pintar el estado de las vinculaciones."""
        async with self._sesiones.sesion_de_tenant(ctx) as sesion:
            filas = await sesion.scalars(
                select(ConexionDeBuzonORM).order_by(ConexionDeBuzonORM.created_at.desc())
            )
            return [_a_entidad_sin_tokens(f) for f in filas]

    async def obtener(self, ctx: TenantContext, conexion_id: UUID) -> ConexionDeBuzon | None:
        async with self._sesiones.sesion_de_tenant(ctx) as sesion:
            fila = await sesion.get(ConexionDeBuzonORM, conexion_id)
            if fila is None:
                return None
            return await self._descifrar(sesion, fila)

    async def obtener_por_id_y_tenant(
        self, tenant_id: UUID, conexion_id: UUID
    ) -> ConexionDeBuzon | None:
        async with self._sesiones.sesion_de_tenant_por_id(tenant_id) as sesion:
            fila = await sesion.get(ConexionDeBuzonORM, conexion_id)
            if fila is None:
                return None
            return await self._descifrar(sesion, fila)

    # ── Cifrado ──────────────────────────────────────────────────────

    async def _obtener_o_crear_dek(self, sesion, tenant_id: UUID) -> tuple[UUID, bytes]:  # type: ignore[no-untyped-def]
        fila = await sesion.scalar(
            select(ClaveDeCifradoORM).where(
                ClaveDeCifradoORM.tenant_id == tenant_id,
                ClaveDeCifradoORM.estado == "active",
            )
        )
        if fila is not None:
            envuelta = DekEnvuelta(material=fila.dek_envuelta, version_kek=fila.version_kek)
            return fila.id, self._cifrado.desenvolver_dek(envuelta)

        envuelta = self._cifrado.generar_dek()
        nueva = ClaveDeCifradoORM(
            id=uuid7(),
            tenant_id=tenant_id,
            dek_envuelta=envuelta.material,
            version_kek=envuelta.version_kek,
            estado="active",
        )
        sesion.add(nueva)
        await sesion.flush()
        return nueva.id, self._cifrado.desenvolver_dek(envuelta)

    async def _descifrar(self, sesion, fila: ConexionDeBuzonORM) -> ConexionDeBuzon:  # type: ignore[no-untyped-def]
        clave = await sesion.get(ClaveDeCifradoORM, fila.dek_id)
        if clave is None:
            # La DEK fue destruida (supresion de datos). La conexion existe
            # pero es criptograficamente inutil: se reporta como revocada.
            conexion = _a_entidad_sin_tokens(fila)
            conexion.marcar_revocada()
            return conexion

        dek = self._cifrado.desenvolver_dek(
            DekEnvuelta(material=clave.dek_envuelta, version_kek=clave.version_kek)
        )
        conexion = _a_entidad_sin_tokens(fila)
        contexto_base = _contexto(fila.tenant_id, conexion)

        conexion.access_token = self._cifrado.descifrar_texto(
            dek, fila.access_token_ct, contexto_base(_PROPOSITO_ACCESS)
        )
        if fila.refresh_token_ct:
            conexion.refresh_token = self._cifrado.descifrar_texto(
                dek, fila.refresh_token_ct, contexto_base(_PROPOSITO_REFRESH)
            )
        return conexion


# ── Auxiliares ───────────────────────────────────────────────────────


def _contexto(tenant_id: UUID, conexion: ConexionDeBuzon):  # type: ignore[no-untyped-def]
    """
    Fabrica de AAD para esta conexion.

    El sujeto incluye proveedor y usuario, de modo que el ciphertext queda
    atado a esa combinacion exacta: moverlo a otra fila lo invalida.
    """

    def construir(proposito: str) -> ContextoCripto:
        return ContextoCripto(
            tenant_id=str(tenant_id),
            proposito=proposito,
            sujeto=f"{conexion.proveedor.value}:{conexion.user_id}",
        )

    return construir


def _a_entidad_sin_tokens(fila: ConexionDeBuzonORM) -> ConexionDeBuzon:
    return ConexionDeBuzon(
        id=fila.id,
        tenant_id=fila.tenant_id,
        user_id=fila.user_id,
        proveedor=Proveedor(fila.proveedor),
        correo_de_la_cuenta=fila.correo_de_la_cuenta,
        access_token="",
        refresh_token=None,
        expira_en=fila.expira_en,
        alcances_concedidos=tuple(fila.alcances_concedidos),
        estado=EstadoDeConexion(fila.estado),
        verificada_en=fila.verificada_en,
    )
