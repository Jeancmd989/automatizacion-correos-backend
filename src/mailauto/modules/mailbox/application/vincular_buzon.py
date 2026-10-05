"""
Casos de uso: vincular un buzon por OAuth.

Proposito
    Orquestar las dos mitades del flujo de consentimiento, con las
    verificaciones de seguridad que lo hacen resistente a CSRF, a robo de
    codigo y a redirecciones manipuladas.

Flujo
    IniciarVinculacion   -> guarda (state, code_verifier) -> URL de consentimiento
    CompletarVinculacion -> consume el state -> canjea el codigo -> persiste cifrado

Dependencias
    Puertos del dominio. Ningun import de httpx, Redis ni SQLAlchemy.

Decisiones de seguridad
    1. El `redirect_uri` se valida contra una allowlist cerrada, tanto al
       iniciar como al completar. Es la defensa contra el ataque clasico
       de redirigir el codigo de autorizacion a un dominio del atacante.

    2. El `state` se consume de forma atomica y se comprueba que el
       usuario que completa es el mismo que inicio. Sin esta segunda
       comprobacion, un atacante puede inducir a la victima a completar
       *su* flujo y acabar con el buzon del atacante vinculado a la cuenta
       de la victima (login CSRF).

    3. Se verifica que los alcances concedidos incluyen lectura de correo.
       En el consentimiento granular el usuario puede desmarcarlo, y sin
       esta comprobacion el fallo aparece despues, al escanear.
"""

from __future__ import annotations

from mailauto.modules.mailbox.domain.entities import (
    ConexionDeBuzon,
    EstadoDeConexion,
    Proveedor,
)
from mailauto.modules.mailbox.domain.ports import (
    AlmacenDeEstadoOAuth,
    ProveedorOAuth,
    RepositorioDeBuzones,
)
from mailauto.shared.errors import ErrorDeAutorizacion, ErrorDeValidacion
from mailauto.shared.security.context import Permiso, TenantContext
from mailauto.shared.types import ahora_utc


class IniciarVinculacion:
    """Primera mitad: genera la URL de consentimiento."""

    def __init__(
        self,
        proveedores: dict[Proveedor, ProveedorOAuth],
        almacen_de_estado: AlmacenDeEstadoOAuth,
        *,
        redirect_uris_permitidos: list[str],
        ttl_estado_segundos: int,
    ) -> None:
        self._proveedores = proveedores
        self._almacen = almacen_de_estado
        self._permitidos = frozenset(redirect_uris_permitidos)
        self._ttl = ttl_estado_segundos

    async def ejecutar(self, ctx: TenantContext, *, proveedor: Proveedor, redirect_uri: str) -> str:
        ctx.exigir(Permiso.MAILBOX_WRITE)

        if redirect_uri not in self._permitidos:
            # Comparacion exacta contra la allowlist, no prefijo ni regex:
            # un `startswith` permite "https://app.legitimo.com.atacante.io".
            raise ErrorDeValidacion("La URL de retorno no esta autorizada.", campo="redirect_uri")

        adaptador = self._proveedores.get(proveedor)
        if adaptador is None:
            raise ErrorDeValidacion(
                f"El proveedor '{proveedor.value}' no esta habilitado.", campo="proveedor"
            )

        solicitud = adaptador.construir_autorizacion(redirect_uri=redirect_uri)

        await self._almacen.guardar(
            state=solicitud.state,
            code_verifier=solicitud.code_verifier,
            tenant_id=ctx.tenant_id,
            user_id=ctx.user_id,
            proveedor=proveedor,
            redirect_uri=redirect_uri,
            ttl_segundos=self._ttl,
        )
        return solicitud.url_de_autorizacion


class CompletarVinculacion:
    """Segunda mitad: canjea el codigo y persiste la conexion cifrada."""

    def __init__(
        self,
        proveedores: dict[Proveedor, ProveedorOAuth],
        almacen_de_estado: AlmacenDeEstadoOAuth,
        repositorio: RepositorioDeBuzones,
    ) -> None:
        self._proveedores = proveedores
        self._almacen = almacen_de_estado
        self._repositorio = repositorio

    async def ejecutar(self, ctx: TenantContext, *, codigo: str, state: str) -> ConexionDeBuzon:
        ctx.exigir(Permiso.MAILBOX_WRITE)

        guardado = await self._almacen.consumir(state)
        if guardado is None:
            # Cubre tres casos: state inventado, state ya usado y state
            # vencido. No se distinguen: las tres son señal de abuso o de
            # un flujo abandonado, y ninguna merece una pista al cliente.
            raise ErrorDeValidacion("La solicitud de vinculacion no es valida o expiro.")

        # El que completa tiene que ser el que inicio. Sin esta
        # comprobacion el `state` deja de proteger: basta con que el
        # atacante haga que la victima visite su propio callback.
        if guardado.get("user_id") != str(ctx.user_id) or guardado.get("tenant_id") != str(
            ctx.tenant_id
        ):
            raise ErrorDeAutorizacion()

        proveedor = Proveedor(guardado["proveedor"])
        adaptador = self._proveedores[proveedor]

        tokens = await adaptador.canjear_codigo(
            codigo=codigo,
            code_verifier=guardado["code_verifier"],
            redirect_uri=guardado["redirect_uri"],
        )

        conexion = ConexionDeBuzon(
            tenant_id=ctx.tenant_id,
            user_id=ctx.user_id,
            proveedor=proveedor,
            correo_de_la_cuenta=tokens.correo_de_la_cuenta or "",
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expira_en=tokens.expira_en,
            alcances_concedidos=tokens.alcances,
            estado=EstadoDeConexion.ACTIVA,
            verificada_en=ahora_utc(),
        )

        if not conexion.tiene_alcances_suficientes():
            raise ErrorDeValidacion(
                "No se concedio el permiso de lectura de correo. "
                "Vuelve a conectar aceptando todos los permisos solicitados."
            )

        guardada = await self._repositorio.guardar(ctx, conexion)
        # Los tokens no vuelven al llamante: a partir de aqui solo los
        # maneja el repositorio, cifrados.
        guardada.access_token = ""
        guardada.refresh_token = None
        return guardada
