"""
Tests de los casos de uso de vinculación OAuth y control de escaneos.

Concentra los controles que impiden secuestrar una vinculación: la
allowlist de `redirect_uri`, el consumo único del `state` y la
comprobación de que quien completa el flujo es quien lo inició.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import pytest

from mailauto.modules.ingestion.application.gestionar_escaneos import (
    CancelarEscaneo,
    ConsultarEscaneo,
    IniciarEscaneo,
)
from mailauto.modules.ingestion.domain.entities import (
    EstadoDeTrabajo,
    ParametrosDeEscaneo,
    TrabajoDeEscaneo,
)
from mailauto.modules.ingestion.domain.ports import ColaDeTrabajos
from mailauto.modules.mailbox.application.gestionar_buzones import (
    DesvincularBuzon,
    ObtenerTokenVigente,
)
from mailauto.modules.mailbox.application.vincular_buzon import (
    CompletarVinculacion,
    IniciarVinculacion,
)
from mailauto.modules.mailbox.domain.entities import (
    ConexionDeBuzon,
    EstadoDeConexion,
    Proveedor,
    SolicitudDeAutorizacion,
    TokensDelProveedor,
)
from mailauto.modules.mailbox.domain.ports import (
    AlmacenDeEstadoOAuth,
    ProveedorOAuth,
    RepositorioDeBuzones,
)
from mailauto.shared.errors import (
    CredencialesRevocadas,
    ErrorDeAutorizacion,
    ErrorDeValidacion,
    LimiteExcedido,
    RecursoNoEncontrado,
)
from mailauto.shared.security.context import Rol, TenantContext
from mailauto.shared.types import ahora_utc
from tests.conftest import TENANT_A, USUARIO_A

pytestmark = pytest.mark.security

REDIRECT_PERMITIDO = "https://app.ejemplo.com/oauth/callback"


# ─────────────────────────────────────────────────────────────────────
# Dobles
# ─────────────────────────────────────────────────────────────────────


class AlmacenDeEstadoFalso(AlmacenDeEstadoOAuth):
    def __init__(self) -> None:
        self.guardados: dict[str, dict[str, str]] = {}

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
    ) -> None:
        self.guardados[state] = {
            "code_verifier": code_verifier,
            "tenant_id": str(tenant_id),
            "user_id": str(user_id),
            "proveedor": proveedor.value,
            "redirect_uri": redirect_uri,
        }

    async def consumir(self, state: str) -> dict[str, str] | None:
        # Consumo unico, igual que GETDEL en Redis.
        return self.guardados.pop(state, None)


class ProveedorOAuthFalso(ProveedorOAuth):
    def __init__(self, *, alcances: tuple[str, ...] | None = None) -> None:
        self.revocados: list[str] = []
        self.refrescos = 0
        self._alcances = alcances or (
            "openid",
            "email",
            "https://www.googleapis.com/auth/gmail.readonly",
        )

    @property
    def nombre(self) -> Proveedor:
        return Proveedor.GOOGLE

    def construir_autorizacion(self, *, redirect_uri: str) -> SolicitudDeAutorizacion:
        return SolicitudDeAutorizacion(
            url_de_autorizacion=f"https://accounts.google.com/auth?redirect_uri={redirect_uri}",
            state="estado-generado",
            code_verifier="verificador-secreto",
        )

    async def canjear_codigo(
        self, *, codigo: str, code_verifier: str, redirect_uri: str
    ) -> TokensDelProveedor:
        return TokensDelProveedor(
            access_token="access-nuevo",
            refresh_token="refresh-nuevo",
            expira_en=ahora_utc() + timedelta(hours=1),
            alcances=self._alcances,
            correo_de_la_cuenta="usuario@ejemplo.com",
        )

    async def refrescar(self, refresh_token: str) -> TokensDelProveedor:
        self.refrescos += 1
        return TokensDelProveedor(
            access_token="access-refrescado",
            refresh_token="refresh-rotado",
            expira_en=ahora_utc() + timedelta(hours=1),
            alcances=self._alcances,
        )

    async def revocar(self, token: str) -> None:
        self.revocados.append(token)


class ProveedorQueRechazaElRefresco(ProveedorOAuthFalso):
    async def refrescar(self, refresh_token: str) -> TokensDelProveedor:
        raise CredencialesRevocadas(proveedor="google")


class RepositorioDeBuzonesFalso(RepositorioDeBuzones):
    def __init__(self) -> None:
        self.conexiones: dict[UUID, ConexionDeBuzon] = {}

    async def guardar(self, ctx: TenantContext, conexion: ConexionDeBuzon) -> ConexionDeBuzon:
        self.conexiones[conexion.id] = conexion
        return conexion

    async def listar(self, ctx: TenantContext) -> list[ConexionDeBuzon]:
        return [c for c in self.conexiones.values() if c.tenant_id == ctx.tenant_id]

    async def obtener(self, ctx: TenantContext, conexion_id: UUID) -> ConexionDeBuzon | None:
        return self.conexiones.get(conexion_id)

    async def obtener_por_id_y_tenant(
        self, tenant_id: UUID, conexion_id: UUID
    ) -> ConexionDeBuzon | None:
        conexion = self.conexiones.get(conexion_id)
        return conexion if conexion and conexion.tenant_id == tenant_id else None

    async def eliminar(self, ctx: TenantContext, conexion_id: UUID) -> bool:
        return self.conexiones.pop(conexion_id, None) is not None


def _iniciar(almacen: AlmacenDeEstadoFalso, proveedor: ProveedorOAuth) -> IniciarVinculacion:
    return IniciarVinculacion(
        {Proveedor.GOOGLE: proveedor},
        almacen,
        redirect_uris_permitidos=[REDIRECT_PERMITIDO],
        ttl_estado_segundos=600,
    )


# ─────────────────────────────────────────────────────────────────────
# Inicio de la vinculación
# ─────────────────────────────────────────────────────────────────────


async def test_inicia_la_vinculacion_y_custodia_el_pkce(
    contexto_a: TenantContext,
) -> None:
    almacen = AlmacenDeEstadoFalso()
    url = await _iniciar(almacen, ProveedorOAuthFalso()).ejecutar(
        contexto_a, proveedor=Proveedor.GOOGLE, redirect_uri=REDIRECT_PERMITIDO
    )

    assert url.startswith("https://accounts.google.com/")
    # El `code_verifier` queda en el servidor y nunca viaja al navegador:
    # esa es exactamente la garantia que aporta PKCE.
    assert "verificador-secreto" not in url
    assert almacen.guardados["estado-generado"]["code_verifier"] == "verificador-secreto"


@pytest.mark.parametrize(
    "redirect",
    [
        "https://atacante.ejemplo/callback",
        # Prefijo del dominio legitimo: lo que pasaria un `startswith`.
        "https://app.ejemplo.com.atacante.io/oauth/callback",
        "https://app.ejemplo.com/oauth/callback/extra",
        "http://app.ejemplo.com/oauth/callback",
        "",
    ],
)
async def test_rechaza_redirect_uri_fuera_de_la_allowlist(
    contexto_a: TenantContext, redirect: str
) -> None:
    """
    Sin comparacion exacta, un `redirect_uri` manipulado entrega el
    codigo de autorizacion al dominio del atacante.
    """
    with pytest.raises(ErrorDeValidacion):
        await _iniciar(AlmacenDeEstadoFalso(), ProveedorOAuthFalso()).ejecutar(
            contexto_a, proveedor=Proveedor.GOOGLE, redirect_uri=redirect
        )


async def test_un_lector_no_puede_vincular_buzones() -> None:
    lector = TenantContext.construir(
        tenant_id=TENANT_A, user_id=USUARIO_A, external_id="auth0|v", rol=Rol.VIEWER
    )
    with pytest.raises(ErrorDeAutorizacion):
        await _iniciar(AlmacenDeEstadoFalso(), ProveedorOAuthFalso()).ejecutar(
            lector, proveedor=Proveedor.GOOGLE, redirect_uri=REDIRECT_PERMITIDO
        )


async def test_rechaza_un_proveedor_no_habilitado(contexto_a: TenantContext) -> None:
    with pytest.raises(ErrorDeValidacion):
        await _iniciar(AlmacenDeEstadoFalso(), ProveedorOAuthFalso()).ejecutar(
            contexto_a, proveedor=Proveedor.MICROSOFT, redirect_uri=REDIRECT_PERMITIDO
        )


# ─────────────────────────────────────────────────────────────────────
# Callback
# ─────────────────────────────────────────────────────────────────────


async def test_completa_la_vinculacion_y_no_devuelve_los_tokens(
    contexto_a: TenantContext,
) -> None:
    almacen, proveedor = AlmacenDeEstadoFalso(), ProveedorOAuthFalso()
    repositorio = RepositorioDeBuzonesFalso()
    await _iniciar(almacen, proveedor).ejecutar(
        contexto_a, proveedor=Proveedor.GOOGLE, redirect_uri=REDIRECT_PERMITIDO
    )

    conexion = await CompletarVinculacion(
        {Proveedor.GOOGLE: proveedor}, almacen, repositorio
    ).ejecutar(contexto_a, codigo="codigo", state="estado-generado")

    assert conexion.correo_de_la_cuenta == "usuario@ejemplo.com"
    assert conexion.estado is EstadoDeConexion.ACTIVA
    # Los tokens quedan solo en el repositorio, cifrados. Devolverlos al
    # llamante los pondria en la respuesta HTTP y en sus logs.
    assert conexion.access_token == ""
    assert conexion.refresh_token is None


async def test_el_state_solo_sirve_una_vez(contexto_a: TenantContext) -> None:
    """Reproducir el callback capturado debe fallar la segunda vez."""
    almacen, proveedor = AlmacenDeEstadoFalso(), ProveedorOAuthFalso()
    caso = CompletarVinculacion({Proveedor.GOOGLE: proveedor}, almacen, RepositorioDeBuzonesFalso())
    await _iniciar(almacen, proveedor).ejecutar(
        contexto_a, proveedor=Proveedor.GOOGLE, redirect_uri=REDIRECT_PERMITIDO
    )

    await caso.ejecutar(contexto_a, codigo="c", state="estado-generado")
    with pytest.raises(ErrorDeValidacion):
        await caso.ejecutar(contexto_a, codigo="c", state="estado-generado")


async def test_rechaza_un_state_inventado(contexto_a: TenantContext) -> None:
    with pytest.raises(ErrorDeValidacion):
        await CompletarVinculacion(
            {Proveedor.GOOGLE: ProveedorOAuthFalso()},
            AlmacenDeEstadoFalso(),
            RepositorioDeBuzonesFalso(),
        ).ejecutar(contexto_a, codigo="c", state="state-que-nadie-emitio")


async def test_otro_usuario_no_puede_completar_la_vinculacion_ajena(
    contexto_a: TenantContext, contexto_b: TenantContext
) -> None:
    """
    Sin esta comprobacion, un atacante induce a la victima a visitar su
    propio callback y acaba con el buzon del atacante vinculado a la
    cuenta de la victima.
    """
    almacen, proveedor = AlmacenDeEstadoFalso(), ProveedorOAuthFalso()
    await _iniciar(almacen, proveedor).ejecutar(
        contexto_a, proveedor=Proveedor.GOOGLE, redirect_uri=REDIRECT_PERMITIDO
    )

    with pytest.raises(ErrorDeAutorizacion):
        await CompletarVinculacion(
            {Proveedor.GOOGLE: proveedor}, almacen, RepositorioDeBuzonesFalso()
        ).ejecutar(contexto_b, codigo="c", state="estado-generado")


async def test_rechaza_la_vinculacion_sin_permiso_de_lectura_de_correo(
    contexto_a: TenantContext,
) -> None:
    """
    En el consentimiento granular el usuario puede desmarcar permisos. Sin
    esta comprobacion, el fallo aparece despues, al escanear, con un 403
    opaco del proveedor.
    """
    proveedor = ProveedorOAuthFalso(alcances=("openid", "email"))
    almacen = AlmacenDeEstadoFalso()
    await _iniciar(almacen, proveedor).ejecutar(
        contexto_a, proveedor=Proveedor.GOOGLE, redirect_uri=REDIRECT_PERMITIDO
    )

    with pytest.raises(ErrorDeValidacion, match="lectura de correo"):
        await CompletarVinculacion(
            {Proveedor.GOOGLE: proveedor}, almacen, RepositorioDeBuzonesFalso()
        ).ejecutar(contexto_a, codigo="c", state="estado-generado")


# ─────────────────────────────────────────────────────────────────────
# Desvinculación y refresco
# ─────────────────────────────────────────────────────────────────────


async def test_desvincular_revoca_en_el_proveedor(contexto_a: TenantContext) -> None:
    """
    Borrar la fila local no basta: el consentimiento seguiria vigente y
    un token robado funcionaria hasta vencer.
    """
    proveedor = ProveedorOAuthFalso()
    repositorio = RepositorioDeBuzonesFalso()
    conexion = ConexionDeBuzon(
        tenant_id=TENANT_A,
        user_id=USUARIO_A,
        proveedor=Proveedor.GOOGLE,
        access_token="access",
        refresh_token="refresh",
        expira_en=ahora_utc() + timedelta(hours=1),
    )
    await repositorio.guardar(contexto_a, conexion)

    await DesvincularBuzon(repositorio, {Proveedor.GOOGLE: proveedor}).ejecutar(
        contexto_a, conexion.id
    )

    # Se revoca el refresh token: en Google invalida tambien los access
    # token derivados, que es lo que de verdad cierra el acceso.
    assert proveedor.revocados == ["refresh"]
    assert repositorio.conexiones == {}


async def test_no_se_puede_desvincular_una_conexion_de_otro_tenant(
    contexto_a: TenantContext, contexto_b: TenantContext
) -> None:
    repositorio = RepositorioDeBuzonesFalso()
    ajena = ConexionDeBuzon(
        tenant_id=contexto_b.tenant_id,
        user_id=contexto_b.user_id,
        proveedor=Proveedor.GOOGLE,
        access_token="a",
        expira_en=ahora_utc() + timedelta(hours=1),
    )
    await repositorio.guardar(contexto_b, ajena)

    with pytest.raises(ErrorDeAutorizacion):
        await DesvincularBuzon(repositorio, {Proveedor.GOOGLE: ProveedorOAuthFalso()}).ejecutar(
            contexto_a, ajena.id
        )
    assert ajena.id in repositorio.conexiones


async def test_refresca_el_token_proximo_a_vencer(contexto_a: TenantContext) -> None:
    proveedor = ProveedorOAuthFalso()
    repositorio = RepositorioDeBuzonesFalso()
    conexion = ConexionDeBuzon(
        tenant_id=TENANT_A,
        user_id=USUARIO_A,
        proveedor=Proveedor.GOOGLE,
        access_token="viejo",
        refresh_token="refresh",
        expira_en=ahora_utc() + timedelta(seconds=30),  # dentro del margen
    )
    await repositorio.guardar(contexto_a, conexion)

    vigente = await ObtenerTokenVigente(repositorio, {Proveedor.GOOGLE: proveedor}).ejecutar(
        contexto_a, conexion.id
    )

    assert vigente.access_token == "access-refrescado"
    # Rotacion: el proveedor devolvio un refresh token nuevo y se adopta.
    assert vigente.refresh_token == "refresh-rotado"
    assert proveedor.refrescos == 1


async def test_no_refresca_un_token_todavia_vigente(
    contexto_a: TenantContext,
) -> None:
    proveedor = ProveedorOAuthFalso()
    repositorio = RepositorioDeBuzonesFalso()
    conexion = ConexionDeBuzon(
        tenant_id=TENANT_A,
        user_id=USUARIO_A,
        proveedor=Proveedor.GOOGLE,
        access_token="vigente",
        refresh_token="refresh",
        expira_en=ahora_utc() + timedelta(hours=2),
    )
    await repositorio.guardar(contexto_a, conexion)

    await ObtenerTokenVigente(repositorio, {Proveedor.GOOGLE: proveedor}).ejecutar(
        contexto_a, conexion.id
    )
    assert proveedor.refrescos == 0


async def test_un_refresco_rechazado_marca_la_conexion_como_revocada(
    contexto_a: TenantContext,
) -> None:
    """
    El usuario revoco el acceso desde la consola del proveedor. Hay que
    pedirle que reconecte, no reintentar en bucle un refresco imposible.
    """
    repositorio = RepositorioDeBuzonesFalso()
    conexion = ConexionDeBuzon(
        tenant_id=TENANT_A,
        user_id=USUARIO_A,
        proveedor=Proveedor.GOOGLE,
        access_token="viejo",
        refresh_token="refresh",
        expira_en=ahora_utc() - timedelta(minutes=1),
    )
    await repositorio.guardar(contexto_a, conexion)

    with pytest.raises(CredencialesRevocadas):
        await ObtenerTokenVigente(
            repositorio, {Proveedor.GOOGLE: ProveedorQueRechazaElRefresco()}
        ).ejecutar(contexto_a, conexion.id)

    assert repositorio.conexiones[conexion.id].estado is EstadoDeConexion.REVOCADA


async def test_una_conexion_sin_refresh_token_vencida_se_revoca(
    contexto_a: TenantContext,
) -> None:
    repositorio = RepositorioDeBuzonesFalso()
    conexion = ConexionDeBuzon(
        tenant_id=TENANT_A,
        user_id=USUARIO_A,
        proveedor=Proveedor.GOOGLE,
        access_token="viejo",
        refresh_token=None,
        expira_en=ahora_utc() - timedelta(minutes=1),
    )
    await repositorio.guardar(contexto_a, conexion)

    with pytest.raises(CredencialesRevocadas):
        await ObtenerTokenVigente(repositorio, {Proveedor.GOOGLE: ProveedorOAuthFalso()}).ejecutar(
            contexto_a, conexion.id
        )


# ─────────────────────────────────────────────────────────────────────
# Control de escaneos
# ─────────────────────────────────────────────────────────────────────


class RepositorioDeEscaneosFalso:
    """Solo lo que necesitan estos casos de uso."""

    def __init__(self, *, activos: int = 0) -> None:
        self.trabajos: dict[UUID, TrabajoDeEscaneo] = {}
        self.activos = activos
        self.por_idempotencia: dict[str, TrabajoDeEscaneo] = {}

    async def crear_trabajo(
        self, ctx: TenantContext, trabajo: TrabajoDeEscaneo
    ) -> TrabajoDeEscaneo:
        self.trabajos[trabajo.id] = trabajo
        if trabajo.clave_de_idempotencia:
            self.por_idempotencia[trabajo.clave_de_idempotencia] = trabajo
        return trabajo

    async def actualizar_trabajo(self, tenant_id: UUID, trabajo: TrabajoDeEscaneo) -> None:
        self.trabajos[trabajo.id] = trabajo

    async def obtener_trabajo(
        self, ctx: TenantContext, trabajo_id: UUID
    ) -> TrabajoDeEscaneo | None:
        return self.trabajos.get(trabajo_id)

    async def buscar_por_idempotencia(
        self, ctx: TenantContext, clave: str
    ) -> TrabajoDeEscaneo | None:
        return self.por_idempotencia.get(clave)

    async def contar_trabajos_activos(self, tenant_id: UUID) -> int:
        return self.activos


class ColaDeEscaneosFalsa(ColaDeTrabajos):
    def __init__(self) -> None:
        self.encolados: list[UUID] = []
        self.cancelados: list[UUID] = []

    async def encolar_escaneo(self, *, tenant_id: UUID, trabajo_id: UUID) -> str:
        self.encolados.append(trabajo_id)
        return "job"

    async def encolar_extraccion(
        self,
        *,
        tenant_id: UUID,
        trabajo_id: UUID,
        adjunto_id: UUID,
        clave_de_almacenamiento: str,
        tipo_mime: str,
        nombre: str,
    ) -> str:
        return "extract"

    async def solicitar_cancelacion(self, trabajo_id: UUID) -> None:
        self.cancelados.append(trabajo_id)

    async def cancelacion_solicitada(self, trabajo_id: UUID) -> bool:
        return trabajo_id in self.cancelados

    async def esta_disponible(self) -> bool:
        return True


def _iniciar_escaneo(
    repositorio: object, cola: ColaDeTrabajos, *, maximo_concurrentes: int = 3
) -> IniciarEscaneo:
    return IniciarEscaneo(
        repositorio,  # type: ignore[arg-type]
        cola,
        maximo_mensajes=5000,
        maximo_dias=366,
        maximo_concurrentes=maximo_concurrentes,
    )


async def test_encola_el_escaneo_tras_persistirlo(contexto_a: TenantContext) -> None:
    """
    El orden importa: si fallara la cola, queda un trabajo visible que el
    cron puede reintentar. Al reves seria un mensaje huerfano.
    """
    repositorio, cola = RepositorioDeEscaneosFalso(), ColaDeEscaneosFalsa()
    trabajo = await _iniciar_escaneo(repositorio, cola).ejecutar(
        contexto_a, conexion_id=TENANT_A, parametros=ParametrosDeEscaneo()
    )
    assert trabajo.id in repositorio.trabajos
    assert cola.encolados == [trabajo.id]


async def test_la_clave_de_idempotencia_evita_el_doble_escaneo(
    contexto_a: TenantContext,
) -> None:
    repositorio, cola = RepositorioDeEscaneosFalso(), ColaDeEscaneosFalsa()
    caso = _iniciar_escaneo(repositorio, cola)

    primero = await caso.ejecutar(
        contexto_a,
        conexion_id=TENANT_A,
        parametros=ParametrosDeEscaneo(),
        clave_de_idempotencia="clave-1",
    )
    segundo = await caso.ejecutar(
        contexto_a,
        conexion_id=TENANT_A,
        parametros=ParametrosDeEscaneo(),
        clave_de_idempotencia="clave-1",
    )

    assert primero.id == segundo.id
    assert len(cola.encolados) == 1


async def test_la_cuota_de_escaneos_concurrentes_se_aplica(
    contexto_a: TenantContext,
) -> None:
    """
    Sin tope, un cliente encola cien escaneos y monopoliza los workers
    compartidos: un problema de equidad que acaba siendo denegacion de
    servicio para el resto.
    """
    repositorio = RepositorioDeEscaneosFalso(activos=3)
    with pytest.raises(LimiteExcedido):
        await _iniciar_escaneo(repositorio, ColaDeEscaneosFalsa(), maximo_concurrentes=3).ejecutar(
            contexto_a, conexion_id=TENANT_A, parametros=ParametrosDeEscaneo()
        )


async def test_la_idempotencia_se_evalua_antes_que_la_cuota(
    contexto_a: TenantContext,
) -> None:
    """Reintentar una peticion ya atendida no debe fallar por limite."""
    repositorio = RepositorioDeEscaneosFalso(activos=0)
    cola = ColaDeEscaneosFalsa()
    caso = _iniciar_escaneo(repositorio, cola, maximo_concurrentes=1)
    primero = await caso.ejecutar(
        contexto_a,
        conexion_id=TENANT_A,
        parametros=ParametrosDeEscaneo(),
        clave_de_idempotencia="k",
    )

    repositorio.activos = 1  # la cuota ya esta agotada
    segundo = await caso.ejecutar(
        contexto_a,
        conexion_id=TENANT_A,
        parametros=ParametrosDeEscaneo(),
        clave_de_idempotencia="k",
    )
    assert segundo.id == primero.id


async def test_un_lector_no_puede_lanzar_escaneos() -> None:
    lector = TenantContext.construir(
        tenant_id=TENANT_A, user_id=USUARIO_A, external_id="auth0|v", rol=Rol.VIEWER
    )
    with pytest.raises(ErrorDeAutorizacion):
        await _iniciar_escaneo(RepositorioDeEscaneosFalso(), ColaDeEscaneosFalsa()).ejecutar(
            lector, conexion_id=TENANT_A, parametros=ParametrosDeEscaneo()
        )


async def test_cancelar_senaliza_la_cola_y_marca_el_trabajo(
    contexto_a: TenantContext,
) -> None:
    repositorio, cola = RepositorioDeEscaneosFalso(), ColaDeEscaneosFalsa()
    trabajo = await _iniciar_escaneo(repositorio, cola).ejecutar(
        contexto_a, conexion_id=TENANT_A, parametros=ParametrosDeEscaneo()
    )

    cancelado = await CancelarEscaneo(repositorio, cola).ejecutar(  # type: ignore[arg-type]
        contexto_a, trabajo.id
    )
    assert cancelado.estado is EstadoDeTrabajo.CANCELADO
    assert cola.cancelados == [trabajo.id]


async def test_no_se_puede_cancelar_un_escaneo_de_otro_tenant(
    contexto_a: TenantContext, contexto_b: TenantContext
) -> None:
    repositorio, cola = RepositorioDeEscaneosFalso(), ColaDeEscaneosFalsa()
    ajeno = await _iniciar_escaneo(repositorio, cola).ejecutar(
        contexto_b, conexion_id=TENANT_A, parametros=ParametrosDeEscaneo()
    )

    with pytest.raises(ErrorDeAutorizacion):
        await CancelarEscaneo(repositorio, cola).ejecutar(contexto_a, ajeno.id)  # type: ignore[arg-type]


async def test_consultar_un_escaneo_inexistente_da_404(
    contexto_a: TenantContext,
) -> None:
    with pytest.raises(RecursoNoEncontrado):
        await ConsultarEscaneo(RepositorioDeEscaneosFalso()).obtener(  # type: ignore[arg-type]
            contexto_a, TENANT_A
        )
