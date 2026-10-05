"""
Verificacion de tokens OIDC.

Proposito
    Validar el JWT de acceso con todas las comprobaciones que suelen
    omitirse y que convierten la autenticacion en decorativa.

Flujo
    Authorization: Bearer <jwt> -> cabecera -> kid -> JWKS (cacheado)
    -> verificacion de firma -> verificacion de claims -> ClaimsVerificados

Dependencias
    PyJWT (con backend criptografico), httpx para descargar el JWKS.

Decisiones de diseño
    1. Allowlist de algoritmos fija en RS256. Si se aceptara el `alg` que
       viene en la cabecera del token, un atacante podria enviar
       `alg: none` (sin firma) o `alg: HS256` firmando con la clave publica
       RSA, que es publica por definicion. Son los dos ataques clasicos
       contra JWT y ambos se cierran aqui.

    2. `aud` e `iss` se verifican siempre. Sin `aud`, un token emitido para
       otra API del mismo tenant de Auth0 seria aceptado aqui.

    3. El JWKS se cachea con TTL y se refresca ante un `kid` desconocido,
       pero con un intervalo minimo entre refrescos: de lo contrario, un
       atacante que envie tokens con `kid` aleatorios provoca una descarga
       por peticion y convierte al proveedor de identidad en el cuello de
       botella (amplificacion de denegacion de servicio).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Final

import httpx
import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError

from mailauto.shared.errors import TokenInvalido

ALGORITMOS_PERMITIDOS: Final[list[str]] = ["RS256"]
_INTERVALO_MINIMO_REFRESCO_SEGUNDOS: Final = 60
_TIMEOUT_JWKS_SEGUNDOS: Final = 5.0
_MARGEN_RELOJ_SEGUNDOS: Final = 30


@dataclass(frozen=True, slots=True)
class ClaimsVerificados:
    """Claims utiles de un token ya validado."""

    sub: str
    email: str | None
    roles: tuple[str, ...]
    scopes: tuple[str, ...]
    expira_en: int

    @property
    def tiene_email_verificado(self) -> bool:
        return self.email is not None


class VerificadorDeTokens:
    """
    Valida tokens de acceso contra el JWKS del proveedor de identidad.

    Instancia unica por proceso: mantiene la cache de claves publicas.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        roles_claim: str,
        jwks_cache_seconds: int = 3600,
    ) -> None:
        self._issuer = issuer if issuer.endswith("/") else f"{issuer}/"
        self._audience = audience
        self._roles_claim = roles_claim
        self._jwks_url = f"{self._issuer}.well-known/jwks.json"
        self._cache_seconds = jwks_cache_seconds

        self._cliente_jwks: PyJWKClient | None = None
        self._cargado_en: float = 0.0
        self._ultimo_refresco_forzado: float = 0.0
        self._cerrojo = asyncio.Lock()

    # ── JWKS ─────────────────────────────────────────────────────────

    async def _obtener_cliente(self, *, forzar_refresco: bool = False) -> PyJWKClient:
        ahora = time.monotonic()
        cache_vencida = (ahora - self._cargado_en) > self._cache_seconds

        if self._cliente_jwks is not None and not cache_vencida and not forzar_refresco:
            return self._cliente_jwks

        async with self._cerrojo:
            # Otra corrutina pudo refrescar mientras esperabamos el cerrojo.
            ahora = time.monotonic()
            if (
                self._cliente_jwks is not None
                and (ahora - self._cargado_en) <= self._cache_seconds
                and not forzar_refresco
            ):
                return self._cliente_jwks

            if (
                forzar_refresco
                and (ahora - self._ultimo_refresco_forzado) < _INTERVALO_MINIMO_REFRESCO_SEGUNDOS
            ):
                # Freno al refresco por `kid` desconocido. Sin esto, tokens
                # con kid aleatorio generan una descarga de JWKS por peticion.
                if self._cliente_jwks is not None:
                    return self._cliente_jwks
                raise TokenInvalido()

            await self._descargar_jwks()
            if forzar_refresco:
                self._ultimo_refresco_forzado = ahora
            if self._cliente_jwks is None:  # pragma: no cover - defensivo
                # `_descargar_jwks` lanza si falla, asi que no deberia
                # ocurrir. Un `assert` aqui se evaporaria bajo `python -O`.
                raise TokenInvalido()
            return self._cliente_jwks

    async def _descargar_jwks(self) -> None:
        """
        Descarga el JWKS verificando TLS.

        Se descarga con httpx (async) y se entrega a PyJWKClient ya
        resuelto, para no bloquear el event loop con la descarga sincrona
        que PyJWKClient hace por su cuenta.
        """
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_JWKS_SEGUNDOS, verify=True) as cliente:
                respuesta = await cliente.get(self._jwks_url)
                respuesta.raise_for_status()
                respuesta.json()  # valida que sea JSON antes de cachear
        except (httpx.HTTPError, ValueError) as exc:
            raise TokenInvalido("No fue posible validar las credenciales en este momento.") from exc

        self._cliente_jwks = PyJWKClient(
            self._jwks_url,
            cache_keys=True,
            lifespan=self._cache_seconds,
            timeout=int(_TIMEOUT_JWKS_SEGUNDOS),
        )
        self._cargado_en = time.monotonic()

    # ── Verificacion ─────────────────────────────────────────────────

    async def verificar(self, token: str) -> ClaimsVerificados:
        """
        Valida firma y claims. Lanza TokenInvalido ante cualquier anomalia.

        El mensaje de error nunca distingue el motivo: "firma invalida" y
        "token expirado" dan informacion distinta a quien esta probando.
        """
        cabecera = self._leer_cabecera(token)
        kid = cabecera.get("kid")
        if not kid:
            raise TokenInvalido()

        # Rechazo temprano del `alg` de la cabecera. jwt.decode ya lo
        # impondria via `algorithms=`, pero fallar aqui deja el intento
        # registrado como lo que es: un ataque conocido, no un error.
        if cabecera.get("alg") not in ALGORITMOS_PERMITIDOS:
            raise TokenInvalido()

        clave = await self._resolver_clave(kid)

        try:
            carga: dict[str, Any] = jwt.decode(
                token,
                key=clave,
                algorithms=ALGORITMOS_PERMITIDOS,
                audience=self._audience,
                issuer=self._issuer,
                leeway=_MARGEN_RELOJ_SEGUNDOS,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise TokenInvalido() from exc

        return self._extraer_claims(carga)

    async def _resolver_clave(self, kid: str) -> Any:
        cliente = await self._obtener_cliente()
        try:
            return cliente.get_signing_key(kid).key
        except PyJWKClientError:
            # `kid` desconocido puede significar rotacion legitima de claves.
            # Un solo reintento con refresco, sujeto al freno de arriba.
            cliente = await self._obtener_cliente(forzar_refresco=True)
            try:
                return cliente.get_signing_key(kid).key
            except PyJWKClientError as exc:
                raise TokenInvalido() from exc

    @staticmethod
    def _leer_cabecera(token: str) -> dict[str, Any]:
        try:
            cabecera: dict[str, Any] = jwt.get_unverified_header(token)
            return cabecera
        except jwt.PyJWTError as exc:
            raise TokenInvalido() from exc

    def _extraer_claims(self, carga: dict[str, Any]) -> ClaimsVerificados:
        roles_crudos = carga.get(self._roles_claim, [])
        roles = tuple(str(r) for r in roles_crudos) if isinstance(roles_crudos, list) else ()

        scope_crudo = carga.get("scope", "")
        scopes = tuple(scope_crudo.split()) if isinstance(scope_crudo, str) else ()

        correo = carga.get("email")
        return ClaimsVerificados(
            sub=str(carga["sub"]),
            email=str(correo) if correo else None,
            roles=roles,
            scopes=scopes,
            expira_en=int(carga["exp"]),
        )
