"""
Tests de seguridad del cifrado sobre envolvente.

Lo que se verifica aqui no es que el cifrado "funcione" (eso lo garantiza
la biblioteca), sino que el *diseño* resiste los ataques que motivaron
sus decisiones: reutilizacion de ciphertext entre filas, manipulacion y
sustitucion de clave.
"""

from __future__ import annotations

import os

import pytest

from mailauto.shared.crypto.envelope import (
    ClaveMaestraLocal,
    ContextoCripto,
    ServicioDeCifrado,
)
from mailauto.shared.errors import ErrorDeCifrado

pytestmark = pytest.mark.security


def _contexto(tenant: str = "tenant-a", sujeto: str = "google:usuario-1") -> ContextoCripto:
    return ContextoCripto(tenant_id=tenant, proposito="oauth_access_token", sujeto=sujeto)


def test_ida_y_vuelta(cifrado: ServicioDeCifrado) -> None:
    dek = cifrado.desenvolver_dek(cifrado.generar_dek())
    ctx = _contexto()

    cifrado_texto = cifrado.cifrar_texto(dek, "ya29.token-secreto", ctx)
    assert cifrado.descifrar_texto(dek, cifrado_texto, ctx) == "ya29.token-secreto"


def test_el_ciphertext_no_contiene_el_texto_plano(cifrado: ServicioDeCifrado) -> None:
    dek = cifrado.desenvolver_dek(cifrado.generar_dek())
    resultado = cifrado.cifrar_texto(dek, "ya29.token-secreto", _contexto())
    assert b"ya29" not in resultado


def test_un_ciphertext_de_otro_tenant_no_descifra(cifrado: ServicioDeCifrado) -> None:
    """
    El ataque que cierra la AAD: alguien con acceso de escritura a la base
    de datos copia el token cifrado del tenant A a la fila del tenant B,
    esperando que el sistema lo use en su nombre.
    """
    dek = cifrado.desenvolver_dek(cifrado.generar_dek())
    de_a = cifrado.cifrar_texto(dek, "token-de-a", _contexto(tenant="tenant-a"))

    with pytest.raises(ErrorDeCifrado):
        cifrado.descifrar_texto(dek, de_a, _contexto(tenant="tenant-b"))


def test_un_ciphertext_de_otro_usuario_no_descifra(cifrado: ServicioDeCifrado) -> None:
    """Misma proteccion dentro de un mismo tenant, entre usuarios distintos."""
    dek = cifrado.desenvolver_dek(cifrado.generar_dek())
    del_uno = cifrado.cifrar_texto(dek, "token", _contexto(sujeto="google:usuario-1"))

    with pytest.raises(ErrorDeCifrado):
        cifrado.descifrar_texto(dek, del_uno, _contexto(sujeto="google:usuario-2"))


def test_un_ciphertext_de_otro_proposito_no_descifra(cifrado: ServicioDeCifrado) -> None:
    """Un access token no puede hacerse pasar por un refresh token."""
    dek = cifrado.desenvolver_dek(cifrado.generar_dek())
    ctx_access = ContextoCripto(tenant_id="t", proposito="oauth_access_token", sujeto="s")
    ctx_refresh = ContextoCripto(tenant_id="t", proposito="oauth_refresh_token", sujeto="s")

    resultado = cifrado.cifrar_texto(dek, "token", ctx_access)
    with pytest.raises(ErrorDeCifrado):
        cifrado.descifrar_texto(dek, resultado, ctx_refresh)


@pytest.mark.parametrize("posicion", [0, 5, 20, -1])
def test_la_manipulacion_del_ciphertext_se_detecta(
    cifrado: ServicioDeCifrado, posicion: int
) -> None:
    """GCM autentica: cualquier bit alterado hace fallar el descifrado."""
    dek = cifrado.desenvolver_dek(cifrado.generar_dek())
    ctx = _contexto()
    resultado = bytearray(cifrado.cifrar_texto(dek, "token-secreto", ctx))
    resultado[posicion] ^= 0xFF

    with pytest.raises(ErrorDeCifrado):
        cifrado.descifrar_texto(dek, bytes(resultado), ctx)


def test_una_dek_distinta_no_descifra(cifrado: ServicioDeCifrado) -> None:
    """Comprometer la DEK de un tenant no expone los datos de otro."""
    dek_a = cifrado.desenvolver_dek(cifrado.generar_dek())
    dek_b = cifrado.desenvolver_dek(cifrado.generar_dek())
    ctx = _contexto()

    resultado = cifrado.cifrar_texto(dek_a, "token", ctx)
    with pytest.raises(ErrorDeCifrado):
        cifrado.descifrar_texto(dek_b, resultado, ctx)


def test_cada_cifrado_usa_un_nonce_distinto(cifrado: ServicioDeCifrado) -> None:
    """
    Reutilizar un nonce con la misma clave rompe GCM por completo: permite
    recuperar el texto plano y falsificar mensajes. Cifrar lo mismo dos
    veces debe producir ciphertexts diferentes.
    """
    dek = cifrado.desenvolver_dek(cifrado.generar_dek())
    ctx = _contexto()
    primero = cifrado.cifrar_texto(dek, "mismo-valor", ctx)
    segundo = cifrado.cifrar_texto(dek, "mismo-valor", ctx)
    assert primero != segundo


def test_una_kek_de_otra_version_no_desenvuelve() -> None:
    """La version de KEK va autenticada: no se puede presentar una antigua como actual."""
    servicio_v1 = ServicioDeCifrado(ClaveMaestraLocal(os.urandom(32), version=1))
    servicio_v2 = ServicioDeCifrado(ClaveMaestraLocal(os.urandom(32), version=2))

    envuelta = servicio_v1.generar_dek()
    with pytest.raises(ErrorDeCifrado):
        servicio_v2.desenvolver_dek(envuelta)


def test_detecta_dek_pendiente_de_rotacion() -> None:
    servicio_v1 = ServicioDeCifrado(ClaveMaestraLocal(os.urandom(32), version=1))
    envuelta = servicio_v1.generar_dek()

    servicio_v2 = ServicioDeCifrado(ClaveMaestraLocal(os.urandom(32), version=2))
    assert servicio_v2.necesita_rotacion(envuelta) is True
    assert servicio_v1.necesita_rotacion(envuelta) is False


def test_una_clave_maestra_corta_se_rechaza() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        ClaveMaestraLocal(os.urandom(16))
