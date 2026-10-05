"""
Fixtures compartidas.

Proposito
    Dar a los tests datos y objetos listos para usar, sin que cada
    fichero reconstruya el mismo andamiaje.

Decision de diseño
    Las fixtures de dominio no tocan base de datos. Los tests unitarios
    deben correr en milisegundos y sin infraestructura; si para probar el
    validador de RUC hiciera falta PostgreSQL, dejarian de ejecutarse en
    cada guardado y la suite perderia su utilidad.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from uuid import UUID

import pytest

from mailauto.shared.crypto.envelope import ClaveMaestraLocal, ServicioDeCifrado
from mailauto.shared.security.context import Rol, TenantContext

TENANT_A = UUID("00000000-0000-7000-8000-00000000000a")
TENANT_B = UUID("00000000-0000-7000-8000-00000000000b")
USUARIO_A = UUID("00000000-0000-7000-8000-0000000000a1")
USUARIO_B = UUID("00000000-0000-7000-8000-0000000000b1")


@pytest.fixture(autouse=True)
def _entorno_de_pruebas(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Variables minimas para que importar la configuracion no falle."""
    monkeypatch.setenv("ENVIRONMENT", "testing")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost:5432/mailauto_test")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/1")
    monkeypatch.setenv("OIDC_ISSUER", "https://pruebas.ejemplo.com/")
    monkeypatch.setenv("OIDC_AUDIENCE", "https://api.ejemplo.com")
    monkeypatch.setenv("MASTER_KEY_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "id-de-pruebas")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secreto-de-pruebas")
    monkeypatch.setenv("STORAGE_ACCESS_KEY", "pruebas")
    monkeypatch.setenv("STORAGE_SECRET_KEY", "pruebas")
    yield


@pytest.fixture
def cifrado() -> ServicioDeCifrado:
    return ServicioDeCifrado(ClaveMaestraLocal(os.urandom(32)))


@pytest.fixture
def contexto_a() -> TenantContext:
    return TenantContext.construir(
        tenant_id=TENANT_A,
        user_id=USUARIO_A,
        external_id="auth0|a",
        rol=Rol.OPERATOR,
    )


@pytest.fixture
def contexto_b() -> TenantContext:
    return TenantContext.construir(
        tenant_id=TENANT_B,
        user_id=USUARIO_B,
        external_id="auth0|b",
        rol=Rol.OPERATOR,
    )


@pytest.fixture
def contexto_admin() -> TenantContext:
    return TenantContext.construir(
        tenant_id=TENANT_A,
        user_id=USUARIO_A,
        external_id="auth0|admin",
        rol=Rol.ADMIN,
    )


# ── Generadores de ficheros de prueba ────────────────────────────────


def pdf_valido(paginas: int = 1) -> bytes:
    """PDF minimo sintetico. Nunca se usa un documento real en los tests."""
    cuerpo = b"%PDF-1.7\n"
    for i in range(paginas):
        cuerpo += f"{i + 1} 0 obj\n<</Type/Page>>\nendobj\n".encode()
    cuerpo += b"trailer\n<</Root 1 0 R>>\n%%EOF\n"
    return cuerpo + b"\x00" * max(0, 128 - len(cuerpo))


def png_valido() -> bytes:
    return b"\x89PNG\r\n\x1a\n" + b"\x00" * 200


def jpeg_valido() -> bytes:
    return b"\xff\xd8\xff\xe0" + b"\x00" * 200
