"""
Dependencias de FastAPI.

Proposito
    Resolver autenticacion, tenant y paginacion antes de que la peticion
    llegue al caso de uso, de modo que ningun router repita esa logica.

Flujo
    Authorization -> verificar JWT -> resolver identidad -> TenantContext
    -> inyectado en el endpoint

Dependencias
    FastAPI y el `Contenedor`. No importa infraestructura directamente
    (contrato `api-sin-infraestructura`): todo llega ya construido.

Decision de diseño
    `obtener_contexto` tambien deja el contexto en `request.state`, porque
    el middleware de rate limit se ejecuta antes que las dependencias y
    necesita identificar al usuario para contar por sujeto y no por IP.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, Query, Request

from mailauto.bootstrap.container import Contenedor
from mailauto.shared.errors import ErrorDeAutenticacion, ErrorDeValidacion
from mailauto.shared.pagination import LIMITE_MAXIMO, LIMITE_POR_DEFECTO, SolicitudDePagina
from mailauto.shared.security.context import Permiso, TenantContext


def obtener_contenedor(request: Request) -> Contenedor:
    contenedor: Contenedor = request.app.state.contenedor
    return contenedor


ContenedorDep = Annotated[Contenedor, Depends(obtener_contenedor)]


async def obtener_contexto(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_tenant_id: Annotated[str | None, Header()] = None,
) -> TenantContext:
    """Autentica la peticion y resuelve el tenant activo."""
    # El token se extrae primero, a proposito: una peticion sin cabecera
    # de autorizacion se rechaza sin resolver el contenedor ni abrir
    # ninguna conexion.
    token = _extraer_bearer(authorization)

    contenedor = obtener_contenedor(request)
    claims = await contenedor.verificador.verificar(token)

    tenant_solicitado = _parsear_tenant(x_tenant_id)

    contexto = await contenedor.resolver_identidad.ejecutar(
        claims,
        tenant_solicitado=tenant_solicitado,
        ip_origen=request.client.host if request.client else None,
        request_id=getattr(request.state, "request_id", None),
    )
    request.state.tenant_context = contexto
    return contexto


ContextoDep = Annotated[TenantContext, Depends(obtener_contexto)]


def exige(permiso: Permiso):  # type: ignore[no-untyped-def]
    """
    Dependencia que verifica un permiso en el borde.

    El caso de uso vuelve a comprobarlo por su cuenta: esto es solo para
    que la peticion se rechace antes de abrir una transaccion, no la
    unica barrera. Si fuera la unica, invocar el caso de uso desde un
    worker se saltaria el control.
    """

    async def verificar(contexto: ContextoDep) -> TenantContext:
        contexto.exigir(permiso)
        return contexto

    return verificar


def obtener_paginacion(
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limite: Annotated[int, Query(ge=1, le=LIMITE_MAXIMO)] = LIMITE_POR_DEFECTO,
) -> SolicitudDePagina:
    return SolicitudDePagina(cursor=cursor, limite=limite)


PaginacionDep = Annotated[SolicitudDePagina, Depends(obtener_paginacion)]


def obtener_clave_de_idempotencia(
    idempotency_key: Annotated[str | None, Header(max_length=128)] = None,
) -> str | None:
    """
    Clave de idempotencia opcional pero recomendada en los POST que crean
    trabajo. Se valida la longitud para que no sirva de vector de
    almacenamiento arbitrario.
    """
    if idempotency_key is None:
        return None
    clave = idempotency_key.strip()
    if not clave or len(clave) > 128:
        raise ErrorDeValidacion("Idempotency-Key invalida.", campo="Idempotency-Key")
    return clave


# ── Auxiliares ───────────────────────────────────────────────────────


def _extraer_bearer(cabecera: str | None) -> str:
    if not cabecera:
        raise ErrorDeAutenticacion()
    partes = cabecera.split(maxsplit=1)
    # Comparacion insensible a mayusculas: RFC 7235 define el esquema como
    # case-insensitive y algunos clientes envian "bearer".
    if len(partes) != 2 or partes[0].lower() != "bearer" or not partes[1].strip():
        raise ErrorDeAutenticacion()
    return partes[1].strip()


def _parsear_tenant(crudo: str | None) -> UUID | None:
    if not crudo:
        return None
    try:
        return UUID(crudo)
    except ValueError as exc:
        raise ErrorDeValidacion("X-Tenant-Id no es un UUID valido.", campo="X-Tenant-Id") from exc
