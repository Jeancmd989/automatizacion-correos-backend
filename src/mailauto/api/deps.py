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

Decisiones de diseño
    1. `obtener_contexto` deja el contexto en `request.state` para que el
       middleware de correlacion pueda enriquecer el log de la peticion
       una vez resuelta. No sirve para el rate limit: ese middleware se
       ejecuta ANTES de las dependencias y nunca vera este valor.

    2. Las cuotas de negocio —escaneos por hora, vinculaciones por hora—
       se aplican aqui con `limita_por_tenant` y no en el middleware. El
       middleware solo puede identificar por IP, y contar una cuota de
       tenant por IP antes de autenticar permite que cualquiera sin
       credenciales agote la cuota de todos los que comparten salida a
       internet. Ver `mailauto.shared.cuotas`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, Query, Request, params

from mailauto.bootstrap.container import Contenedor
from mailauto.bootstrap.settings import Settings
from mailauto.shared.errors import ErrorDeAutenticacion, ErrorDeValidacion, LimiteExcedido
from mailauto.shared.observability import metricas
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


def limita_por_tenant(
    recurso: str,
    *,
    maximo_de: Callable[[Settings], int],
    ventana_segundos: int,
) -> params.Depends:
    """
    Dependencia de cuota por tenant para una operacion concreta.

    Se declara con un lector de la configuracion (`maximo_de`) en lugar
    de con un numero: el limite se resuelve en cada peticion a partir de
    los ajustes del contenedor, de modo que el valor efectivo es el del
    despliegue y no el que hubiera al importar el modulo.

    Corre despues de `obtener_contexto`, asi que el consumo se atribuye al
    tenant autenticado. Una peticion sin credenciales valida se rechaza
    antes de llegar aqui y no gasta cuota de nadie.
    """

    async def verificar(contexto: ContextoDep, contenedor: ContenedorDep) -> None:
        maximo = maximo_de(contenedor.settings)
        permitido = await contenedor.cuotas.consumir(
            recurso=recurso,
            tenant_id=contexto.tenant_id,
            maximo=maximo,
            ventana_segundos=ventana_segundos,
        )
        if not permitido:
            metricas.rechazos_por_limite.labels(control="cuota").inc()
            raise LimiteExcedido(
                reintentar_en_segundos=ventana_segundos,
                contexto={"recurso": recurso, "maximo": maximo},
            )

    # Se construye la clase y no el ayudante `Depends()`, que devuelve
    # `Any` y dejaria la firma de esta funcion sin verificar.
    return params.Depends(dependency=verificar)


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
