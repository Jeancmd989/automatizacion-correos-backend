"""
Ruta de perfil y auditoria.

Proposito
    Que el frontend sepa quien es el usuario y que puede hacer, sin
    deducirlo del rol por su cuenta, y exponer la bitacora a los
    administradores.

Dependencias
    FastAPI y el contenedor.

Decision de diseño
    `/me` devuelve la lista de permisos efectivos, no solo el rol. Asi el
    frontend oculta o muestra acciones consultando un permiso concreto, y
    no replicando la tabla rol->permisos del backend, que inevitablemente
    se desincronizaria.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from mailauto.api.deps import ContenedorDep, ContextoDep, PaginacionDep, exige
from mailauto.api.schemas.comunes import (
    EntradaDeAuditoriaSalida,
    MetaDePagina,
    PerfilSalida,
    Respuesta,
)
from mailauto.shared.security.context import Permiso, TenantContext

router = APIRouter(tags=["perfil"])


@router.get("/me", response_model=Respuesta[PerfilSalida])
async def perfil(contexto: ContextoDep) -> Respuesta[PerfilSalida]:
    return Respuesta(
        data=PerfilSalida(
            user_id=contexto.user_id,
            tenant_id=contexto.tenant_id,
            email=contexto.external_id,
            rol=contexto.rol.value,
            permisos=sorted(p.value for p in contexto.permisos),
        )
    )


@router.get("/audit", response_model=Respuesta[list[EntradaDeAuditoriaSalida]])
async def auditoria(
    contenedor: ContenedorDep,
    pagina: PaginacionDep,
    contexto: TenantContext = Depends(exige(Permiso.ADMIN_READ)),
) -> Respuesta[list[EntradaDeAuditoriaSalida]]:
    """Bitacora del tenant. Requiere rol administrativo."""
    resultado = await contenedor.auditoria.listar(contexto, pagina)
    return Respuesta(
        data=[EntradaDeAuditoriaSalida.desde_dominio(e) for e in resultado.elementos],
        meta=MetaDePagina(
            cursor=resultado.siguiente_cursor, hay_mas=resultado.hay_mas
        ).model_dump(),
    )
