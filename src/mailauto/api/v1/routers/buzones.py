"""
Rutas de vinculacion de buzones.

Proposito
    Exponer el flujo OAuth y la gestion de conexiones, delegando toda la
    logica en los casos de uso.

Dependencias
    FastAPI, casos de uso del modulo de buzones, registro de auditoria.

Decision de diseño
    El callback es POST y no GET. El proveedor redirige al frontend con
    el codigo en la query; es el frontend (su BFF) quien lo envia aqui en
    el cuerpo. Asi el codigo de autorizacion no queda en los logs de
    acceso del servidor ni en el historial del navegador, que es donde
    suele acabar cuando el callback es un GET directo contra la API.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Response, status

from mailauto.api.deps import ContenedorDep, ContextoDep
from mailauto.api.schemas.comunes import (
    BuzonSalida,
    CallbackEntrada,
    IniciarVinculacionEntrada,
    Respuesta,
    UrlDeAutorizacionSalida,
)
from mailauto.modules.audit.domain.entities import AccionAuditada
from mailauto.modules.mailbox.domain.entities import Proveedor

router = APIRouter(prefix="/mailboxes", tags=["buzones"])


@router.get("", response_model=Respuesta[list[BuzonSalida]])
async def listar(contexto: ContextoDep, contenedor: ContenedorDep) -> Respuesta[list[BuzonSalida]]:
    conexiones = await contenedor.listar_buzones.ejecutar(contexto)
    return Respuesta(data=[BuzonSalida.desde_dominio(c) for c in conexiones])


@router.post("/authorize", response_model=Respuesta[UrlDeAutorizacionSalida])
async def autorizar(
    entrada: IniciarVinculacionEntrada,
    contexto: ContextoDep,
    contenedor: ContenedorDep,
) -> Respuesta[UrlDeAutorizacionSalida]:
    """Devuelve la URL de consentimiento. El `state` y el PKCE quedan en Redis."""
    url = await contenedor.iniciar_vinculacion.ejecutar(
        contexto,
        proveedor=Proveedor(entrada.proveedor),
        redirect_uri=entrada.redirect_uri,
    )
    return Respuesta(data=UrlDeAutorizacionSalida(url_de_autorizacion=url))


@router.post(
    "/callback", response_model=Respuesta[BuzonSalida], status_code=status.HTTP_201_CREATED
)
async def callback(
    entrada: CallbackEntrada,
    contexto: ContextoDep,
    contenedor: ContenedorDep,
) -> Respuesta[BuzonSalida]:
    """Completa la vinculacion canjeando el codigo por tokens."""
    conexion = await contenedor.completar_vinculacion.ejecutar(
        contexto, codigo=entrada.codigo, state=entrada.state
    )
    await contenedor.auditoria.registrar(
        contexto,
        accion=AccionAuditada.BUZON_VINCULADO,
        tipo_de_recurso="mailbox_connection",
        recurso_id=conexion.id,
        metadatos={"proveedor": conexion.proveedor.value},
    )
    return Respuesta(data=BuzonSalida.desde_dominio(conexion))


# `response_class=Response` es obligatorio con 204: la clase JSON por
# defecto generaria un cuerpo, y un 204 con cuerpo es invalido segun la
# especificacion HTTP. FastAPI lo rechaza al montar la ruta.
@router.delete(
    "/{conexion_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def desvincular(
    conexion_id: UUID,
    contexto: ContextoDep,
    contenedor: ContenedorDep,
) -> Response:
    """Revoca el consentimiento en el proveedor y elimina la conexion."""
    await contenedor.desvincular_buzon.ejecutar(contexto, conexion_id)
    await contenedor.auditoria.registrar(
        contexto,
        accion=AccionAuditada.BUZON_DESVINCULADO,
        tipo_de_recurso="mailbox_connection",
        recurso_id=conexion_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
