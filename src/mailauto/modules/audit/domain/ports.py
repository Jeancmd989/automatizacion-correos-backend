"""
Puerto de auditoria.

Proposito
    Permitir que cualquier caso de uso registre una accion sin conocer
    donde se persiste.

Dependencias
    Entidades del propio dominio y `shared`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID

from mailauto.modules.audit.domain.entities import AccionAuditada, EntradaDeAuditoria
from mailauto.shared.pagination import Pagina, SolicitudDePagina
from mailauto.shared.security.context import TenantContext


class RegistroDeAuditoria(ABC):
    @abstractmethod
    async def registrar(
        self,
        ctx: TenantContext,
        *,
        accion: AccionAuditada,
        tipo_de_recurso: str,
        recurso_id: UUID | None = None,
        metadatos: dict[str, Any] | None = None,
    ) -> None:
        """
        Escribe una entrada.

        Nunca debe propagar una excepcion al llamante: que falle la
        auditoria no puede impedir la operacion que el usuario pidio. El
        fallo se registra en el log para que el monitoreo lo detecte.
        """

    @abstractmethod
    async def listar(
        self, ctx: TenantContext, pagina: SolicitudDePagina
    ) -> Pagina[EntradaDeAuditoria]: ...
