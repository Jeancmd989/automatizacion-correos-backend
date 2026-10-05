"""
Registro de auditoria sobre PostgreSQL.

Proposito
    Persistir la bitacora en una tabla append-only, sin que un fallo de
    escritura pueda tumbar la operacion que la origino.

Dependencias
    SQLAlchemy async.

Decision de diseño
    La tabla no tiene politica de UPDATE ni de DELETE en RLS (ver la
    migracion): el rol de aplicacion solo puede insertar y leer. Aunque
    alguien escriba un `UPDATE audit_log`, PostgreSQL lo rechaza. Una
    bitacora que el propio sistema puede reescribir no sirve como prueba.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, Index, String, func, select
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from mailauto.modules.audit.domain.entities import AccionAuditada, EntradaDeAuditoria
from mailauto.modules.audit.domain.ports import RegistroDeAuditoria
from mailauto.shared.db.base import Base, MixinDeTenant
from mailauto.shared.db.session import FabricaDeSesiones
from mailauto.shared.observability.logging import obtener_logger
from mailauto.shared.pagination import Cursor, Pagina, SolicitudDePagina
from mailauto.shared.security.context import TenantContext

logger = obtener_logger(__name__)


class EntradaDeAuditoriaORM(MixinDeTenant, Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_tenant_ocurrido", "tenant_id", "ocurrido_en"),)

    # BIGSERIAL y no UUID: es una tabla de solo-insercion con mucho
    # volumen, y un entero secuencial es la clave mas barata de mantener.
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    actor_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    actor_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    accion: Mapped[str] = mapped_column(String(64), nullable=False)
    tipo_de_recurso: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    recurso_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    metadatos: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    ocurrido_en: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class RegistroDeAuditoriaPostgres(RegistroDeAuditoria):
    def __init__(self, sesiones: FabricaDeSesiones) -> None:
        self._sesiones = sesiones

    async def registrar(
        self,
        ctx: TenantContext,
        *,
        accion: AccionAuditada,
        tipo_de_recurso: str,
        recurso_id: UUID | None = None,
        metadatos: dict[str, Any] | None = None,
    ) -> None:
        try:
            async with self._sesiones.sesion_de_tenant(ctx) as sesion:
                sesion.add(
                    EntradaDeAuditoriaORM(
                        tenant_id=ctx.tenant_id,
                        actor_id=ctx.user_id,
                        actor_ip=ctx.ip_origen,
                        accion=accion.value,
                        tipo_de_recurso=tipo_de_recurso,
                        recurso_id=recurso_id,
                        metadatos=metadatos or {},
                    )
                )
        except Exception:
            # La auditoria no puede hacer fallar la accion auditada. Se
            # emite a nivel error para que el monitoreo lo detecte: perder
            # trazabilidad es un incidente, aunque no sea un fallo visible.
            logger.error(
                "fallo_al_registrar_auditoria",
                accion=accion.value,
                **ctx.para_log(),
            )

    async def listar(
        self, ctx: TenantContext, pagina: SolicitudDePagina
    ) -> Pagina[EntradaDeAuditoria]:
        async with self._sesiones.sesion_de_tenant(ctx) as sesion:
            consulta = select(EntradaDeAuditoriaORM).order_by(
                EntradaDeAuditoriaORM.ocurrido_en.desc(), EntradaDeAuditoriaORM.id.desc()
            )
            cursor = pagina.cursor_decodificado()
            if cursor is not None:
                consulta = consulta.where(EntradaDeAuditoriaORM.ocurrido_en < cursor.creado_en)
            filas = list(await sesion.scalars(consulta.limit(pagina.limite + 1)))

            hay_mas = len(filas) > pagina.limite
            visibles = filas[: pagina.limite]
            siguiente = None
            if hay_mas and visibles:
                ultima = visibles[-1]
                # El cursor de auditoria usa un UUID nulo como desempate:
                # el id es un entero y no encaja en el formato generico.
                siguiente = Cursor(
                    creado_en=ultima.ocurrido_en,
                    identificador=UUID(int=0),
                ).codificar()

            return Pagina(
                elementos=[_a_dominio(f) for f in visibles],
                siguiente_cursor=siguiente,
                hay_mas=hay_mas,
            )


def _a_dominio(fila: EntradaDeAuditoriaORM) -> EntradaDeAuditoria:
    return EntradaDeAuditoria(
        id=fila.id,
        tenant_id=fila.tenant_id,
        actor_id=fila.actor_id,
        actor_ip=fila.actor_ip,
        accion=AccionAuditada(fila.accion),
        tipo_de_recurso=fila.tipo_de_recurso,
        recurso_id=fila.recurso_id,
        metadatos=fila.metadatos or {},
        ocurrido_en=fila.ocurrido_en,
    )
