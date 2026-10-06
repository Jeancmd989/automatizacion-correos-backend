"""
Sesiones de base de datos con aislamiento multi-tenant.

Proposito
    Garantizar que toda consulta se ejecute dentro de una transaccion que
    ya declaro a que tenant pertenece, de modo que Row Level Security
    pueda filtrar aunque el repositorio olvide un WHERE.

Flujo
    peticion -> TenantContext -> sesion_de_tenant() -> SET LOCAL
    app.current_tenant -> consultas -> commit -> la variable muere con la
    transaccion.

Dependencias
    SQLAlchemy async + asyncpg.

Decisiones de diseño
    1. `SET LOCAL` y no `SET`. `SET LOCAL` vive solo dentro de la
       transaccion; `SET` persistiria en la conexion y, al devolverla al
       pool, la siguiente peticion de *otro tenant* heredaria el valor.
       Esa diferencia de una palabra es toda la seguridad del esquema.

    2. El tenant se interpola como parametro vinculado, nunca concatenado.
       `SET LOCAL` no admite placeholders directamente, asi que se usa
       `set_config()`, que si es una funcion con parametros y por tanto
       inmune a inyeccion.

    3. Existe una sesion "sin tenant" para operaciones de sistema
       (resolver la identidad antes de conocer el tenant, migraciones,
       jobs de cron). Es explicita y de nombre incomodo a proposito:
       debe costar usarla por descuido.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from mailauto.shared.security.context import TenantContext

_VARIABLE_TENANT = "app.current_tenant"


def crear_engine(
    url: str,
    *,
    pool_size: int,
    max_overflow: int,
    command_timeout: int,
    echo: bool,
) -> AsyncEngine:
    """
    Crea el engine async.

    `pool_pre_ping` detecta conexiones muertas por un reinicio del servidor
    o por el corte de un balanceador, a cambio de un ping barato. Sin el,
    el primer request tras una caida de red falla aunque la BD ya este sana.
    """
    return create_async_engine(
        url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=True,
        pool_recycle=1800,
        echo=echo,
        connect_args={
            "command_timeout": command_timeout,
            # Las sentencias preparadas de asyncpg no conviven bien con
            # PgBouncer en modo transaction; desactivarlas mantiene la
            # compatibilidad con el pooler.
            "statement_cache_size": 0,
            "server_settings": {"application_name": "mailauto-api"},
        },
    )


class FabricaDeSesiones:
    """
    Punto unico de creacion de sesiones.

    Se inyecta en los repositorios en lugar de una sesion suelta, para que
    sea la fabrica quien garantice que el contexto de tenant quedo fijado.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._crear = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,  # permite leer entidades tras el commit
            autoflush=False,  # el flush explicito hace predecible el orden del SQL
        )

    @asynccontextmanager
    async def sesion_de_tenant(self, ctx: TenantContext) -> AsyncIterator[AsyncSession]:
        """
        Sesion con RLS activo para el tenant del contexto.

        Es la unica forma admitida de tocar tablas de negocio. Abre
        transaccion, fija `app.current_tenant`, y hace commit o rollback.
        """
        async with self._crear() as sesion, sesion.begin():
            await _fijar_tenant(sesion, ctx.tenant_id)
            yield sesion

    @asynccontextmanager
    async def sesion_de_tenant_por_id(self, tenant_id: UUID) -> AsyncIterator[AsyncSession]:
        """
        Variante para los workers, que reciben el tenant_id en la carga del
        job y no tienen un TenantContext completo de una peticion HTTP.
        """
        async with self._crear() as sesion, sesion.begin():
            await _fijar_tenant(sesion, tenant_id)
            yield sesion

    @asynccontextmanager
    async def sesion_de_sistema_sin_aislamiento(self) -> AsyncIterator[AsyncSession]:
        """
        Sesion SIN contexto de tenant. Solo para tablas globales
        (`users`, `tenants`, `memberships`) o tareas de mantenimiento.

        Nombre largo e incomodo a proposito: aparece en las revisiones de
        codigo y obliga a justificar cada uso.
        """
        async with self._crear() as sesion, sesion.begin():
            yield sesion

    @property
    def engine(self) -> AsyncEngine:
        """
        Motor subyacente.

        Lo necesita la instrumentacion de trazas, que envuelve el engine y
        no las sesiones. Se expone como propiedad de solo lectura para que
        nadie lo sustituya y se salte el aislamiento por tenant.
        """
        return self._engine

    async def cerrar(self) -> None:
        await self._engine.dispose()

    async def esta_disponible(self) -> bool:
        """Sonda para /health/ready."""
        try:
            async with self._engine.connect() as conexion:
                await conexion.execute(text("SELECT 1"))
            return True
        except Exception:  # noqa: BLE001 - sonda de salud: informa binario, no diagnostica
            return False


async def _fijar_tenant(sesion: AsyncSession, tenant_id: UUID) -> None:
    """
    Declara el tenant de la transaccion para que las politicas RLS filtren.

    `set_config(clave, valor, is_local=true)` equivale a `SET LOCAL` pero
    acepta parametros vinculados, asi que el UUID nunca se concatena en el
    texto de la sentencia.
    """
    await sesion.execute(
        text("SELECT set_config(:clave, :valor, true)"),
        {"clave": _VARIABLE_TENANT, "valor": str(tenant_id)},
    )


async def leer_tenant_actual(sesion: AsyncSession) -> str | None:
    """
    Devuelve el tenant fijado en la transaccion. Lo usan los tests de
    seguridad para comprobar que el aislamiento esta realmente activo.
    """
    resultado: Any = await sesion.execute(
        text("SELECT current_setting(:clave, true)"), {"clave": _VARIABLE_TENANT}
    )
    valor = resultado.scalar_one_or_none()
    return str(valor) if valor else None
