"""
Contrato de esquema compartido entre los tests estaticos y los de integracion.

Proposito
    Exponer una sola vez la lista de tablas que deben estar protegidas
    por Row Level Security y las que estan excluidas a proposito.

Por que vive aqui
    Dos tests distintos necesitan la misma informacion desde angulos
    opuestos: uno comprueba que la migracion declare la politica, el
    otro que PostgreSQL la tenga activa. Si cada uno leyera las
    migraciones por su cuenta, un cambio en el formato del contrato
    arreglaria la mitad de la verificacion y dejaria la otra mirando a
    una lista vacia, que es la forma mas silenciosa de fallar.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

# Tablas que NO se filtran por tenant a proposito. `tenants` y `users`
# no tienen columna; `memberships` si la tiene, pero es justo la tabla
# que dice a que tenant pertenece un usuario, y filtrarla por el tenant
# activo seria circular.
TABLAS_GLOBALES: frozenset[str] = frozenset({"tenants", "users", "memberships"})

# Tabla de control de Alembic: ni es de negocio ni lleva tenant.
TABLAS_DE_INFRAESTRUCTURA: frozenset[str] = frozenset({"alembic_version"})

_RAIZ = Path(__file__).resolve().parents[1]
_MIGRACIONES = _RAIZ / "migrations" / "versions"


def importar_todos_los_modelos() -> None:
    """
    Puebla `Base.metadata`.

    Sin estos imports la metadata esta vacia y cualquier comprobacion
    sobre ella pasaria sin comprobar nada, que es peor que no tenerla.
    """
    import mailauto.modules.audit.infrastructure.repository
    import mailauto.modules.extraction.infrastructure.persistence.models
    import mailauto.modules.identity.infrastructure.models
    import mailauto.modules.ingestion.infrastructure.models
    import mailauto.modules.mailbox.infrastructure.models
    import mailauto.modules.reporting.infrastructure.models  # noqa: F401


def ficheros_de_migracion() -> list[Path]:
    ficheros = sorted(_MIGRACIONES.glob("*.py"))
    assert ficheros, "No se encontro ninguna migracion"
    return ficheros


def tablas_protegidas_por_las_migraciones() -> set[str]:
    """
    Union de las constantes `TABLAS_CON_RLS` de todas las migraciones.

    Se leen de la constante y no del texto SQL porque las migraciones
    generan las sentencias en un bucle: el literal
    `ALTER TABLE attachments ...` no llega a aparecer en el fichero.
    La constante es el contrato explicito entre migracion y test.
    """
    protegidas: set[str] = set()
    for fichero in ficheros_de_migracion():
        especificacion = importlib.util.spec_from_file_location(
            f"_migracion_{fichero.stem}", fichero
        )
        assert especificacion is not None
        assert especificacion.loader is not None
        modulo = importlib.util.module_from_spec(especificacion)
        especificacion.loader.exec_module(modulo)
        protegidas.update(getattr(modulo, "TABLAS_CON_RLS", ()))
    return protegidas


def tablas_de_negocio() -> set[str]:
    """Tablas con `tenant_id` que no estan excluidas del aislamiento."""
    from mailauto.shared.db.base import Base

    importar_todos_los_modelos()
    return {
        nombre
        for nombre, tabla in Base.metadata.tables.items()
        if "tenant_id" in tabla.columns and nombre not in TABLAS_GLOBALES
    }
