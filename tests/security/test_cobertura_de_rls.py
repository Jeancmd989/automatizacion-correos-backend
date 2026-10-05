"""
Test de cobertura de Row Level Security.

Proposito
    Impedir que una tabla futura entre al esquema con `tenant_id` y
    sin politica de aislamiento.

Por que hace falta
    El aislamiento entre clientes depende de dos cosas: la columna y
    la politica. La columna es dificil de olvidar (sin ella el modelo
    no encaja con las claves foraneas); la politica, en cambio, vive
    en la migracion y no en el modelo, y olvidarla no produce ningun
    error. El esquema queda aparentemente correcto y los datos de un
    cliente pasan a ser visibles para otro.

    Este test compara la metadata declarada en el codigo con la lista
    de tablas que cada migracion declara proteger. No necesita base de
    datos, asi que corre en cada push y no solo en el job de
    integracion.

    La verificacion contra PostgreSQL real -que la politica este
    ACTIVA y que el rol de aplicacion no sea propietario- corresponde
    a los tests de integracion de la fase 7. Este cubre el olvido, que
    es el fallo frecuente; aquel cubre la configuracion, que es el
    fallo raro.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from mailauto.shared.db.base import Base

pytestmark = pytest.mark.security

# Tablas que NO se filtran por tenant a proposito. `tenants` y `users`
# no tienen columna; `memberships` si la tiene, pero es justo la tabla
# que dice a que tenant pertenece un usuario, y filtrarla por el
# tenant activo seria circular.
TABLAS_GLOBALES: frozenset[str] = frozenset({"tenants", "users", "memberships"})

_RAIZ = Path(__file__).resolve().parents[2]
_MIGRACIONES = _RAIZ / "migrations" / "versions"


def _importar_todos_los_modelos() -> None:
    """
    Puebla `Base.metadata`.

    Sin estos imports la metadata esta vacia y el fichero entero
    pasaria sin comprobar nada, que es peor que no tenerlo.
    """
    import mailauto.modules.audit.infrastructure.repository
    import mailauto.modules.extraction.infrastructure.persistence.models
    import mailauto.modules.identity.infrastructure.models
    import mailauto.modules.ingestion.infrastructure.models
    import mailauto.modules.mailbox.infrastructure.models
    import mailauto.modules.reporting.infrastructure.models  # noqa: F401


def _ficheros_de_migracion() -> list[Path]:
    ficheros = sorted(_MIGRACIONES.glob("*.py"))
    assert ficheros, "No se encontro ninguna migracion"
    return ficheros


def _texto_de_las_migraciones() -> str:
    return "\n".join(f.read_text(encoding="utf-8") for f in _ficheros_de_migracion())


def _tablas_protegidas_por_las_migraciones() -> set[str]:
    """
    Union de las constantes `TABLAS_CON_RLS` de todas las migraciones.

    Se leen de la constante y no del texto SQL porque las migraciones
    generan las sentencias en un bucle: el literal
    `ALTER TABLE attachments ...` no llega a aparecer en el fichero.
    La constante es el contrato explicito entre migracion y test.
    """
    protegidas: set[str] = set()
    for fichero in _ficheros_de_migracion():
        especificacion = importlib.util.spec_from_file_location(
            f"_migracion_{fichero.stem}", fichero
        )
        assert especificacion is not None
        assert especificacion.loader is not None
        modulo = importlib.util.module_from_spec(especificacion)
        especificacion.loader.exec_module(modulo)
        protegidas.update(getattr(modulo, "TABLAS_CON_RLS", ()))
    return protegidas


def _tablas_de_negocio() -> set[str]:
    _importar_todos_los_modelos()
    return {
        nombre
        for nombre, tabla in Base.metadata.tables.items()
        if "tenant_id" in tabla.columns and nombre not in TABLAS_GLOBALES
    }


# ─────────────────────────────────────────────────────────────────────
# Salvaguardas del propio test
# ─────────────────────────────────────────────────────────────────────


def test_la_metadata_no_esta_vacia() -> None:
    """Si los imports fallaran, el resto del fichero pasaria en falso."""
    _importar_todos_los_modelos()
    assert len(Base.metadata.tables) >= 9


def test_se_detectan_tablas_de_negocio() -> None:
    assert len(_tablas_de_negocio()) >= 7


# ─────────────────────────────────────────────────────────────────────
# Cobertura
# ─────────────────────────────────────────────────────────────────────


def test_toda_tabla_de_negocio_lleva_tenant_id() -> None:
    _importar_todos_los_modelos()
    sin_tenant = {
        nombre for nombre, tabla in Base.metadata.tables.items() if "tenant_id" not in tabla.columns
    }
    assert sin_tenant <= TABLAS_GLOBALES, (
        "Tablas sin tenant_id que no estan declaradas como globales: "
        f"{sorted(sin_tenant - TABLAS_GLOBALES)}"
    )


def test_toda_tabla_de_negocio_esta_declarada_con_rls() -> None:
    """
    El olvido que este fichero existe para impedir: una tabla nueva
    con `tenant_id` que nadie añadio a la lista de la migracion. No
    produce ningun error y abre un agujero en un esquema que por lo
    demas esta bien protegido.
    """
    sin_proteger = sorted(_tablas_de_negocio() - _tablas_protegidas_por_las_migraciones())
    assert not sin_proteger, (
        f"Tablas con tenant_id que ninguna migracion protege con RLS: {sin_proteger}"
    )


def test_las_migraciones_no_declaran_tablas_inexistentes() -> None:
    """Al reves: una tabla en la lista que ya nadie usa es ruido que confunde."""
    _importar_todos_los_modelos()
    declaradas = _tablas_protegidas_por_las_migraciones()
    existentes = set(Base.metadata.tables)
    assert declaradas <= existentes, (
        f"Tablas declaradas con RLS que no existen: {sorted(declaradas - existentes)}"
    )


# ─────────────────────────────────────────────────────────────────────
# Forma de las sentencias
# ─────────────────────────────────────────────────────────────────────


def test_cada_enable_lleva_su_force() -> None:
    """
    Sin FORCE, PostgreSQL exime al propietario de sus propias
    politicas: RLS apareceria activo y no filtraria nada. Un ENABLE
    suelto sin su FORCE es exactamente ese fallo silencioso.
    """
    texto = _texto_de_las_migraciones()
    # Solo las sentencias reales: la frase tambien aparece en los
    # comentarios que explican por que hace falta FORCE, y contarlos
    # haria que el test midiera la documentacion en vez del SQL.
    enables = len(re.findall(r"ALTER TABLE \S+ ENABLE ROW LEVEL SECURITY", texto))
    forces = len(re.findall(r"ALTER TABLE \S+ FORCE ROW LEVEL SECURITY", texto))
    assert enables > 0
    assert enables == forces, f"{enables} ENABLE frente a {forces} FORCE"


def test_las_migraciones_crean_politicas() -> None:
    texto = _texto_de_las_migraciones()
    assert re.search(r"CREATE POLICY\s+\w+\s+ON\s+\S+", texto)


def test_las_politicas_comparan_contra_la_variable_de_sesion() -> None:
    """
    Una politica que no lea `app.current_tenant` no filtra por el
    tenant de la transaccion, por bien escrita que este.
    """
    texto = _texto_de_las_migraciones()
    politicas = re.findall(
        r"CREATE POLICY\s+\w+\s+ON\s+(\S+)(.*?)(?:\"\"\"|\n\s*\)\n)", texto, re.S
    )
    assert politicas, "No se encontro ninguna politica"
    for tabla, cuerpo in politicas:
        assert "app.current_tenant" in cuerpo, (
            f"La politica de {tabla} no compara contra app.current_tenant"
        )


def test_las_politicas_de_escritura_llevan_with_check() -> None:
    """
    Sin WITH CHECK se puede INSERTAR una fila con el tenant_id de
    otro: el aislamiento protegeria la lectura y no la escritura.
    """
    texto = _texto_de_las_migraciones()
    assert texto.count("WITH CHECK") >= 2


def test_la_bitacora_de_auditoria_no_admite_update_ni_delete() -> None:
    """
    Una auditoria que el propio sistema puede reescribir no sirve como
    evidencia. Sus politicas cubren solo SELECT e INSERT, asi que
    PostgreSQL rechaza lo demas por ausencia de politica permisiva.
    """
    texto = _texto_de_las_migraciones()
    bloques = re.findall(
        r"CREATE POLICY\s+\w+\s+ON\s+audit_log(.*?)(?:\"\"\"|\n\s*\)\n)", texto, re.S
    )
    assert bloques, "audit_log no tiene politicas"

    unido = " ".join(bloques).upper()
    assert "FOR SELECT" in unido
    assert "FOR INSERT" in unido
    assert "FOR UPDATE" not in unido
    assert "FOR DELETE" not in unido
    assert "FOR ALL" not in unido
