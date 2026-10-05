"""
Tests de la maquina de estados del trabajo de escaneo.

El sistema de referencia guardaba el estado en un singleton en memoria y
lo cambiaba por asignacion directa. Aqui las transiciones son metodos que
validan el origen, y estos tests fijan ese contrato.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from mailauto.modules.ingestion.domain.entities import (
    ContadoresDeEscaneo,
    EstadoDeTrabajo,
    FaseDeEscaneo,
    ParametrosDeEscaneo,
    TrabajoDeEscaneo,
)
from mailauto.shared.errors import ConflictoDeEstado, ErrorDeValidacion

# ── Transiciones validas ─────────────────────────────────────────────


def test_el_ciclo_normal_termina_completado() -> None:
    trabajo = TrabajoDeEscaneo()
    assert trabajo.estado is EstadoDeTrabajo.EN_COLA

    trabajo.marcar_en_ejecucion()
    assert trabajo.estado is EstadoDeTrabajo.EN_EJECUCION
    assert trabajo.iniciado_en is not None
    assert trabajo.intento == 1

    trabajo.completar()
    assert trabajo.estado is EstadoDeTrabajo.COMPLETADO
    assert trabajo.progreso_porcentaje == 100
    assert trabajo.finalizado_en is not None


def test_con_errores_termina_como_parcial() -> None:
    """Un error aislado no invalida el escaneo: lo marca, que es informacion util."""
    trabajo = TrabajoDeEscaneo()
    trabajo.marcar_en_ejecucion()
    trabajo.contadores.errores = 3
    trabajo.completar()
    assert trabajo.estado is EstadoDeTrabajo.COMPLETADO_CON_ERRORES


def test_el_intento_se_incrementa_en_cada_reejecucion() -> None:
    trabajo = TrabajoDeEscaneo()
    trabajo.marcar_en_ejecucion()
    trabajo.fallar(codigo="error_de_proveedor", mensaje="fallo")
    trabajo.estado = EstadoDeTrabajo.EN_COLA  # lo que hace el reintento de la cola
    trabajo.marcar_en_ejecucion()
    assert trabajo.intento == 2


# ── Transiciones invalidas ───────────────────────────────────────────


def test_no_se_puede_iniciar_dos_veces() -> None:
    trabajo = TrabajoDeEscaneo()
    trabajo.marcar_en_ejecucion()
    with pytest.raises(ConflictoDeEstado):
        trabajo.marcar_en_ejecucion()


def test_no_se_puede_completar_sin_haber_empezado() -> None:
    with pytest.raises(ConflictoDeEstado):
        TrabajoDeEscaneo().completar()


def test_no_se_puede_cancelar_un_trabajo_terminado() -> None:
    """
    Sin esta validacion, una reentrega tardia de la cola podria "cancelar"
    un escaneo ya completado y falsear la auditoria.
    """
    trabajo = TrabajoDeEscaneo()
    trabajo.marcar_en_ejecucion()
    trabajo.completar()
    with pytest.raises(ConflictoDeEstado):
        trabajo.cancelar()


def test_no_se_puede_fallar_un_trabajo_terminado() -> None:
    trabajo = TrabajoDeEscaneo()
    trabajo.marcar_en_ejecucion()
    trabajo.cancelar()
    with pytest.raises(ConflictoDeEstado):
        trabajo.fallar(codigo="x", mensaje="y")


def test_se_puede_cancelar_antes_de_empezar() -> None:
    """Cancelar algo que aun esta en cola es el caso mas comun."""
    trabajo = TrabajoDeEscaneo()
    trabajo.cancelar()
    assert trabajo.estado is EstadoDeTrabajo.CANCELADO


# ── Progreso ─────────────────────────────────────────────────────────


def test_el_progreso_nunca_retrocede() -> None:
    """Una barra que baja destruye la confianza en todo el indicador."""
    trabajo = TrabajoDeEscaneo()
    trabajo.avanzar(FaseDeEscaneo.DESCARGANDO_ADJUNTOS, 60)
    trabajo.avanzar(FaseDeEscaneo.DESCARGANDO_ADJUNTOS, 20)
    assert trabajo.progreso_porcentaje == 60


@pytest.mark.parametrize(("entrada", "esperado"), [(-10, 0), (150, 100), (50, 50)])
def test_el_progreso_se_acota_entre_0_y_100(entrada: int, esperado: int) -> None:
    trabajo = TrabajoDeEscaneo()
    trabajo.avanzar(FaseDeEscaneo.LISTANDO_CORREOS, entrada)
    assert trabajo.progreso_porcentaje == esperado


# ── Parametros ───────────────────────────────────────────────────────


def test_acepta_parametros_razonables() -> None:
    ParametrosDeEscaneo(
        desde=date(2026, 1, 1), hasta=date(2026, 3, 31), limite_de_mensajes=500
    ).validar(maximo_mensajes=5000, maximo_dias=366)


def test_rechaza_rango_invertido() -> None:
    parametros = ParametrosDeEscaneo(desde=date(2026, 6, 1), hasta=date(2026, 1, 1))
    with pytest.raises(ErrorDeValidacion, match="posterior"):
        parametros.validar(maximo_mensajes=5000, maximo_dias=366)


def test_rechaza_rango_demasiado_amplio() -> None:
    """
    Un escaneo sin acotar sobre un buzon de diez años agota la cuota del
    proveedor y bloquea a los demas tenants que comparten el worker.
    """
    inicio = date(2020, 1, 1)
    parametros = ParametrosDeEscaneo(desde=inicio, hasta=inicio + timedelta(days=2000))
    with pytest.raises(ErrorDeValidacion, match="dias"):
        parametros.validar(maximo_mensajes=5000, maximo_dias=366)


@pytest.mark.parametrize("limite", [0, -1, 999_999])
def test_rechaza_limites_fuera_de_rango(limite: int) -> None:
    parametros = ParametrosDeEscaneo(limite_de_mensajes=limite)
    with pytest.raises(ErrorDeValidacion):
        parametros.validar(maximo_mensajes=5000, maximo_dias=366)


# ── Contadores ───────────────────────────────────────────────────────


def test_los_contadores_sobreviven_a_la_serializacion() -> None:
    """Van y vuelven de una columna JSONB en cada actualizacion del trabajo."""
    original = ContadoresDeEscaneo(mensajes_revisados=10, adjuntos_descargados=4, errores=1)
    recuperado = ContadoresDeEscaneo.desde_dict(original.como_dict())
    assert recuperado == original


def test_contadores_desde_none_arranca_en_cero() -> None:
    assert ContadoresDeEscaneo.desde_dict(None) == ContadoresDeEscaneo()
