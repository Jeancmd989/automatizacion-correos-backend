"""
Tests de los objetos de valor del dominio tributario.

Son el filtro que impide que un dato invalido exista en el sistema, y
el que convierte un error de OCR en un campo vacio en vez de en una
cifra equivocada que nadie detectara. Merecen el test mas exhaustivo
del proyecto.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mailauto.modules.extraction.domain.value_objects import (
    FechaDePago,
    Importe,
    NumeroDeOperacion,
    PeriodoTributario,
    Ruc,
)

# RUC reales y publicos de entidades peruanas. Son la referencia contra
# la que se valida el algoritmo del digito verificador: inventarlos
# haria que el test confirmara la implementacion en lugar de la regla.
RUCS_REALES = (
    "20131312955",  # SUNAT
    "20100047218",  # Banco de Credito del Peru
    "20100070970",  # Backus
)


# ─────────────────────────────────────────────────────────────────────
# RUC
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("valor", RUCS_REALES)
def test_acepta_rucs_reales(valor: str) -> None:
    assert Ruc(valor).valor == valor


@pytest.mark.parametrize("valor", RUCS_REALES)
def test_el_digito_verificador_detecta_una_cifra_cambiada(valor: str) -> None:
    """
    El motivo de ser del modulo 11: el OCR confunde 0/O, 1/l y 5/S, y
    sin esta comprobacion esos errores entran en el reporte como RUC
    aparentemente validos.
    """
    alterado = valor[:5] + str((int(valor[5]) + 1) % 10) + valor[6:]
    assert alterado != valor
    assert not Ruc.es_valido(alterado)


@pytest.mark.parametrize(
    "valor",
    [
        "2013131295",  # diez digitos
        "201313129550",  # doce
        "2013131295A",  # con letra
        "",
        "99131312955",  # prefijo inexistente
        "00131312955",
    ],
)
def test_rechaza_rucs_malformados(valor: str) -> None:
    assert not Ruc.es_valido(valor)
    with pytest.raises(ValueError, match="RUC invalido"):
        Ruc(valor)


@pytest.mark.parametrize(
    "crudo",
    [
        "RUC: 20131312955",
        "  20131312955  ",
        "20-131312955",
        "RUC del Arrendador 20131312955 Nombre",
        "2 0 1 3 1 3 1 2 9 5 5",
    ],
)
def test_extrae_el_ruc_de_un_texto_sucio(crudo: str) -> None:
    """El OCR pega la etiqueta al valor o parte los digitos con espacios."""
    resultado = Ruc.interpretar(crudo)
    assert resultado is not None
    assert resultado.valor == "20131312955"


def test_interpretar_devuelve_none_si_no_hay_ruc_valido() -> None:
    assert Ruc.interpretar("sin numeros aqui") is None
    assert Ruc.interpretar("12345678901") is None  # digito verificador malo
    assert Ruc.interpretar(None) is None


def test_distingue_persona_natural_de_empresa() -> None:
    assert not Ruc("20131312955").es_persona_natural
    assert Ruc.es_valido("20131312955")


def test_el_ruc_es_inmutable() -> None:
    ruc = Ruc("20131312955")
    with pytest.raises((AttributeError, TypeError)):
        ruc.valor = "20100047218"  # type: ignore[misc]


@given(st.text(min_size=0, max_size=60))
def test_interpretar_nunca_lanza_con_entrada_arbitraria(crudo: str) -> None:
    """
    Lo que llega aqui es texto de OCR: cualquier cosa. Una excepcion no
    controlada tumbaria el job de extraccion entero.
    """
    resultado = Ruc.interpretar(crudo)
    assert resultado is None or Ruc.es_valido(resultado.valor)


# ─────────────────────────────────────────────────────────────────────
# Periodo tributario
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("crudo", "esperado"),
    [
        ("202603", "202603"),
        ("03/2026", "202603"),
        ("2026-03", "202603"),
        ("03-2026", "202603"),
        ("marzo 2026", "202603"),
        ("Marzo de 2026", "202603"),
        ("SETIEMBRE 2026", "202609"),
        ("septiembre 2026", "202609"),
        ("032026", "202603"),  # separador perdido por el OCR
        ("122025", "202512"),
    ],
)
def test_normaliza_todas_las_formas_del_periodo(crudo: str, esperado: str) -> None:
    """
    El mismo periodo llega escrito de seis maneras. Sin normalizar,
    agrupar por periodo en el reporte produce seis filas donde deberia
    haber una.
    """
    periodo = PeriodoTributario.interpretar(crudo)
    assert periodo is not None
    assert str(periodo) == esperado


def test_el_periodo_legible_usa_el_formato_local() -> None:
    assert PeriodoTributario(2026, 3).legible == "03/2026"


@pytest.mark.parametrize(("anio", "mes"), [(2026, 0), (2026, 13), (1800, 6), (3000, 6)])
def test_rechaza_periodos_imposibles(anio: int, mes: int) -> None:
    with pytest.raises(ValueError, match="fuera de rango"):
        PeriodoTributario(anio, mes)


def test_periodo_sin_coincidencia_devuelve_none() -> None:
    assert PeriodoTributario.interpretar("no hay periodo") is None
    assert PeriodoTributario.interpretar(None) is None


# ─────────────────────────────────────────────────────────────────────
# Importe
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("crudo", "esperado"),
    [
        ("1234.56", "1234.56"),
        ("1,234.56", "1234.56"),  # formato anglosajon
        ("1.234,56", "1234.56"),  # formato europeo
        ("S/ 1,850.00", "1850.00"),
        ("S/. 980.50", "980.50"),
        ("1 850,00", "1850.00"),
        ("500", "500.00"),
    ],
)
def test_interpreta_ambas_convenciones_numericas(crudo: str, esperado: str) -> None:
    """
    "1.234" es ambiguo. Se resuelve por el ultimo separador, que es el
    decimal en las dos convenciones cuando hay dos.
    """
    importe = Importe.interpretar(crudo)
    assert importe is not None
    assert str(importe) == esperado


@pytest.mark.parametrize(
    ("crudo", "moneda"),
    [("S/ 100", "PEN"), ("USD 100", "USD"), ("$ 100", "USD"), ("100", "PEN")],
)
def test_detecta_la_moneda(crudo: str, moneda: str) -> None:
    importe = Importe.interpretar(crudo)
    assert importe is not None
    assert importe.moneda == moneda


def test_usa_decimal_y_no_coma_flotante() -> None:
    """
    Un reporte tributario cuadra al centimo. Con float, 0.1 + 0.2 no
    es 0.3 y el total no cuadra.
    """
    importe = Importe.interpretar("0.10")
    assert importe is not None
    assert isinstance(importe.cantidad, Decimal)
    assert importe.cantidad + Decimal("0.20") == Decimal("0.30")


def test_rechaza_importes_negativos() -> None:
    with pytest.raises(ValueError, match="negativo"):
        Importe(Decimal("-1.00"))


def test_rechaza_importes_desmesurados() -> None:
    with pytest.raises(ValueError, match="maximo"):
        Importe(Decimal("9999999999.00"))


def test_importe_sin_numero_devuelve_none() -> None:
    assert Importe.interpretar("sin cifras") is None
    assert Importe.interpretar(None) is None


# ─────────────────────────────────────────────────────────────────────
# Fecha de pago
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("crudo", "esperado"),
    [
        ("05/10/2026", date(2026, 10, 5)),
        ("5-10-2026", date(2026, 10, 5)),
        ("05.10.2026", date(2026, 10, 5)),
        ("05/10/26", date(2026, 10, 5)),
        ("2026-10-05", date(2026, 10, 5)),
    ],
)
def test_interpreta_la_fecha_en_formato_peruano(crudo: str, esperado: date) -> None:
    fecha = FechaDePago.interpretar(crudo)
    assert fecha is not None
    assert fecha.valor == esperado


def test_el_dia_va_antes_que_el_mes() -> None:
    """
    En Peru el formato es DD/MM. Interpretar 05/10 como 10 de mayo
    cambiaria el periodo al que se imputa el pago.
    """
    fecha = FechaDePago.interpretar("05/10/2026")
    assert fecha is not None
    assert fecha.valor.month == 10
    assert fecha.valor.day == 5


@pytest.mark.parametrize("crudo", ["31/02/2026", "32/01/2026", "15/13/2026"])
def test_descarta_fechas_imposibles(crudo: str) -> None:
    """El OCR las produce al confundir digitos; inventar una seria peor."""
    assert FechaDePago.interpretar(crudo) is None


def test_la_fecha_legible_usa_el_formato_local() -> None:
    fecha = FechaDePago(date(2026, 10, 5))
    assert fecha.legible == "05/10/2026"
    assert str(fecha) == "2026-10-05"


@given(st.text(min_size=0, max_size=40))
def test_la_fecha_nunca_lanza_con_entrada_arbitraria(crudo: str) -> None:
    resultado = FechaDePago.interpretar(crudo)
    assert resultado is None or isinstance(resultado.valor, date)


# ─────────────────────────────────────────────────────────────────────
# Numero de operacion
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("crudo", "esperado"),
    [
        ("0012345678", "0012345678"),
        ("OP-2026-0001", "OP-2026-0001"),
        ("  0012345678  ", "0012345678"),
        ("N. 0012345678", "N0012345678"),
    ],
)
def test_limpia_el_numero_de_operacion(crudo: str, esperado: str) -> None:
    numero = NumeroDeOperacion.interpretar(crudo)
    assert numero is not None
    assert numero.valor == esperado


@pytest.mark.parametrize("crudo", ["abc", "", "x" * 50])
def test_rechaza_numeros_de_operacion_de_longitud_invalida(crudo: str) -> None:
    assert NumeroDeOperacion.interpretar(crudo) is None


def test_el_numero_de_operacion_rechaza_caracteres_extraños() -> None:
    with pytest.raises(ValueError, match="caracteres invalidos"):
        NumeroDeOperacion("abc$%&/")
