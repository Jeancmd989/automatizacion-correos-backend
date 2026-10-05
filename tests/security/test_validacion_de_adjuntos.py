"""
Tests de la validacion de adjuntos.

Los adjuntos son la entrada no confiable mas peligrosa del sistema: los
produce un tercero cualquiera y acaban en manos de parsers nativos. Estos
tests recorren los vectores conocidos.
"""

from __future__ import annotations

import pytest

from mailauto.modules.ingestion.infrastructure.validador import (
    ValidadorDeAdjuntosPorContenido,
)
from tests.conftest import jpeg_valido, pdf_valido, png_valido

pytestmark = pytest.mark.security

TIPOS = ["application/pdf", "image/jpeg", "image/png", "image/webp"]


@pytest.fixture
def validador() -> ValidadorDeAdjuntosPorContenido:
    return ValidadorDeAdjuntosPorContenido(tipos_permitidos=TIPOS, tamano_maximo=1_000_000)


# ── Casos legitimos ──────────────────────────────────────────────────


def test_acepta_pdf(validador: ValidadorDeAdjuntosPorContenido) -> None:
    resultado = validador.validar(pdf_valido(), nombre="constancia.pdf")
    assert resultado.aceptado
    assert resultado.tipo_mime_real == "application/pdf"
    assert len(resultado.sha256) == 64


def test_acepta_png_y_jpeg(validador: ValidadorDeAdjuntosPorContenido) -> None:
    assert validador.validar(png_valido(), nombre="foto.png").aceptado
    assert validador.validar(jpeg_valido(), nombre="foto.jpg").aceptado
    assert validador.validar(jpeg_valido(), nombre="foto.jpeg").aceptado


def test_el_hash_identifica_el_contenido(
    validador: ValidadorDeAdjuntosPorContenido,
) -> None:
    """La deduplicacion depende de que el mismo contenido de el mismo hash."""
    uno = validador.validar(pdf_valido(), nombre="a.pdf")
    otro = validador.validar(pdf_valido(), nombre="nombre-distinto.pdf")
    assert uno.sha256 == otro.sha256


# ── Tipo real frente a tipo declarado ────────────────────────────────


def test_rechaza_ejecutable_disfrazado_de_pdf(
    validador: ValidadorDeAdjuntosPorContenido,
) -> None:
    """Un PE de Windows renombrado a .pdf. La extension no decide nada."""
    ejecutable = b"MZ\x90\x00" + b"\x00" * 300
    resultado = validador.validar(ejecutable, nombre="factura.pdf")
    assert not resultado.aceptado
    assert resultado.motivo_de_rechazo == "tipo_no_reconocido"


def test_rechaza_script_disfrazado_de_imagen(
    validador: ValidadorDeAdjuntosPorContenido,
) -> None:
    script = b"#!/bin/sh\nrm -rf /\n" + b"\x00" * 300
    assert not validador.validar(script, nombre="recibo.png").aceptado


def test_rechaza_png_con_extension_pdf(
    validador: ValidadorDeAdjuntosPorContenido,
) -> None:
    """Contenido valido pero incoherente con el nombre: anomalia que se corta."""
    resultado = validador.validar(png_valido(), nombre="documento.pdf")
    assert not resultado.aceptado
    assert resultado.motivo_de_rechazo == "extension_no_coincide_con_contenido"


def test_rechaza_zip_aunque_la_extension_sea_valida(
    validador: ValidadorDeAdjuntosPorContenido,
) -> None:
    zip_bytes = b"PK\x03\x04" + b"\x00" * 300
    assert not validador.validar(zip_bytes, nombre="archivo.pdf").aceptado


def test_rechaza_riff_que_no_es_webp(
    validador: ValidadorDeAdjuntosPorContenido,
) -> None:
    """RIFF tambien es AVI y WAV: hace falta el marcador WEBP del offset 8."""
    avi = b"RIFF" + b"\x00" * 4 + b"AVI " + b"\x00" * 300
    assert not validador.validar(avi, nombre="imagen.webp").aceptado


# ── Nombres hostiles ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "nombre",
    [
        "../../etc/passwd.pdf",
        "..\\..\\windows\\system32\\config.pdf",
        "/etc/shadow.pdf",
        "archivo\x00oculto.pdf",
        "a" * 300 + ".pdf",
        "",
    ],
)
def test_rechaza_nombres_hostiles(validador: ValidadorDeAdjuntosPorContenido, nombre: str) -> None:
    """
    El nombre nunca determina la ruta de almacenamiento (se usa un UUID),
    pero si se muestra en la UI y en los reportes, asi que se filtra igual.
    """
    resultado = validador.validar(pdf_valido(), nombre=nombre)
    assert not resultado.aceptado
    assert resultado.motivo_de_rechazo == "nombre_invalido"


# ── Tamaño ───────────────────────────────────────────────────────────


def test_rechaza_archivo_demasiado_grande() -> None:
    validador = ValidadorDeAdjuntosPorContenido(tipos_permitidos=TIPOS, tamano_maximo=1024)
    resultado = validador.validar(pdf_valido() + b"\x00" * 5000, nombre="grande.pdf")
    assert not resultado.aceptado
    assert resultado.motivo_de_rechazo == "tamano_excedido"


def test_rechaza_archivo_vacio_o_truncado(
    validador: ValidadorDeAdjuntosPorContenido,
) -> None:
    assert not validador.validar(b"%PDF-", nombre="truncado.pdf").aceptado


# ── PDFs hostiles ────────────────────────────────────────────────────


def test_rechaza_pdf_con_javascript(
    validador: ValidadorDeAdjuntosPorContenido,
) -> None:
    """Vector de ejecucion en lectores de PDF. El pipeline solo necesita texto."""
    malicioso = b"%PDF-1.7\n/JavaScript (app.alert('x'))\n" + b"\x00" * 200
    resultado = validador.validar(malicioso, nombre="malicioso.pdf")
    assert not resultado.aceptado
    assert resultado.motivo_de_rechazo == "pdf_con_contenido_activo"


def test_rechaza_pdf_con_launch(validador: ValidadorDeAdjuntosPorContenido) -> None:
    malicioso = b"%PDF-1.7\n/Launch /F (cmd.exe)\n" + b"\x00" * 200
    assert not validador.validar(malicioso, nombre="x.pdf").aceptado


def test_rechaza_pdf_con_archivo_embebido(
    validador: ValidadorDeAdjuntosPorContenido,
) -> None:
    malicioso = b"%PDF-1.7\n/EmbeddedFile\n" + b"\x00" * 200
    assert not validador.validar(malicioso, nombre="x.pdf").aceptado


def test_el_nodo_del_arbol_de_paginas_no_cuenta_como_pagina() -> None:
    """
    "/Type/Pages" es el nodo raiz del arbol, no una pagina. Contarlo
    daria un motivo de rechazo equivocado y haria perder tiempo al
    diagnosticar un fichero legitimo.
    """
    validador = ValidadorDeAdjuntosPorContenido(tipos_permitidos=TIPOS, tamano_maximo=50_000_000)
    normal = b"%PDF-1.7\n<</Type/Pages/Count 2>>\n" + pdf_valido(paginas=2)
    assert validador.validar(normal + b"\x20" * 4000, nombre="normal.pdf").aceptado


def test_rechaza_pdf_con_demasiadas_paginas() -> None:
    validador = ValidadorDeAdjuntosPorContenido(tipos_permitidos=TIPOS, tamano_maximo=50_000_000)
    # Muchas paginas pero con relleno suficiente para no disparar primero
    # la heuristica de ratio de objetos.
    bomba = pdf_valido(paginas=600) + b"\x20" * 2_000_000
    resultado = validador.validar(bomba, nombre="bomba.pdf")
    assert not resultado.aceptado
    assert resultado.motivo_de_rechazo == "pdf_demasiadas_paginas"


def test_rechaza_pdf_sospechoso_de_bomba() -> None:
    """Muchisima estructura en muy poco fichero: patron de bomba de descompresion."""
    validador = ValidadorDeAdjuntosPorContenido(tipos_permitidos=TIPOS, tamano_maximo=50_000_000)
    # Objetos neutros (ni paginas ni contenido activo) para aislar la
    # heuristica de ratio. Cada objeto ocupa 20 bytes: unos 51 objetos
    # por KB, muy por encima del umbral. Un PDF legitimo no se acerca,
    # porque sus objetos llevan fuentes, flujos e imagenes dentro.
    bomba = b"%PDF-1.7\n" + (b"1 0 obj\n<<>>\nendobj\n" * 3000)
    resultado = validador.validar(bomba, nombre="bomba.pdf")
    assert not resultado.aceptado
    assert resultado.motivo_de_rechazo == "pdf_sospechoso_de_bomba"


# ── Allowlist ────────────────────────────────────────────────────────


def test_respeta_la_allowlist_de_tipos() -> None:
    """Si un tipo sale de la lista, deja de aceptarse aunque sea valido."""
    validador = ValidadorDeAdjuntosPorContenido(
        tipos_permitidos=["application/pdf"], tamano_maximo=1_000_000
    )
    assert validador.validar(pdf_valido(), nombre="a.pdf").aceptado
    resultado = validador.validar(png_valido(), nombre="a.png")
    assert not resultado.aceptado
    assert resultado.motivo_de_rechazo == "tipo_no_permitido"
