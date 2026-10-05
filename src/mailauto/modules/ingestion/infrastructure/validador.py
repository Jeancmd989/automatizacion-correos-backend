"""
Validacion de seguridad de adjuntos.

Proposito
    Decidir si un fichero procedente de un correo ajeno puede entrar al
    sistema. Es el ultimo filtro antes de que ese contenido se almacene y,
    mas adelante, lo abran parsers nativos.

Flujo
    bytes -> tamaño -> magic bytes -> coherencia con la extension ->
    heuristicas por formato -> SHA-256 -> veredicto

Dependencias
    Solo biblioteca estandar. Deliberado: python-magic depende de libmagic
    nativa, y la validacion primaria no debe apoyarse en una biblioteca C
    que es, ella misma, superficie de ataque. Las firmas que necesitamos
    son cuatro y estan documentadas.

Decisiones de diseño
    1. Allowlist de tipos, nunca denylist. Enumerar lo prohibido siempre
       deja fuera algo; enumerar lo permitido falla del lado seguro.

    2. El tipo se determina por contenido, no por extension ni por el MIME
       que declara el proveedor. Ambos los controla quien envio el correo.

    3. Se exige coherencia entre extension y contenido real. Un .pdf que
       por dentro es un PNG no es necesariamente un ataque, pero si es una
       anomalia, y aceptarla significa que el pipeline procesara algo
       distinto de lo que el nombre promete.

    4. Limite de paginas y de ratio de objetos en PDF: defensa barata
       contra bombas de descompresion antes de que PyMuPDF las abra.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Final

from mailauto.modules.ingestion.domain.ports import (
    ResultadoDeValidacion,
    ValidadorDeAdjuntos,
)

# Firmas de los unicos cuatro formatos admitidos. Cada entrada define el
# patron de bytes iniciales y, si hace falta, una comprobacion adicional.
_FIRMAS: Final[tuple[tuple[bytes, str, tuple[str, ...]], ...]] = (
    (b"%PDF-", "application/pdf", (".pdf",)),
    (b"\xff\xd8\xff", "image/jpeg", (".jpg", ".jpeg")),
    (b"\x89PNG\r\n\x1a\n", "image/png", (".png",)),
    (b"RIFF", "image/webp", (".webp",)),  # se confirma con 'WEBP' en el offset 8
)

_MINIMO_BYTES: Final = 64
_MAXIMO_PAGINAS_PDF: Final = 500
_MAXIMO_OBJETOS_PDF: Final = 50_000
# Un PDF con mas de este ratio de objetos por KB es casi con seguridad una
# bomba de descompresion: muchisima estructura en muy poco fichero.
_RATIO_MAXIMO_OBJETOS_POR_KB: Final = 40

_PATRON_NOMBRE_SEGURO: Final = re.compile(r"^[\w\s.,()\[\]\-+#&@]{1,255}$", re.UNICODE)
# "/Type/Page" seguido de algo que no sea "s": excluye "/Type/Pages",
# que es el nodo raiz del arbol de paginas y no una pagina.
_PATRON_PAGINA_PDF: Final = re.compile(rb"/Type\s*/Page(?![s/\w])")


@dataclass(frozen=True, slots=True)
class _TipoDetectado:
    mime: str
    extensiones: tuple[str, ...]


class ValidadorDeAdjuntosPorContenido(ValidadorDeAdjuntos):
    def __init__(self, *, tipos_permitidos: list[str], tamano_maximo: int) -> None:
        self._permitidos = frozenset(tipos_permitidos)
        self._tamano_maximo = tamano_maximo

    def validar(self, contenido: bytes, *, nombre: str) -> ResultadoDeValidacion:
        sha256 = hashlib.sha256(contenido).hexdigest()

        rechazo = self._revisar_tamano(contenido) or self._revisar_nombre(nombre)
        if rechazo:
            return ResultadoDeValidacion(False, "", sha256, rechazo)

        detectado = self._detectar_tipo(contenido)
        if detectado is None:
            return ResultadoDeValidacion(False, "", sha256, "tipo_no_reconocido")

        if detectado.mime not in self._permitidos:
            return ResultadoDeValidacion(False, detectado.mime, sha256, "tipo_no_permitido")

        if not self._extension_coincide(nombre, detectado):
            return ResultadoDeValidacion(
                False, detectado.mime, sha256, "extension_no_coincide_con_contenido"
            )

        if detectado.mime == "application/pdf":
            anomalia = self._revisar_pdf(contenido)
            if anomalia:
                return ResultadoDeValidacion(False, detectado.mime, sha256, anomalia)

        return ResultadoDeValidacion(True, detectado.mime, sha256, None)

    # ── Comprobaciones ───────────────────────────────────────────────

    def _revisar_tamano(self, contenido: bytes) -> str | None:
        if len(contenido) < _MINIMO_BYTES:
            # Un fichero de pocos bytes no puede ser un documento valido;
            # suele ser un adjunto truncado o un marcador vacio.
            return "archivo_vacio_o_truncado"
        if len(contenido) > self._tamano_maximo:
            return "tamano_excedido"
        return None

    @staticmethod
    def _revisar_nombre(nombre: str) -> str | None:
        """
        El nombre nunca determina la ruta de almacenamiento, pero si se
        muestra en la UI y en los reportes. Se filtra para que no pueda
        llevar separadores de ruta ni caracteres de control.
        """
        if not nombre or len(nombre) > 255:
            return "nombre_invalido"
        if "\x00" in nombre or "/" in nombre or "\\" in nombre:
            return "nombre_invalido"
        if ".." in nombre:
            return "nombre_invalido"
        if not _PATRON_NOMBRE_SEGURO.match(nombre):
            return "nombre_invalido"
        return None

    @staticmethod
    def _detectar_tipo(contenido: bytes) -> _TipoDetectado | None:
        for firma, mime, extensiones in _FIRMAS:
            if not contenido.startswith(firma):
                continue
            # RIFF es un contenedor generico (tambien AVI y WAV); el
            # marcador 'WEBP' en el offset 8 es lo que lo confirma.
            if mime == "image/webp" and (len(contenido) < 12 or contenido[8:12] != b"WEBP"):
                continue
            return _TipoDetectado(mime=mime, extensiones=extensiones)
        return None

    @staticmethod
    def _extension_coincide(nombre: str, detectado: _TipoDetectado) -> bool:
        minusculas = nombre.lower()
        return any(minusculas.endswith(ext) for ext in detectado.extensiones)

    @staticmethod
    def _revisar_pdf(contenido: bytes) -> str | None:
        """
        Heuristicas baratas contra PDFs hostiles, antes de que ningun
        parser los abra.

        No pretende ser un analisis completo: el aislamiento del worker es
        la defensa real. Esto descarta los casos obvios sin coste.
        """
        objetos = contenido.count(b" obj")
        if objetos > _MAXIMO_OBJETOS_PDF:
            return "pdf_demasiados_objetos"

        kilobytes = max(1, len(contenido) // 1024)
        if objetos / kilobytes > _RATIO_MAXIMO_OBJETOS_POR_KB:
            return "pdf_sospechoso_de_bomba"

        paginas = len(_PATRON_PAGINA_PDF.findall(contenido))
        if paginas > _MAXIMO_PAGINAS_PDF:
            return "pdf_demasiadas_paginas"

        # /JavaScript, /Launch y /EmbeddedFile son vectores conocidos de
        # ejecucion en lectores de PDF. El pipeline solo necesita texto e
        # imagenes, asi que rechazarlos no pierde nada legitimo.
        for marcador in (b"/JavaScript", b"/JS ", b"/Launch", b"/EmbeddedFile"):
            if marcador in contenido:
                return "pdf_con_contenido_activo"

        return None
