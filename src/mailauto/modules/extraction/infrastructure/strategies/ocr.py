"""
Motor de lectura por OCR local (Tesseract).

Proposito
    Leer documentos sin capa de texto: fotos, escaneos y PDFs que son
    solo imagenes. Es el ultimo motor gratuito antes de recurrir a la
    IA de vision, que si cuesta dinero.

Dependencias
    pytesseract, PyMuPDF (para rasterizar PDFs) y el preprocesamiento
    propio.

Decisiones de diseño
    1. La confianza NO se inventa: Tesseract la informa palabra por
       palabra y de ahi sale la del campo. Poner una constante seria
       mentir al sistema de revision, que es justo quien necesita ese
       dato para decidir a quien molestar.

    2. Un PDF sin texto se rasteriza a 300 DPI. Menos pierde los
       digitos pequeños; mas multiplica el tiempo y la memoria sin
       mejorar el reconocimiento.

    3. Idiomas `spa+eng`: los documentos son en español pero las
       etiquetas tecnicas y los codigos suelen venir en ingles, y
       Tesseract con un solo idioma fuerza las palabras al diccionario
       equivocado.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Final

from mailauto.modules.extraction.domain.entities import (
    CampoExtraido,
    Estrategia,
    ResultadoDeEstrategia,
)
from mailauto.modules.extraction.domain.ports import (
    DocumentoAExtraer,
    EstrategiaDeExtraccion,
    PerfilDeExtraccion,
)
from mailauto.modules.extraction.infrastructure.preprocessing.imagen import (
    preparar_para_ocr,
)
from mailauto.shared.observability.logging import obtener_logger

logger = obtener_logger(__name__)

_IDIOMAS: Final = "spa+eng"
# PSM 6: "un bloque uniforme de texto". Es el modo adecuado para un
# formulario; el automatico (3) intenta detectar columnas y en una
# constancia con etiquetas a la izquierda y valores a la derecha acaba
# mezclando el orden de lectura.
_CONFIGURACION: Final = "--oem 3 --psm 6"
_TIMEOUT_SEGUNDOS: Final = 90.0
_DPI_RASTERIZADO: Final = 300
_MAXIMO_PAGINAS: Final = 5
# Tesseract marca con -1 las palabras que no reconocio; incluirlas en
# la media hundiria la confianza de un documento por lo demas legible.
_CONFIANZA_NO_DISPONIBLE: Final = -1


class OcrLocal(EstrategiaDeExtraccion):
    """Tesseract sobre la imagen preprocesada."""

    @property
    def nombre(self) -> Estrategia:
        return Estrategia.OCR_LOCAL

    @property
    def costo_relativo(self) -> int:
        return 50

    def admite(self, documento: DocumentoAExtraer) -> bool:
        return documento.es_pdf or documento.es_imagen

    async def leer(
        self, documento: DocumentoAExtraer, perfil: PerfilDeExtraccion
    ) -> ResultadoDeEstrategia:
        inicio = time.perf_counter()
        try:
            texto, confianza = await asyncio.wait_for(
                asyncio.to_thread(self._reconocer, documento),
                timeout=_TIMEOUT_SEGUNDOS,
            )
        except TimeoutError:
            return ResultadoDeEstrategia(
                estrategia=self.nombre, duracion_ms=_ms(inicio), error="timeout"
            )
        except Exception as exc:  # noqa: BLE001 - frontera del motor
            logger.warning("ocr_fallo", error=type(exc).__name__)
            return ResultadoDeEstrategia(
                estrategia=self.nombre,
                duracion_ms=_ms(inicio),
                error=type(exc).__name__,
            )

        if not texto.strip():
            return ResultadoDeEstrategia(
                estrategia=self.nombre, duracion_ms=_ms(inicio), error="sin_texto"
            )

        campos = perfil.extraer_campos(texto)
        return ResultadoDeEstrategia(
            estrategia=self.nombre,
            campos=self._ajustar_confianza(campos, confianza),
            texto_crudo=texto,
            duracion_ms=_ms(inicio),
        )

    # ── Interno ──────────────────────────────────────────────────────

    def _reconocer(self, documento: DocumentoAExtraer) -> tuple[str, float]:
        imagenes = (
            self._rasterizar_pdf(documento.contenido) if documento.es_pdf else [documento.contenido]
        )

        textos: list[str] = []
        confianzas: list[float] = []
        for crudo in imagenes:
            texto, confianza = self._reconocer_una(crudo)
            if texto.strip():
                textos.append(texto)
                confianzas.append(confianza)

        media = sum(confianzas) / len(confianzas) if confianzas else 0.0
        return "\n".join(textos), media

    def _reconocer_una(self, contenido: bytes) -> tuple[str, float]:
        import pytesseract
        from PIL import Image

        preparada = preparar_para_ocr(contenido)
        imagen = Image.fromarray(preparada)

        datos: dict[str, Any] = pytesseract.image_to_data(
            imagen,
            lang=_IDIOMAS,
            config=_CONFIGURACION,
            output_type=pytesseract.Output.DICT,
        )

        palabras: list[str] = []
        confianzas: list[float] = []
        for texto, confianza in zip(datos["text"], datos["conf"], strict=True):
            if not str(texto).strip():
                continue
            palabras.append(str(texto))
            valor = float(confianza)
            if valor > _CONFIANZA_NO_DISPONIBLE:
                confianzas.append(valor / 100.0)

        media = sum(confianzas) / len(confianzas) if confianzas else 0.0
        return " ".join(palabras), media

    @staticmethod
    def _rasterizar_pdf(contenido: bytes) -> list[bytes]:
        import pymupdf

        paginas: list[bytes] = []
        with pymupdf.open(stream=contenido, filetype="pdf") as documento:
            for indice, pagina in enumerate(documento):
                if indice >= _MAXIMO_PAGINAS:
                    break
                mapa = pagina.get_pixmap(dpi=_DPI_RASTERIZADO)
                paginas.append(mapa.tobytes("png"))
        return paginas

    def _ajustar_confianza(
        self, campos: dict[str, CampoExtraido], confianza_del_ocr: float
    ) -> dict[str, CampoExtraido]:
        """
        Combina la confianza del patron con la que informa Tesseract.

        Se multiplican en lugar de promediarse: si el OCR leyo mal la
        pagina, da igual lo especifico que fuera el patron que
        coincidio. El producto refleja que ambas condiciones tienen que
        cumplirse para que el dato sea fiable.
        """
        return {
            nombre: CampoExtraido(
                valor=campo.valor,
                confianza=round(campo.confianza * confianza_del_ocr, 3),
                estrategia=self.nombre,
            )
            for nombre, campo in campos.items()
        }


def _ms(inicio: float) -> int:
    return int((time.perf_counter() - inicio) * 1000)
