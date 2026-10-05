"""
Motores de lectura para PDF: texto nativo y tablas.

Proposito
    Sacar el texto de un PDF sin recurrir a OCR cuando el documento ya
    lo lleva dentro, que es la inmensa mayoria de los generados por
    SUNAT.

Dependencias
    PyMuPDF (rapido, texto plano) y pdfplumber (lento, entiende tablas).

Decisiones de diseño
    1. PyMuPDF primero: lee un PDF tipico en unos diez milisegundos y
       sin coste. Antes de plantearse OCR o IA hay que agotar lo que el
       fichero ya contiene.

    2. Limites de paginas y de tiempo en ambos motores. El validador de
       ingesta ya descarta los casos obvios, pero un PDF puede ser
       legitimo y aun asi tardar minutos en renderizar; sin tope, un
       solo documento retiene una ranura del worker indefinidamente.

    3. Ninguno lanza excepciones hacia arriba. Un PDF corrupto devuelve
       un resultado con `error` y el pipeline prueba el siguiente
       motor, en lugar de abortar el escaneo entero.
"""

from __future__ import annotations

import asyncio
import io
import time
from typing import Final

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
from mailauto.shared.observability.logging import obtener_logger

logger = obtener_logger(__name__)

# Las constancias tienen una o dos paginas. Diez es margen de sobra y
# acota el coste de un documento inesperadamente largo.
_MAXIMO_PAGINAS: Final = 10
_TIMEOUT_SEGUNDOS: Final = 20.0
_TIMEOUT_TABLAS_SEGUNDOS: Final = 40.0
# Por debajo de esto el "texto nativo" es ruido: el PDF es en realidad
# un escaneo con cuatro caracteres de metadatos sueltos.
_MINIMO_CARACTERES_UTILES: Final = 80


class TextoNativoDePdf(EstrategiaDeExtraccion):
    """Extrae la capa de texto que el PDF ya lleva incorporada."""

    @property
    def nombre(self) -> Estrategia:
        return Estrategia.TEXTO_NATIVO

    @property
    def costo_relativo(self) -> int:
        return 10

    def admite(self, documento: DocumentoAExtraer) -> bool:
        return documento.es_pdf

    async def leer(
        self, documento: DocumentoAExtraer, perfil: PerfilDeExtraccion
    ) -> ResultadoDeEstrategia:
        inicio = time.perf_counter()
        try:
            texto = await asyncio.wait_for(
                asyncio.to_thread(self._extraer_texto, documento.contenido),
                timeout=_TIMEOUT_SEGUNDOS,
            )
        except TimeoutError:
            return self._fallo("timeout", inicio)
        except Exception as exc:  # noqa: BLE001 - frontera del motor
            logger.warning("pdf_texto_nativo_fallo", error=type(exc).__name__)
            return self._fallo(type(exc).__name__, inicio)

        duracion = self._ms(inicio)

        if len(texto.strip()) < _MINIMO_CARACTERES_UTILES:
            # PDF escaneado: no hay capa de texto aprovechable. No es un
            # error, es la señal de que toca pasar al OCR.
            return ResultadoDeEstrategia(
                estrategia=self.nombre,
                texto_crudo=texto,
                duracion_ms=duracion,
                error="sin_capa_de_texto",
            )

        campos = perfil.extraer_campos(texto) if perfil.reconoce(texto) else {}
        return ResultadoDeEstrategia(
            estrategia=self.nombre,
            campos=con_estrategia(campos, self.nombre),
            texto_crudo=texto,
            duracion_ms=duracion,
        )

    @staticmethod
    def _extraer_texto(contenido: bytes) -> str:
        import pymupdf

        partes: list[str] = []
        with pymupdf.open(stream=contenido, filetype="pdf") as documento:
            for indice, pagina in enumerate(documento):
                if indice >= _MAXIMO_PAGINAS:
                    break
                partes.append(pagina.get_text("text"))
        return "\n".join(partes)

    def _fallo(self, motivo: str, inicio: float) -> ResultadoDeEstrategia:
        return ResultadoDeEstrategia(
            estrategia=self.nombre, duracion_ms=self._ms(inicio), error=motivo
        )

    @staticmethod
    def _ms(inicio: float) -> int:
        return int((time.perf_counter() - inicio) * 1000)


class TablasDePdf(EstrategiaDeExtraccion):
    """
    Lee las tablas del PDF y las aplana a texto.

    Existe porque PyMuPDF devuelve el contenido de una tabla en el
    orden en que esta dibujado en el fichero, que no siempre es el
    orden de lectura: una etiqueta puede acabar separada de su valor
    por media pagina y el patron deja de encontrarlos juntos.
    pdfplumber reconstruye filas y columnas, y eso los vuelve a unir.
    """

    @property
    def nombre(self) -> Estrategia:
        return Estrategia.TABLAS_PDF

    @property
    def costo_relativo(self) -> int:
        return 20

    def admite(self, documento: DocumentoAExtraer) -> bool:
        return documento.es_pdf

    async def leer(
        self, documento: DocumentoAExtraer, perfil: PerfilDeExtraccion
    ) -> ResultadoDeEstrategia:
        inicio = time.perf_counter()
        try:
            texto = await asyncio.wait_for(
                asyncio.to_thread(self._extraer_tablas, documento.contenido),
                timeout=_TIMEOUT_TABLAS_SEGUNDOS,
            )
        except TimeoutError:
            return ResultadoDeEstrategia(
                estrategia=self.nombre, duracion_ms=_ms(inicio), error="timeout"
            )
        except Exception as exc:  # noqa: BLE001 - frontera del motor
            logger.warning("pdf_tablas_fallo", error=type(exc).__name__)
            return ResultadoDeEstrategia(
                estrategia=self.nombre,
                duracion_ms=_ms(inicio),
                error=type(exc).__name__,
            )

        if not texto.strip():
            return ResultadoDeEstrategia(
                estrategia=self.nombre, duracion_ms=_ms(inicio), error="sin_tablas"
            )

        return ResultadoDeEstrategia(
            estrategia=self.nombre,
            campos=con_estrategia(perfil.extraer_campos(texto), self.nombre),
            texto_crudo=texto,
            duracion_ms=_ms(inicio),
        )

    @staticmethod
    def _extraer_tablas(contenido: bytes) -> str:
        import pdfplumber

        filas: list[str] = []
        with pdfplumber.open(io.BytesIO(contenido)) as documento:
            for indice, pagina in enumerate(documento.pages):
                if indice >= _MAXIMO_PAGINAS:
                    break
                for tabla in pagina.extract_tables() or []:
                    for fila in tabla:
                        celdas = [str(c).strip() for c in fila if c]
                        if celdas:
                            # Se unen con ": " para que las etiquetas y
                            # sus valores queden adyacentes, que es como
                            # los patrones del perfil esperan verlos.
                            filas.append(": ".join(celdas))
        return "\n".join(filas)


def _ms(inicio: float) -> int:
    return int((time.perf_counter() - inicio) * 1000)


def con_estrategia(
    campos: dict[str, CampoExtraido], estrategia: Estrategia
) -> dict[str, CampoExtraido]:
    """
    Marca cada campo con el motor que lo produjo.

    El perfil no sabe quien lo invoco y pone un valor por defecto.
    Corregirlo aqui es lo que permite despues saber que motor acerto
    con cada campo y, con esos datos, afinar el orden del pipeline en
    lugar de suponerlo.
    """
    return {
        nombre: CampoExtraido(campo.valor, campo.confianza, estrategia)
        for nombre, campo in campos.items()
    }
