"""
Preprocesamiento de imagen antes del OCR.

Proposito
    Subir la tasa de acierto de Tesseract sobre fotos y escaneos de
    mala calidad, que es la entrada habitual: alguien fotografia la
    constancia con el movil, torcida y con sombra.

Dependencias
    OpenCV (variante headless) y numpy.

Decision de diseño
    El orden de los pasos no es intercambiable y cada uno prepara al
    siguiente:

      escala de grises -> quita el color, que al OCR no le dice nada
      CLAHE            -> iguala la iluminacion por zonas, no global:
                          corrige la sombra de media pagina que un
                          ajuste global solo desplazaria
      denoise          -> quita el grano del sensor, que la
                          binarizacion convertiria en puntos negros
      deskew           -> endereza; Tesseract pierde precision muy
                          rapido a partir de dos o tres grados
      binarizacion     -> blanco y negro adaptativo, por bloques, para
                          que un lado oscuro no se trague el texto
      escalado         -> Tesseract rinde mejor con texto de unos 30
                          pixeles de alto

    Hacerlo al reves (binarizar antes de igualar la iluminacion) pierde
    informacion que ya no se recupera.
"""

from __future__ import annotations

from typing import Any, Final

import numpy as np

# Por debajo de esta altura el texto es demasiado pequeño para
# Tesseract y conviene ampliar antes de binarizar.
_ALTURA_OBJETIVO: Final = 1800
# Ampliar mas alla de esto no mejora el reconocimiento y dispara el
# tiempo de proceso y la memoria.
_ALTURA_MAXIMA: Final = 3500
_ANGULO_MAXIMO_CORRECCION: Final = 15.0
# Por debajo de medio grado la correccion no aporta y añade un
# remuestreo que si degrada.
_ANGULO_MINIMO_CORRECCION: Final = 0.5


def preparar_para_ocr(contenido: bytes) -> Any:  # noqa: ANN401 - ndarray de OpenCV
    """
    Devuelve la imagen lista para Tesseract.

    Si algun paso falla se sigue con lo que haya: una imagen peor
    preparada todavia puede leerse, y abortar garantizaria no leer nada.
    """
    import cv2

    bufer = np.frombuffer(contenido, dtype=np.uint8)
    imagen = cv2.imdecode(bufer, cv2.IMREAD_COLOR)
    if imagen is None:
        raise ValueError("No fue posible decodificar la imagen")

    gris = cv2.cvtColor(imagen, cv2.COLOR_BGR2GRAY)
    gris = _igualar_iluminacion(gris)
    gris = _quitar_ruido(gris)
    gris = _enderezar(gris)
    gris = _escalar(gris)
    return _binarizar(gris)


def _igualar_iluminacion(gris: Any) -> Any:  # noqa: ANN401
    """
    CLAHE: ecualizacion adaptativa por bloques.

    La ecualizacion global de histograma arruina una foto con sombra en
    la mitad: sube el contraste donde ya habia y aplasta la zona
    oscura. CLAHE trabaja por regiones, asi que recupera la parte
    sombreada sin quemar el resto.
    """
    import cv2

    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    resultado: Any = clahe.apply(gris)
    return resultado


def _quitar_ruido(gris: Any) -> Any:  # noqa: ANN401
    """
    Filtro bilateral: suaviza el grano conservando los bordes.

    Un desenfoque gaussiano quitaria el ruido igual de bien pero
    tambien emborronaria los trazos de las letras, que es justo lo que
    el OCR necesita nitido.
    """
    import cv2

    resultado: Any = cv2.bilateralFilter(gris, d=5, sigmaColor=50, sigmaSpace=50)
    return resultado


def _enderezar(gris: Any) -> Any:  # noqa: ANN401
    """
    Corrige la inclinacion estimandola a partir del rectangulo minimo
    que envuelve al texto.
    """
    import cv2

    try:
        # Se invierte porque `minAreaRect` trabaja sobre pixeles no
        # nulos y el texto es oscuro sobre fondo claro.
        invertida = cv2.bitwise_not(gris)
        _, umbral = cv2.threshold(invertida, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        coordenadas = cv2.findNonZero(umbral)
        if coordenadas is None:
            # Los stubs de OpenCV declaran un retorno no opcional, pero
            # `findNonZero` devuelve None cuando la imagen esta
            # completamente en negro. Ocurre con un escaneo fallido, y
            # sin esta guarda `minAreaRect` revienta.
            return gris

        angulo = cv2.minAreaRect(coordenadas)[-1]
        # OpenCV devuelve el angulo en [-90, 0); se lleva al rango
        # pequeño alrededor de cero que es el que interesa corregir.
        if angulo < -45:
            angulo += 90

        if abs(angulo) < _ANGULO_MINIMO_CORRECCION or abs(angulo) > _ANGULO_MAXIMO_CORRECCION:
            # Una inclinacion mayor de 15 grados no es un escaneo
            # torcido: es una pagina en otra orientacion, y rotarla
            # como si fuera un desvio pequeño la dejaria peor.
            return gris

        alto, ancho = gris.shape[:2]
        matriz = cv2.getRotationMatrix2D((ancho / 2, alto / 2), angulo, 1.0)
        resultado: Any = cv2.warpAffine(
            gris,
            matriz,
            (ancho, alto),
            flags=cv2.INTER_CUBIC,
            borderMode=cv2.BORDER_REPLICATE,
        )
        return resultado
    except cv2.error:
        return gris


def _escalar(gris: Any) -> Any:  # noqa: ANN401
    """Lleva la imagen a una altura en la que Tesseract rinde bien."""
    import cv2

    alto, ancho = gris.shape[:2]
    if alto >= _ALTURA_OBJETIVO:
        if alto <= _ALTURA_MAXIMA:
            return gris
        factor = _ALTURA_MAXIMA / alto
    else:
        factor = _ALTURA_OBJETIVO / alto

    resultado: Any = cv2.resize(
        gris,
        (int(ancho * factor), int(alto * factor)),
        # CUBIC al ampliar (inventa pixeles suaves), AREA al reducir
        # (promedia, que es lo que evita el aliasing del texto).
        interpolation=cv2.INTER_CUBIC if factor > 1 else cv2.INTER_AREA,
    )
    return resultado


def _binarizar(gris: Any) -> Any:  # noqa: ANN401
    """
    Umbral adaptativo gaussiano.

    Un umbral global (Otsu) funciona con un escaneo uniforme y falla
    con una foto, donde un borde oscuro se vuelve negro entero. El
    adaptativo decide bloque a bloque.
    """
    import cv2

    resultado: Any = cv2.adaptiveThreshold(
        gris,
        maxValue=255,
        adaptiveMethod=cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        thresholdType=cv2.THRESH_BINARY,
        blockSize=31,
        C=11,
    )
    return resultado
