"""
Metricas de Prometheus.

Proposito
    Exponer las series que un panel y una alerta necesitan para decidir si
    el sistema esta sano: trafico y latencia del borde HTTP, profundidad y
    antiguedad de la cola, duracion de cada etapa del pipeline, resultado
    por estrategia de extraccion y rechazos de los proveedores de correo.

Dependencias
    `prometheus_client`. Ya estaba declarada en el proyecto.

Decisiones de diseño
    1. **Ninguna etiqueta con `tenant_id`.** El plan de arquitectura pedia
       "coste de IA por tenant" como etiqueta, y es una mala idea por dos
       razones: cada tenant nuevo crea una serie temporal por cada metrica
       y combinacion de etiquetas, de modo que la cardinalidad crece sin
       techo y Prometheus se degrada; y un identificador de cliente en un
       endpoint de metricas, que suele estar menos protegido que la API,
       filtra cuantos clientes hay y cuanto usa cada uno. El consumo por
       tenant se consulta en la base de datos, que es donde ya esta y
       donde si tiene control de acceso.

    2. **La ruta se etiqueta con el patron, no con la URL.** Usar la URL
       real crearia una serie por identificador: `/scans/<uuid>` genera
       una serie distinta por escaneo. Se usa el `route.path` de FastAPI,
       que es `/api/v1/scans/{trabajo_id}`.

    3. **Los histogramas llevan buckets explicitos.** Los de la libreria
       llegan hasta 10 s, y aqui hay dos escalas muy distintas: una
       peticion HTTP se mide en milisegundos y una etapa de OCR en
       decenas de segundos. Compartir buckets dejaria uno de los dos
       percentiles sin resolucion util.
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from prometheus_client.openmetrics.exposition import CONTENT_TYPE_LATEST

# Registro propio en lugar del global: el global recoge tambien las
# metricas del proceso y del recolector de basura que la libreria instala
# por su cuenta, y mezclarlas con las del dominio hace mas dificil saber
# que expone realmente este servicio.
REGISTRO = CollectorRegistry()

_BUCKETS_HTTP = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
_BUCKETS_ETAPA = (0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0)

# ── Borde HTTP ───────────────────────────────────────────────────────

peticiones_http = Counter(
    "mailauto_peticiones_http_total",
    "Peticiones HTTP atendidas.",
    labelnames=("metodo", "ruta", "estado"),
    registry=REGISTRO,
)

duracion_http = Histogram(
    "mailauto_peticion_http_segundos",
    "Duracion de las peticiones HTTP.",
    labelnames=("metodo", "ruta"),
    buckets=_BUCKETS_HTTP,
    registry=REGISTRO,
)

rechazos_por_limite = Counter(
    "mailauto_rechazos_por_limite_total",
    "Peticiones rechazadas por limite de volumen, por tipo de control.",
    # `cortafuegos` es el limite por minuto del middleware; `cuota` es la
    # cuota de negocio por tenant. Distinguirlos importa: lo primero suele
    # ser un cliente mal programado, lo segundo un cliente que necesita
    # mas plan.
    labelnames=("control",),
    registry=REGISTRO,
)

# ── Cola de trabajos ─────────────────────────────────────────────────

profundidad_de_cola = Gauge(
    "mailauto_cola_profundidad",
    "Trabajos pendientes en la cola.",
    labelnames=("cola",),
    registry=REGISTRO,
)

antiguedad_de_cola = Gauge(
    "mailauto_cola_antiguedad_segundos",
    "Antiguedad del trabajo mas viejo sin empezar.",
    labelnames=("cola",),
    registry=REGISTRO,
)

# ── Pipeline ─────────────────────────────────────────────────────────

duracion_de_etapa = Histogram(
    "mailauto_etapa_segundos",
    "Duracion de cada etapa del pipeline de ingesta y extraccion.",
    labelnames=("etapa",),
    buckets=_BUCKETS_ETAPA,
    registry=REGISTRO,
)

extracciones = Counter(
    "mailauto_extracciones_total",
    "Intentos de extraccion por estrategia y resultado.",
    labelnames=("estrategia", "resultado"),
    registry=REGISTRO,
)

llamadas_a_ia = Counter(
    "mailauto_llamadas_a_ia_total",
    "Llamadas al modelo de vision, por resultado. Sin etiqueta de tenant a proposito.",
    labelnames=("resultado",),
    registry=REGISTRO,
)

# ── Proveedores externos ─────────────────────────────────────────────

respuestas_de_proveedor = Counter(
    "mailauto_respuestas_de_proveedor_total",
    "Respuestas de los proveedores de correo, por clase de estado.",
    labelnames=("proveedor", "clase"),
    registry=REGISTRO,
)


def exponer() -> tuple[bytes, str]:
    """Devuelve el cuerpo y el tipo de contenido para el endpoint `/metrics`."""
    return generate_latest(REGISTRO), CONTENT_TYPE_LATEST


def clase_de_estado(estado: int) -> str:
    """
    Agrupa el codigo HTTP en su clase (`2xx`, `4xx`...).

    Se agrupa porque la alerta pregunta "¿esta fallando el proveedor?", no
    "¿cuantos 418 hubo?", y una serie por codigo exacto multiplica las
    series sin responder mejor a esa pregunta.
    """
    return f"{estado // 100}xx"
