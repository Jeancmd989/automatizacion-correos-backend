"""
Logging estructurado con redaccion de secretos.

Proposito
    Producir logs JSON correlacionables y hacer que sea tecnicamente
    dificil que un token, una contraseña o un dato personal termine en
    ellos.

Flujo
    evento -> procesadores (contexto, trazas, REDACCION) -> JSON -> stdout

Dependencias
    structlog, OpenTelemetry (solo para leer el trace_id activo).

Decision de diseño
    La redaccion es un procesador obligatorio del pipeline, no una
    responsabilidad de quien escribe el log. Confiar en que nadie loguee
    un token funciona hasta el primer `log.debug("payload", data=payload)`
    puesto a las 2 de la madrugada para depurar algo. Aqui, aunque ese
    log llegue a produccion, el valor sale enmascarado.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from typing import Any, Final

import structlog
from opentelemetry import trace

# Claves cuyo valor nunca debe aparecer en un log, en cualquier nivel de
# anidamiento. La comparacion es por subcadena en minusculas, para que
# `user_access_token` o `X-Refresh-Token` caigan igual que `token`.
CLAVES_SENSIBLES: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "authorization",
        "api_key",
        "apikey",
        "client_secret",
        "master_key",
        "encryption_key",
        "dek",
        "kek",
        "cookie",
        "set-cookie",
        "session",
        "code_verifier",
        "private_key",
        "ssn",
        "ruc",  # identificador fiscal: dato personal en este dominio
        "email",
        "correo",
        "remitente",
        "asunto",
        "ocr_text",
        "raw_text",
    }
)

_MASCARA: Final = "***"
_PROFUNDIDAD_MAXIMA: Final = 6  # corta estructuras ciclicas o absurdamente anidadas


def _es_sensible(clave: str) -> bool:
    clave_normalizada = clave.lower().replace("-", "_")
    return any(sensible in clave_normalizada for sensible in CLAVES_SENSIBLES)


def _redactar(valor: Any, profundidad: int = 0) -> Any:  # noqa: ANN401 - recorre cualquier estructura de evento
    if profundidad >= _PROFUNDIDAD_MAXIMA:
        return _MASCARA
    if isinstance(valor, dict):
        return {
            clave: (_MASCARA if _es_sensible(str(clave)) else _redactar(sub, profundidad + 1))
            for clave, sub in valor.items()
        }
    if isinstance(valor, list | tuple):
        return [_redactar(item, profundidad + 1) for item in valor]
    return valor


def procesador_de_redaccion(
    _logger: Any,  # noqa: ANN401 - firma impuesta por structlog
    _nombre: str,
    evento: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Enmascara todo valor cuya clave parezca sensible, a cualquier profundidad."""
    redactado: dict[str, Any] = _redactar(dict(evento))
    return redactado


def procesador_de_traza(
    _logger: Any,  # noqa: ANN401 - firma impuesta por structlog
    _nombre: str,
    evento: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """
    Adjunta el trace_id activo.

    Es lo que permite saltar de una linea de log a la traza completa del
    escaneo que la produjo, atravesando API, cola y worker.
    """
    span = trace.get_current_span()
    contexto = span.get_span_context()
    if contexto.is_valid:
        evento["trace_id"] = format(contexto.trace_id, "032x")
        evento["span_id"] = format(contexto.span_id, "016x")
    return evento


def configurar_logging(*, nivel: str = "INFO", formato_json: bool = True) -> None:
    """
    Configura structlog sobre el logging estandar.

    Todo pasa por `logging`, no por una salida propia: asi los eventos de
    la aplicacion y los de las librerias de terceros (uvicorn, SQLAlchemy,
    httpx) atraviesan los MISMOS procesadores, incluido el de redaccion.
    Si structlog escribiera por su cuenta, una libreria que registre una
    URL con un token en la query lo volcaria en claro, porque nunca
    habria pasado por el filtro.

    En desarrollo la salida es legible y con color; en produccion, una
    linea JSON por evento, que es lo que esperan los agregadores.
    """
    # Cadena comun a los eventos propios y a los ajenos. El orden importa:
    # la redaccion va siempre al final, cuando el evento ya esta completo.
    procesadores_comunes: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        procesador_de_traza,
        procesador_de_redaccion,
    ]

    renderizador: Any = (
        structlog.processors.JSONRenderer()
        if formato_json
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    structlog.configure(
        processors=[
            *procesadores_comunes,
            # Entrega el evento al formateador de stdlib en lugar de
            # renderizarlo aqui, que es lo que permite unificar ambos
            # origenes en un unico formato de salida.
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formateador = structlog.stdlib.ProcessorFormatter(
        # `foreign_pre_chain` es lo que aplica la misma cadena a los
        # registros que NO vienen de structlog.
        foreign_pre_chain=procesadores_comunes,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.dict_tracebacks
            if formato_json
            else structlog.processors.format_exc_info,
            renderizador,
        ],
    )

    manejador = logging.StreamHandler(stream=sys.stdout)
    manejador.setFormatter(formateador)

    raiz = logging.getLogger()
    # Se reemplazan los manejadores en lugar de añadir: configurar dos
    # veces (la app y luego un worker en el mismo proceso) duplicaria
    # cada linea de log.
    raiz.handlers = [manejador]
    raiz.setLevel(nivel.upper())

    # Estas librerias emiten una linea por peticion o por sentencia. A
    # nivel INFO ahogan los eventos propios y disparan el coste del
    # agregador sin aportar nada que las trazas no digan mejor.
    for ruidoso in ("uvicorn.access", "sqlalchemy.engine", "httpx", "httpcore"):
        logging.getLogger(ruidoso).setLevel(logging.WARNING)


def obtener_logger(nombre: str) -> structlog.stdlib.BoundLogger:
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(nombre)
    return logger
