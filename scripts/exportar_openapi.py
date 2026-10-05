"""
Exporta el esquema OpenAPI a un fichero versionado.

Proposito
    Al estar el frontend en otro repositorio, el cliente TypeScript no
    puede generarse en el mismo commit que cambia la API. Este fichero
    versionado es el contrato compartido: el CI del backend comprueba que
    esta al dia, y el del frontend regenera su cliente a partir de el.
    Si alguien renombra un campo sin regenerar, el PR falla aqui en lugar
    de romperse en produccion.

Uso
    python scripts/exportar_openapi.py [ruta]      # por defecto openapi.json

Nota
    Se exporta con `docs_enabled=True` forzado, porque en produccion el
    esquema no se publica. Lo que se versiona es el contrato, no la
    configuracion del entorno.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from mailauto.bootstrap.app import crear_app
from mailauto.bootstrap.settings import Settings, get_settings


def main() -> int:
    destino = Path(sys.argv[1] if len(sys.argv) > 1 else "openapi.json")

    ajustes: Settings = get_settings().model_copy(update={"docs_enabled": True})
    esquema = crear_app(ajustes).openapi()

    # `sort_keys` y una indentacion fija hacen el fichero estable entre
    # ejecuciones: sin eso, el diff cambiaria en cada regeneracion y la
    # comprobacion del CI seria ruido permanente.
    destino.write_text(
        json.dumps(esquema, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Esquema OpenAPI escrito en {destino}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
