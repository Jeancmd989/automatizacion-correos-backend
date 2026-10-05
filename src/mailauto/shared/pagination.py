"""
Paginacion por cursor.

Proposito
    Garantizar que ninguna lista del sistema pueda devolverse completa y
    que el recorrido de paginas no se descoloque cuando se insertan filas
    mientras el usuario navega.

Dependencias
    Solo biblioteca estandar y pydantic.

Decision de diseño
    Cursor opaco en lugar de OFFSET. Con OFFSET, la pagina 500 obliga a
    PostgreSQL a leer y descartar 500*N filas, y una insercion concurrente
    desplaza los resultados y duplica o saltea registros. El cursor codifica
    la posicion exacta (created_at, id) y la consulta siguiente es siempre
    un rango indexado de costo constante.

    Se codifica en base64url y se trata como opaco de cara al cliente: su
    formato interno puede cambiar sin romper integraciones.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field

from mailauto.shared.errors import ErrorDeValidacion
from mailauto.shared.types import asegurar_utc

T = TypeVar("T")

LIMITE_POR_DEFECTO = 50
LIMITE_MAXIMO = 200


@dataclass(frozen=True, slots=True)
class Cursor:
    """Posicion exacta en un listado ordenado por (created_at DESC, id DESC)."""

    creado_en: datetime
    identificador: UUID

    def codificar(self) -> str:
        carga = json.dumps(
            {"c": self.creado_en.isoformat(), "i": str(self.identificador)},
            separators=(",", ":"),
        )
        return base64.urlsafe_b64encode(carga.encode()).decode().rstrip("=")

    @classmethod
    def decodificar(cls, crudo: str) -> Cursor:
        try:
            relleno = "=" * (-len(crudo) % 4)
            datos = json.loads(base64.urlsafe_b64decode(crudo + relleno))
            return cls(
                creado_en=asegurar_utc(datetime.fromisoformat(datos["c"])),
                identificador=UUID(datos["i"]),
            )
        except (binascii.Error, ValueError, KeyError, TypeError) as exc:
            # No se detalla el motivo: un cursor es opaco, y explicar su
            # estructura solo le sirve a quien intenta manipularlo.
            raise ErrorDeValidacion("Cursor invalido.", campo="cursor") from exc


class SolicitudDePagina(BaseModel):
    """Parametros de paginacion recibidos en el query string."""

    cursor: str | None = None
    limite: Annotated[int, Field(ge=1, le=LIMITE_MAXIMO)] = LIMITE_POR_DEFECTO

    def cursor_decodificado(self) -> Cursor | None:
        return Cursor.decodificar(self.cursor) if self.cursor else None


class Pagina(BaseModel, Generic[T]):
    """Resultado paginado. `siguiente_cursor` es None cuando no hay mas datos."""

    elementos: list[T]
    siguiente_cursor: str | None = None
    hay_mas: bool = False

    @classmethod
    def construir(
        cls,
        filas: list[T],
        *,
        limite: int,
        extraer_cursor: object,
    ) -> Pagina[T]:
        """
        Construye la pagina a partir de `limite + 1` filas.

        Pedir una fila de mas es como se sabe si hay siguiente pagina sin
        ejecutar un COUNT(*), que en tablas grandes es un recorrido completo.
        """
        hay_mas = len(filas) > limite
        visibles = filas[:limite]
        siguiente = None
        if hay_mas and visibles:
            cursor = extraer_cursor(visibles[-1])  # type: ignore[operator]
            siguiente = cursor.codificar()
        return cls(elementos=visibles, siguiente_cursor=siguiente, hay_mas=hay_mas)
