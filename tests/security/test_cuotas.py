"""
Tests de las cuotas por tenant.

Proposito
    Fijar la separacion entre los dos controles de volumen, que se
    confundieron una vez con consecuencias:

      · El middleware de rate limit es un cortafuegos contra avalanchas.
        Corre antes de autenticar y solo puede contar por direccion IP.
      · Las cuotas de negocio pertenecen al tenant y se aplican despues
        de resolver la identidad.

Por que hace falta este fichero
    Mientras la cuota horaria de escaneos la aplicaba el middleware, se
    contaba por IP y antes de autenticar: veintiuna peticiones ANONIMAS
    agotaban la cuota de todos los que compartieran salida a internet, y
    dejaban una oficina sin poder lanzar escaneos durante una hora. No
    hacia falta ninguna credencial. Lo detecto una prueba de carga, no un
    test, porque ningun test miraba el efecto cruzado entre trafico
    anonimo y cuota de tenant.

    Estos tests lo fijan en las dos direcciones: que el trafico sin
    credenciales no consuma cuota de nadie, y que la cuota si corte al
    tenant que la agota.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from mailauto.bootstrap.app import crear_app
from mailauto.shared.cuotas import ControlDeCuotas, CuotasEnRedis
from mailauto.shared.errors import TokenInvalido
from tests.conftest import ajustes_de_pruebas

pytestmark = pytest.mark.security

TENANT_A = UUID("00000000-0000-7000-8000-0000000000a0")
TENANT_B = UUID("00000000-0000-7000-8000-0000000000b0")


class RedisFalso:
    """Doble minimo de Redis con pipeline de INCR y EXPIRE."""

    def __init__(self) -> None:
        self.contadores: dict[str, int] = {}
        self.expiraciones: dict[str, int] = {}

    def pipeline(self) -> RedisFalso._Pipeline:
        return RedisFalso._Pipeline(self)

    class _Pipeline:
        def __init__(self, padre: RedisFalso) -> None:
            self._padre = padre
            self._ordenes: list[tuple[str, str, int]] = []

        def incr(self, clave: str) -> None:
            self._ordenes.append(("incr", clave, 0))

        def expire(self, clave: str, segundos: int) -> None:
            self._ordenes.append(("expire", clave, segundos))

        async def execute(self) -> list[int]:
            resultados: list[int] = []
            for orden, clave, valor in self._ordenes:
                if orden == "incr":
                    self._padre.contadores[clave] = self._padre.contadores.get(clave, 0) + 1
                    resultados.append(self._padre.contadores[clave])
                else:
                    self._padre.expiraciones[clave] = valor
                    resultados.append(1)
            return resultados


class RedisCaido:
    def pipeline(self) -> RedisCaido:
        return self

    def incr(self, clave: str) -> None:
        pass

    def expire(self, clave: str, segundos: int) -> None:
        pass

    async def execute(self) -> list[int]:
        raise ConnectionError("Redis no responde")


async def _consumir(control: ControlDeCuotas, tenant_id: UUID, veces: int) -> list[bool]:
    return [
        await control.consumir(
            recurso="escaneos", tenant_id=tenant_id, maximo=3, ventana_segundos=3600
        )
        for _ in range(veces)
    ]


async def test_permite_hasta_el_maximo_y_corta_despues() -> None:
    control = CuotasEnRedis(RedisFalso())  # type: ignore[arg-type]

    resultados = await _consumir(control, TENANT_A, 5)

    assert resultados == [True, True, True, False, False]


async def test_la_cuota_de_un_tenant_no_afecta_a_otro() -> None:
    """
    Es la propiedad que el control por IP no podia dar: dos clientes
    detras de la misma salida a internet comparten direccion, pero no
    deben compartir cuota.
    """
    control = CuotasEnRedis(RedisFalso())  # type: ignore[arg-type]

    assert await _consumir(control, TENANT_A, 4) == [True, True, True, False]
    # El tenant B parte de cero aunque A ya la haya agotado.
    assert await _consumir(control, TENANT_B, 3) == [True, True, True]


async def test_recursos_distintos_llevan_contadores_distintos() -> None:
    """Vincular un buzon no debe gastar cuota de escaneos."""
    redis = RedisFalso()
    control = CuotasEnRedis(redis)  # type: ignore[arg-type]

    for _ in range(3):
        await control.consumir(
            recurso="escaneos", tenant_id=TENANT_A, maximo=3, ventana_segundos=3600
        )
    permitido = await control.consumir(
        recurso="vinculaciones", tenant_id=TENANT_A, maximo=3, ventana_segundos=3600
    )

    assert permitido is True
    assert len(redis.contadores) == 2


async def test_cada_contador_lleva_caducidad() -> None:
    """
    Sin TTL los contadores se acumularian para siempre: una clave por
    tenant, recurso y ventana, y nadie las borra.
    """
    redis = RedisFalso()
    control = CuotasEnRedis(redis)  # type: ignore[arg-type]

    await control.consumir(recurso="escaneos", tenant_id=TENANT_A, maximo=3, ventana_segundos=3600)

    assert list(redis.expiraciones.values()) == [3600]


async def test_la_clave_incluye_el_tenant_y_el_recurso() -> None:
    """
    La forma de la clave es contrato con el operador: es lo que permite
    inspeccionar o purgar una cuota concreta desde Redis sin adivinar.
    """
    redis = RedisFalso()
    control = CuotasEnRedis(redis)  # type: ignore[arg-type]

    await control.consumir(recurso="escaneos", tenant_id=TENANT_A, maximo=3, ventana_segundos=3600)

    clave = next(iter(redis.contadores))
    assert clave.startswith("cuota:escaneos:")
    assert str(TENANT_A) in clave


async def test_si_redis_cae_la_cuota_deja_pasar() -> None:
    """
    Decision consciente, la misma que toma el middleware: convertir una
    caida del contador en una caida del servicio seria peor que admitir
    trafico sin contar durante unos minutos. Queda registrado como error
    para que se alerte.
    """
    control = CuotasEnRedis(RedisCaido())  # type: ignore[arg-type]

    assert await _consumir(control, uuid4(), 10) == [True] * 10


# ─────────────────────────────────────────────────────────────────────
# Borde HTTP: el trafico anonimo no gasta cuota
# ─────────────────────────────────────────────────────────────────────


class _CuotasEspia(ControlDeCuotas):
    """Registra cada consumo para poder afirmar que no hubo ninguno."""

    def __init__(self) -> None:
        self.consumos: list[tuple[str, UUID]] = []

    async def consumir(
        self,
        *,
        recurso: str,
        tenant_id: UUID,
        maximo: int,
        ventana_segundos: int,
    ) -> bool:
        self.consumos.append((recurso, tenant_id))
        return True


class _VerificadorQueRechaza:
    async def verificar(self, token: str) -> None:
        raise TokenInvalido()


def test_una_peticion_sin_credenciales_no_consume_cuota_de_nadie() -> None:
    """
    El fallo que esta separacion corrige.

    Con la cuota en el middleware, cada POST anonimo a `/scans` incrementaba
    el contador de la IP de origen. Veintiuna peticiones sin credenciales
    dejaban sin escaneos durante una hora a todos los que compartieran esa
    salida a internet. Ahora la cuota vive detras de la autenticacion, asi
    que el trafico anonimo muere en el 401 sin tocar ningun contador.
    """
    espia = _CuotasEspia()
    app = crear_app(ajustes_de_pruebas())
    app.state.contenedor = SimpleNamespace(
        verificador=_VerificadorQueRechaza(), redis=None, cuotas=espia
    )
    cliente = TestClient(app, raise_server_exceptions=False)

    for _ in range(30):
        respuesta = cliente.post(
            "/api/v1/scans",
            json={"conexion_id": str(uuid4()), "limite_de_mensajes": 10},
        )
        assert respuesta.status_code == 401

    assert espia.consumos == [], f"El trafico anonimo consumio cuota: {espia.consumos}"


def test_las_rutas_de_vinculacion_tampoco_gastan_cuota_sin_credenciales() -> None:
    espia = _CuotasEspia()
    app = crear_app(ajustes_de_pruebas())
    app.state.contenedor = SimpleNamespace(
        verificador=_VerificadorQueRechaza(), redis=None, cuotas=espia
    )
    cliente = TestClient(app, raise_server_exceptions=False)

    for ruta, cuerpo in (
        ("/api/v1/mailboxes/authorize", {"proveedor": "google", "redirect_uri": "http://x/y"}),
        ("/api/v1/mailboxes/callback", {"codigo": "c", "state": "s"}),
    ):
        respuesta = cliente.post(ruta, json=cuerpo)
        assert respuesta.status_code == 401

    assert espia.consumos == []


def test_el_limitador_de_avalanchas_no_aplica_cuotas_horarias() -> None:
    """
    El middleware debe tener un solo limite, por minuto. Si volviera a
    llevar limites por prefijo con ventanas de una hora, reaparecia el
    agujero: una ventana larga contada por IP y antes de autenticar es
    exactamente lo que permitia el bloqueo.
    """
    from mailauto.api.middleware.seguridad import MiddlewareDeRateLimit

    assert MiddlewareDeRateLimit._VENTANA_SEGUNDOS == 60
    assert not hasattr(MiddlewareDeRateLimit, "_resolver_limite")
