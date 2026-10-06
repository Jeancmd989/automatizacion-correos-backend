"""
Tests de las metricas de Prometheus.

Proposito
    Proteger las dos propiedades que hacen que un sistema de metricas siga
    funcionando a los seis meses: cardinalidad acotada y endpoint cerrado.

Por que importa la cardinalidad
    Prometheus crea una serie temporal por cada combinacion de etiquetas.
    Etiquetar con la URL recibida en lugar de con el patron de ruta genera
    una serie por recurso: `/api/v1/scans/<uuid>` produce una serie nueva
    por cada escaneo que alguien consulte, y una ruta inexistente permite
    a cualquiera crear series a voluntad pidiendo URLs al azar. Es una via
    de agotamiento de memoria del sistema de monitorizacion, y no se nota
    el primer dia.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from mailauto.bootstrap.app import crear_app
from mailauto.shared.errors import TokenInvalido
from mailauto.shared.observability import metricas
from tests.conftest import ajustes_de_pruebas

TOKEN_DE_METRICAS = "token-de-pruebas-para-metricas"


class _VerificadorQueRechaza:
    async def verificar(self, token: str) -> None:
        raise TokenInvalido()


class _ColaFalsa:
    def __init__(self, profundidad: int = 7, antiguedad: float = 42.0) -> None:
        self._estado = (profundidad, antiguedad)

    async def estado(self) -> tuple[int, float]:
        return self._estado


class _ColaCaida:
    async def estado(self) -> tuple[int, float]:
        raise ConnectionError("Redis no responde")


def _cliente(*, token: str | None = TOKEN_DE_METRICAS, cola: object | None = None) -> TestClient:
    ajustes = ajustes_de_pruebas(metrics_token=token) if token else ajustes_de_pruebas()
    app = crear_app(ajustes)
    app.state.contenedor = SimpleNamespace(
        settings=ajustes,
        verificador=_VerificadorQueRechaza(),
        redis=None,
        cola=cola or _ColaFalsa(),
    )
    return TestClient(app, raise_server_exceptions=False)


def _cuerpo_de_metricas(cliente: TestClient) -> str:
    respuesta = cliente.get("/metrics", headers={"Authorization": f"Bearer {TOKEN_DE_METRICAS}"})
    assert respuesta.status_code == 200
    return respuesta.text


# ── Acceso al endpoint ───────────────────────────────────────────────


def test_sin_token_configurado_el_endpoint_queda_abierto() -> None:
    """
    En desarrollo no hay token y el endpoint responde. La configuracion
    impide que eso llegue a produccion: `METRICS_TOKEN` es obligatorio
    cuando el entorno es productivo, y sin el la aplicacion no arranca.
    """
    respuesta = _cliente(token=None).get("/metrics")
    assert respuesta.status_code == 200


def test_con_token_configurado_se_exige() -> None:
    cliente = _cliente()
    assert cliente.get("/metrics").status_code == 401
    assert cliente.get("/metrics", headers={"Authorization": "Bearer otro"}).status_code == 401


def test_el_token_correcto_abre_el_endpoint() -> None:
    respuesta = _cliente().get("/metrics", headers={"Authorization": f"Bearer {TOKEN_DE_METRICAS}"})
    assert respuesta.status_code == 200
    assert "mailauto_peticiones_http_total" in respuesta.text


def test_el_endpoint_no_aparece_en_el_contrato() -> None:
    """
    El formato de exposicion no es JSON y no tiene nada que hacer en el
    esquema que consume el cliente generado del frontend.
    """
    esquema = crear_app(ajustes_de_pruebas(metrics_token=TOKEN_DE_METRICAS)).openapi()
    assert "/metrics" not in esquema["paths"]


# ── Cardinalidad ─────────────────────────────────────────────────────


def test_la_ruta_se_etiqueta_con_el_patron_y_no_con_el_identificador() -> None:
    """La propiedad que evita una serie temporal por recurso."""
    cliente = _cliente()
    cliente.get("/api/v1/scans/11111111-1111-4111-8111-111111111111")

    cuerpo = _cuerpo_de_metricas(cliente)

    assert 'ruta="/api/v1/scans/{trabajo_id}"' in cuerpo
    assert "11111111-1111-4111-8111-111111111111" not in cuerpo


def test_una_ruta_inexistente_no_crea_una_serie_por_url() -> None:
    """
    Si no, cualquiera genera series a voluntad pidiendo rutas al azar, y
    eso agota la memoria de Prometheus sin tocar la aplicacion.
    """
    cliente = _cliente()
    for sufijo in ("uno", "dos", "tres"):
        cliente.get(f"/ruta/que/no/existe/{sufijo}")

    cuerpo = _cuerpo_de_metricas(cliente)

    assert 'ruta="desconocida"' in cuerpo
    for sufijo in ("uno", "dos", "tres"):
        assert f"/ruta/que/no/existe/{sufijo}" not in cuerpo


def test_ninguna_metrica_lleva_etiqueta_de_tenant() -> None:
    """
    Una etiqueta por tenant hace crecer la cardinalidad con cada cliente
    nuevo, y expone cuantos clientes hay y cuanto usa cada uno en un
    endpoint que suele estar menos protegido que la API. El consumo por
    tenant se consulta en la base de datos.
    """
    cuerpo = _cuerpo_de_metricas(_cliente())
    assert "tenant_id" not in cuerpo
    assert "{tenant" not in cuerpo


def test_el_propio_raspado_no_se_mide() -> None:
    """Medir `/metrics` solo mide al recolector, que no es trafico de nadie."""
    cliente = _cliente()
    _cuerpo_de_metricas(cliente)
    cuerpo = _cuerpo_de_metricas(cliente)
    assert 'ruta="/metrics"' not in cuerpo


# ── Contenido ────────────────────────────────────────────────────────


def test_se_cuenta_el_estado_de_la_respuesta() -> None:
    cliente = _cliente()
    cliente.get("/api/v1/records")  # 401: sin credenciales

    cuerpo = _cuerpo_de_metricas(cliente)

    assert 'estado="401"' in cuerpo
    assert 'ruta="/api/v1/records"' in cuerpo


def test_los_medidores_de_cola_se_leen_al_raspar() -> None:
    cliente = _cliente(cola=_ColaFalsa(profundidad=7, antiguedad=42.0))

    cuerpo = _cuerpo_de_metricas(cliente)

    assert 'mailauto_cola_profundidad{cola="ingesta"} 7.0' in cuerpo
    assert 'mailauto_cola_antiguedad_segundos{cola="ingesta"} 42.0' in cuerpo


def test_si_la_cola_no_responde_el_raspado_sigue_funcionando() -> None:
    """
    Perder un medidor es aceptable; perder TODAS las metricas porque uno
    falla deja al operador a ciegas justo cuando algo va mal.
    """
    respuesta = _cliente(cola=_ColaCaida()).get(
        "/metrics", headers={"Authorization": f"Bearer {TOKEN_DE_METRICAS}"}
    )
    assert respuesta.status_code == 200
    assert "mailauto_peticiones_http_total" in respuesta.text


@pytest.mark.parametrize(
    ("estado", "esperado"),
    [(200, "2xx"), (204, "2xx"), (301, "3xx"), (404, "4xx"), (429, "4xx"), (503, "5xx")],
)
def test_los_estados_se_agrupan_por_clase(estado: int, esperado: str) -> None:
    """
    La alerta pregunta "¿esta fallando el proveedor?", no "¿cuantos 418
    hubo?". Una serie por codigo exacto multiplica las series sin
    responder mejor a esa pregunta.
    """
    assert metricas.clase_de_estado(estado) == esperado


def test_el_registro_no_arrastra_las_metricas_del_proceso() -> None:
    """
    Registro propio y no el global: el global incluye lo que la libreria
    instala por su cuenta (memoria del proceso, recolector de basura), y
    mezclarlo hace mas dificil saber que expone de verdad este servicio.
    """
    cuerpo = _cuerpo_de_metricas(_cliente())
    assert "python_gc_objects_collected_total" not in cuerpo
    assert "process_virtual_memory_bytes" not in cuerpo
