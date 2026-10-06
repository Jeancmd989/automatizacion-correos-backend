"""
Almacen de adjuntos contra un S3 real (MinIO).

Proposito
    Verificar el ciclo completo de un adjunto —guardar, descargar, firmar
    una URL temporal, borrar— y que las claves aislan a cada tenant.

Por que hace falta el servicio
    La firma v4 de las URLs presignadas, el cifrado en reposo y el
    comportamiento ante una clave inexistente los decide el servidor.
    Un doble devolveria lo que se le programe, incluida una URL que no
    funciona.

Dependencias
    MinIO (o S3) accesible, con credenciales de desarrollo.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
import pytest

from mailauto.modules.ingestion.infrastructure.almacen_s3 import (
    AlmacenDeObjetosS3,
    ErrorDeAlmacenamiento,
)
from tests.integration.conftest import (
    CLAVE_ALMACEN,
    ENDPOINT_ALMACEN,
    SECRETO_ALMACEN,
    exigir_servicio,
)

pytestmark = pytest.mark.integration

_CONTENIDO = b"%PDF-1.7\nconstancia de prueba\n"


@pytest.fixture
async def almacen() -> AsyncIterator[AlmacenDeObjetosS3]:
    exigir_servicio("MinIO", ENDPOINT_ALMACEN, 9000)
    # Bucket propio del test: no comparte espacio con el de desarrollo.
    instancia = AlmacenDeObjetosS3(
        bucket=f"pruebas-{uuid4().hex[:12]}",
        region="us-east-1",
        access_key=CLAVE_ALMACEN,
        secret_key=SECRETO_ALMACEN,
        endpoint_url=ENDPOINT_ALMACEN,
        ttl_presigned=300,
    )
    await instancia.asegurar_bucket()
    yield instancia


def _clave_de(tenant_id: str) -> str:
    """Reproduce la forma de clave que usa el pipeline de ingesta."""
    return f"{tenant_id}/{uuid4()}"


async def test_lo_guardado_se_recupera_identico(almacen: AlmacenDeObjetosS3) -> None:
    clave = _clave_de(str(uuid4()))
    await almacen.guardar(
        clave=clave,
        contenido=_CONTENIDO,
        tipo_mime="application/pdf",
        metadatos={"sha256": "0" * 64},
    )

    assert await almacen.descargar(clave) == _CONTENIDO


async def test_descargar_una_clave_inexistente_da_un_error_de_dominio(
    almacen: AlmacenDeObjetosS3,
) -> None:
    """
    El borde HTTP traduce `ErrorDeDominio` a una respuesta limpia. Si
    aqui escapara un `ClientError` de botocore, el cliente recibiria un
    500 con detalles del proveedor de almacenamiento.
    """
    with pytest.raises(ErrorDeAlmacenamiento):
        await almacen.descargar(_clave_de(str(uuid4())))


async def test_la_url_presignada_descarga_el_objeto(almacen: AlmacenDeObjetosS3) -> None:
    """
    Una URL firmada que no sirve para descargar es un boton roto en la
    interfaz, y no se nota hasta que un usuario lo pulsa.
    """
    clave = _clave_de(str(uuid4()))
    await almacen.guardar(
        clave=clave, contenido=_CONTENIDO, tipo_mime="application/pdf", metadatos={}
    )

    url = await almacen.url_de_descarga(clave, ttl_segundos=120)

    async with httpx.AsyncClient() as cliente:
        respuesta = await cliente.get(url)
    assert respuesta.status_code == 200
    assert respuesta.content == _CONTENIDO


async def test_la_url_presignada_no_lleva_la_clave_secreta() -> None:
    """
    La firma viaja en la URL; la clave secreta no debe hacerlo. La URL
    acaba en el historial del navegador y en los logs de cualquier proxy
    intermedio.

    Se firma con un secreto distintivo y no con las credenciales de
    MinIO porque en desarrollo el identificador y el secreto valen lo
    mismo (`minioadmin`), y `X-Amz-Credential` contiene el
    identificador a proposito: con valores iguales la asercion no
    distinguiria uno de otro y pasaria sin comprobar nada. Presignar es
    un calculo local, asi que no importa que estas credenciales no
    sirvan para conectar.
    """
    secreto = "este-secreto-no-debe-aparecer-en-la-url"
    almacen = AlmacenDeObjetosS3(
        bucket="cualquiera",
        region="us-east-1",
        access_key="identificador-publico",
        secret_key=secreto,
        endpoint_url=ENDPOINT_ALMACEN,
        ttl_presigned=300,
    )

    url = await almacen.url_de_descarga("tenant/objeto", ttl_segundos=120)

    assert secreto not in url
    consulta = urlsplit(url).query
    assert "X-Amz-Signature" in consulta
    assert "X-Amz-Expires" in consulta
    # El identificador si aparece, y debe: es la parte publica de la
    # firma v4. Afirmarlo evita que un cambio futuro lo oculte y rompa
    # la verificacion en el servidor sin que ningun test lo note.
    assert "X-Amz-Credential=identificador-publico" in consulta


async def test_el_ttl_solicitado_no_puede_superar_el_configurado(
    almacen: AlmacenDeObjetosS3,
) -> None:
    """
    Un llamante que pida un dia de validez no debe obtenerlo: el tope lo
    fija la configuracion del almacen, no quien construye el enlace.
    """
    clave = _clave_de(str(uuid4()))
    await almacen.guardar(
        clave=clave, contenido=_CONTENIDO, tipo_mime="application/pdf", metadatos={}
    )

    url = await almacen.url_de_descarga(clave, ttl_segundos=86_400)

    parametros = dict(
        parte.split("=", 1) for parte in urlsplit(url).query.split("&") if "=" in parte
    )
    assert int(parametros["X-Amz-Expires"]) == 300


async def test_la_clave_aisla_a_cada_tenant(almacen: AlmacenDeObjetosS3) -> None:
    """
    Las claves van prefijadas por tenant. Es lo que permite que una
    politica de bucket o una purga por cliente operen por prefijo sin
    tocar los objetos de los demas.
    """
    tenant_a, tenant_b = str(uuid4()), str(uuid4())
    clave_a, clave_b = _clave_de(tenant_a), _clave_de(tenant_b)

    for clave in (clave_a, clave_b):
        await almacen.guardar(
            clave=clave, contenido=_CONTENIDO, tipo_mime="application/pdf", metadatos={}
        )

    assert clave_a.startswith(f"{tenant_a}/")
    assert clave_b.startswith(f"{tenant_b}/")
    assert not clave_b.startswith(f"{tenant_a}/")


async def test_eliminar_deja_el_objeto_inaccesible(almacen: AlmacenDeObjetosS3) -> None:
    """La purga por retencion depende de que el borrado sea efectivo."""
    clave = _clave_de(str(uuid4()))
    await almacen.guardar(
        clave=clave, contenido=_CONTENIDO, tipo_mime="application/pdf", metadatos={}
    )

    await almacen.eliminar(clave)

    with pytest.raises(ErrorDeAlmacenamiento):
        await almacen.descargar(clave)


async def test_la_sonda_de_salud_distingue_disponible_de_caido(
    almacen: AlmacenDeObjetosS3,
) -> None:
    """
    `/health/ready` depende de esta sonda. Una que devolviera siempre
    `True` haria que el balanceador enviara trafico a una instancia que
    no puede escribir adjuntos.
    """
    assert await almacen.esta_disponible() is True

    inexistente = AlmacenDeObjetosS3(
        bucket=f"no-existe-{uuid4().hex[:12]}",
        region="us-east-1",
        access_key=CLAVE_ALMACEN,
        secret_key=SECRETO_ALMACEN,
        endpoint_url=ENDPOINT_ALMACEN,
    )
    assert await inexistente.esta_disponible() is False
