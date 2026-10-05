"""
Almacenamiento de adjuntos en S3 (o MinIO en desarrollo).

Proposito
    Sacar los adjuntos del disco del contenedor para poder reprocesarlos,
    auditarlos y aplicarles retencion.

Dependencias
    aioboto3.

Decisiones de diseño
    1. Cifrado del lado del servidor activado en cada objeto (`AES256`).
       Que el bucket tenga cifrado por defecto no se da por supuesto: una
       configuracion de infraestructura puede cambiar sin que nadie revise
       este codigo.

    2. Descarga solo por URL prefirmada de vida corta. El bucket nunca es
       publico y la API no hace de proxy de bytes, que la obligaria a
       mantener conexiones abiertas durante descargas largas.

    3. Las claves llevan el `tenant_id` como prefijo. Permite politicas
       de ciclo de vida y borrado masivo por tenant, y hace evidente en
       cualquier listado a quien pertenece cada objeto.
"""

from __future__ import annotations

from typing import Any

import aioboto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from mailauto.modules.ingestion.domain.ports import AlmacenDeObjetos
from mailauto.shared.errors import ErrorDeDominio
from mailauto.shared.observability.logging import obtener_logger

logger = obtener_logger(__name__)

_CONFIG = Config(
    retries={"max_attempts": 3, "mode": "standard"},
    connect_timeout=5,
    read_timeout=30,
    signature_version="s3v4",
)


class ErrorDeAlmacenamiento(ErrorDeDominio):
    codigo = "error_de_almacenamiento"
    estado_http = 502
    mensaje_publico = "No fue posible almacenar el archivo."


class AlmacenDeObjetosS3(AlmacenDeObjetos):
    def __init__(
        self,
        *,
        bucket: str,
        region: str,
        access_key: str,
        secret_key: str,
        endpoint_url: str | None = None,
        ttl_presigned: int = 300,
    ) -> None:
        self._bucket = bucket
        self._ttl = ttl_presigned
        self._sesion = aioboto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )
        self._endpoint = endpoint_url

    def _cliente(self) -> Any:  # noqa: ANN401 - context manager de aioboto3, sin tipos publicos
        return self._sesion.client("s3", endpoint_url=self._endpoint, config=_CONFIG)

    async def guardar(
        self, *, clave: str, contenido: bytes, tipo_mime: str, metadatos: dict[str, str]
    ) -> None:
        try:
            async with self._cliente() as s3:
                await s3.put_object(
                    Bucket=self._bucket,
                    Key=clave,
                    Body=contenido,
                    ContentType=tipo_mime,
                    ServerSideEncryption="AES256",
                    Metadata=metadatos,
                )
        except (ClientError, BotoCoreError) as exc:
            logger.error("fallo_al_guardar_objeto", clave=clave, error=type(exc).__name__)
            raise ErrorDeAlmacenamiento() from exc

    async def descargar(self, clave: str) -> bytes:
        try:
            async with self._cliente() as s3:
                respuesta = await s3.get_object(Bucket=self._bucket, Key=clave)
                cuerpo: bytes = await respuesta["Body"].read()
                return cuerpo
        except (ClientError, BotoCoreError) as exc:
            logger.error("fallo_al_descargar_objeto", clave=clave, error=type(exc).__name__)
            raise ErrorDeAlmacenamiento() from exc

    async def url_de_descarga(self, clave: str, *, ttl_segundos: int) -> str:
        try:
            async with self._cliente() as s3:
                url: str = await s3.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": self._bucket, "Key": clave},
                    ExpiresIn=min(ttl_segundos, self._ttl),
                )
                return url
        except (ClientError, BotoCoreError) as exc:
            raise ErrorDeAlmacenamiento() from exc

    async def eliminar(self, clave: str) -> None:
        try:
            async with self._cliente() as s3:
                await s3.delete_object(Bucket=self._bucket, Key=clave)
        except (ClientError, BotoCoreError) as exc:
            logger.error("fallo_al_eliminar_objeto", clave=clave, error=type(exc).__name__)
            raise ErrorDeAlmacenamiento() from exc

    async def esta_disponible(self) -> bool:
        try:
            async with self._cliente() as s3:
                await s3.head_bucket(Bucket=self._bucket)
            return True
        except Exception:  # noqa: BLE001 - sonda de salud: informa binario, no diagnostica
            return False

    async def asegurar_bucket(self) -> None:
        """
        Crea el bucket si no existe. Solo para desarrollo con MinIO: en
        produccion el bucket lo provisiona la infraestructura, con sus
        politicas de acceso y ciclo de vida.
        """
        try:
            async with self._cliente() as s3:
                try:
                    await s3.head_bucket(Bucket=self._bucket)
                except ClientError:
                    await s3.create_bucket(Bucket=self._bucket)
        except (ClientError, BotoCoreError) as exc:
            logger.warning("no_se_pudo_asegurar_bucket", error=type(exc).__name__)
