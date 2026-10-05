"""
Jerarquia de errores de dominio.

Proposito
    Permitir que las capas internas expresen *que* salio mal en terminos
    del negocio, sin saber nada de HTTP, y que el borde traduzca eso a una
    respuesta RFC 9457 sin filtrar detalles internos.

Flujo
    dominio/aplicacion lanza ErrorDeDominio -> el middleware de errores lo
    mapea a Problem Details usando `codigo` y `estado_http`.

Dependencias
    Ninguna. Es deliberado: los errores son parte del vocabulario del
    dominio y no deben arrastrar FastAPI hacia adentro.
"""

from __future__ import annotations

from typing import Any


class ErrorDeDominio(Exception):
    """
    Raiz de todos los errores esperables del sistema.

    `mensaje_publico` es lo unico que llega al cliente. Cualquier detalle
    de diagnostico va en `contexto`, que se registra en el log pero nunca
    se serializa en la respuesta.
    """

    codigo: str = "error_interno"
    estado_http: int = 500
    mensaje_publico: str = "Ocurrio un error procesando la solicitud."

    def __init__(
        self,
        mensaje_publico: str | None = None,
        *,
        contexto: dict[str, Any] | None = None,
    ) -> None:
        self.mensaje_publico = mensaje_publico or self.mensaje_publico
        self.contexto = contexto or {}
        super().__init__(self.mensaje_publico)


# ── Validacion ───────────────────────────────────────────────────────


class ErrorDeValidacion(ErrorDeDominio):
    codigo = "validacion_fallida"
    estado_http = 422
    mensaje_publico = "Los datos enviados no son validos."

    def __init__(
        self,
        mensaje_publico: str | None = None,
        *,
        campo: str | None = None,
        contexto: dict[str, Any] | None = None,
    ) -> None:
        self.campo = campo
        super().__init__(mensaje_publico, contexto=contexto)


# ── Autenticacion y autorizacion ─────────────────────────────────────


class ErrorDeAutenticacion(ErrorDeDominio):
    codigo = "no_autenticado"
    estado_http = 401
    mensaje_publico = "Credenciales ausentes o invalidas."


class TokenInvalido(ErrorDeAutenticacion):
    codigo = "token_invalido"


class ErrorDeAutorizacion(ErrorDeDominio):
    """
    Se usa tanto para "no tienes permiso" como para "ese recurso es de otro
    tenant". Devolver 403 en ambos casos evita convertir el codigo de estado
    en un oraculo que confirme la existencia de recursos ajenos.
    """

    codigo = "permiso_denegado"
    estado_http = 403
    mensaje_publico = "No tienes permiso para realizar esta accion."


# ── Recursos ─────────────────────────────────────────────────────────


class RecursoNoEncontrado(ErrorDeDominio):
    codigo = "recurso_no_encontrado"
    estado_http = 404
    mensaje_publico = "El recurso solicitado no existe."


class ConflictoDeEstado(ErrorDeDominio):
    codigo = "conflicto_de_estado"
    estado_http = 409
    mensaje_publico = "La operacion no es valida en el estado actual del recurso."


# ── Limites ──────────────────────────────────────────────────────────


class LimiteExcedido(ErrorDeDominio):
    codigo = "limite_excedido"
    estado_http = 429
    mensaje_publico = "Se excedio el limite de solicitudes. Reintenta mas tarde."

    def __init__(
        self,
        mensaje_publico: str | None = None,
        *,
        reintentar_en_segundos: int | None = None,
        contexto: dict[str, Any] | None = None,
    ) -> None:
        self.reintentar_en_segundos = reintentar_en_segundos
        super().__init__(mensaje_publico, contexto=contexto)


class CuotaAgotada(ErrorDeDominio):
    codigo = "cuota_agotada"
    estado_http = 402
    mensaje_publico = "Se agoto la cuota contratada para esta operacion."


# ── Criptografia ─────────────────────────────────────────────────────


class ErrorDeCifrado(ErrorDeDominio):
    """
    El mensaje publico es deliberadamente vago: distinguir "clave erronea"
    de "ciphertext manipulado" le da informacion util a un atacante.
    """

    codigo = "error_de_cifrado"
    estado_http = 500
    mensaje_publico = "No fue posible procesar un dato protegido."


# ── Proveedores externos ─────────────────────────────────────────────


class ErrorDeProveedor(ErrorDeDominio):
    codigo = "error_de_proveedor"
    estado_http = 502
    mensaje_publico = "El proveedor de correo no respondio correctamente."

    def __init__(
        self,
        mensaje_publico: str | None = None,
        *,
        proveedor: str | None = None,
        reintentable: bool = True,
        contexto: dict[str, Any] | None = None,
    ) -> None:
        self.proveedor = proveedor
        self.reintentable = reintentable
        super().__init__(mensaje_publico, contexto=contexto)


class CredencialesRevocadas(ErrorDeProveedor):
    """El usuario revoco el acceso desde la consola del proveedor."""

    codigo = "credenciales_revocadas"
    estado_http = 409
    mensaje_publico = "La vinculacion con el buzon dejo de ser valida. Vuelve a conectarlo."

    def __init__(
        self,
        mensaje_publico: str | None = None,
        *,
        proveedor: str | None = None,
        contexto: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            mensaje_publico, proveedor=proveedor, reintentable=False, contexto=contexto
        )


class ProveedorSaturado(ErrorDeProveedor):
    """429 del proveedor. Trae el `Retry-After` para respetarlo en el backoff."""

    codigo = "proveedor_saturado"
    estado_http = 503

    def __init__(
        self,
        mensaje_publico: str | None = None,
        *,
        proveedor: str | None = None,
        reintentar_en_segundos: int = 60,
        contexto: dict[str, Any] | None = None,
    ) -> None:
        self.reintentar_en_segundos = reintentar_en_segundos
        super().__init__(mensaje_publico, proveedor=proveedor, reintentable=True, contexto=contexto)


# ── Adjuntos ─────────────────────────────────────────────────────────


class AdjuntoRechazado(ErrorDeDominio):
    """
    El adjunto no supero la validacion de seguridad: tipo no permitido,
    magic bytes que no coinciden con la extension, tamaño excesivo.
    """

    codigo = "adjunto_rechazado"
    estado_http = 422
    mensaje_publico = "El adjunto no cumple los requisitos de formato o tamaño."

    def __init__(
        self,
        mensaje_publico: str | None = None,
        *,
        motivo: str,
        contexto: dict[str, Any] | None = None,
    ) -> None:
        self.motivo = motivo
        super().__init__(mensaje_publico, contexto=contexto)
