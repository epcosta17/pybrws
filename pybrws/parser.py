"""Fase 0 - EL ORACULO. Esto lo escribes TU.

Parsear un ClientHello. Sin librerias, sin atajos. Es el ejercicio que vuelve
el formato tuyo, y es la herramienta de la que depende todo el resto del
proyecto.

---------------------------------------------------------------------------
LA ESTRUCTURA
---------------------------------------------------------------------------

Record layer (5 bytes):
    content_type            1 byte    0x16 = handshake
    legacy_record_version   2 bytes   0x0301 o 0x0303
    length                  2 bytes

Handshake header (4 bytes):
    msg_type                1 byte    0x01 = client_hello
    length                  3 bytes   <- ojo, TRES bytes

ClientHello body (los 7 campos, en este orden, siempre):
    legacy_version          2 bytes
    random                 32 bytes
    session_id              1 byte de longitud + 0..32 bytes
    cipher_suites           2 bytes de longitud + N*2 bytes
    compression_methods     1 byte de longitud + N bytes
    extensions              2 bytes de longitud + lista

Cada extension:
    type                    2 bytes
    length                  2 bytes
    data                    length bytes

---------------------------------------------------------------------------
AVISO
---------------------------------------------------------------------------

Hay longitudes dentro de longitudes dentro de longitudes. Ahi se atora todo el
mundo, incluido tu. Cuando el parser falle, no adivines: usa
`hexio.hexdump()` y cuenta bytes con el dedo.

Decide y documenta: ¿aceptas solo el record completo, o tambien un
ClientHello "pelado" sin record layer? Los dos casos van a aparecer.

Valida contra Wireshark. Si tu arbol coincide con el suyo, terminaste.
"""

from __future__ import annotations

from .model import ClientHello, Extension


def parse_client_hello(data: bytes) -> ClientHello:
    """Parse raw bytes into a ClientHello.

    Args:
        data: the full TLS record starting with 0x16, or a bare handshake
              message starting with 0x01. Your call which you support.

    Returns:
        A populated ClientHello, with `raw` set to the bytes consumed.

    Raises:
        ValueError: on anything that is not a well-formed ClientHello.
    """
    raise NotImplementedError("Fase 0: escribelo tu. Ver el docstring del modulo.")
