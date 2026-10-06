"""ClientHello parsing.

Wire format: RFC 8446 section 4.1.2.
"""

from __future__ import annotations

from .model import ClientHello, Extension


def parse_client_hello(data: bytes) -> ClientHello:
    """Parse raw bytes into a ClientHello.

    Args:
        data: a TLS record starting with 0x16, or a bare handshake message
            starting with 0x01.

    Returns:
        A ClientHello with `raw` set to the bytes consumed.

    Raises:
        ValueError: if the input is not a well-formed ClientHello.
    """
    raise NotImplementedError
