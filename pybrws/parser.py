"""ClientHello parsing.

Wire format: RFC 8446 section 4.1.2.
"""

from __future__ import annotations

from .model import ClientHello, Extension

CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
RANDOM_SIZE = 32


class _Reader:
    """Cursor over a byte string, for length-prefixed structures."""

    __slots__ = ("_buf", "_pos", "_what")

    def __init__(self, buf: bytes, what: str = "input") -> None:
        self._buf = buf
        self._pos = 0
        self._what = what

    @property
    def remaining(self) -> int:
        return len(self._buf) - self._pos

    def read(self, n: int) -> bytes:
        if n > self.remaining:
            raise ValueError(
                f"truncated {self._what}: need {n} bytes at offset {self._pos}, "
                f"have {self.remaining}"
            )
        chunk = self._buf[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def uint(self, n: int) -> int:
        return int.from_bytes(self.read(n), "big")

    def vector(self, length_bytes: int) -> bytes:
        """Read a vector prefixed by a big-endian length of `length_bytes`."""
        return self.read(self.uint(length_bytes))


def _parse_extensions(data: bytes) -> list[Extension]:
    reader = _Reader(data, "extension list")
    extensions: list[Extension] = []
    while reader.remaining:
        if reader.remaining < 4:
            raise ValueError(
                f"truncated extension header: {reader.remaining} trailing bytes"
            )
        ext_type = reader.uint(2)
        extensions.append(Extension(ext_type, reader.vector(2)))
    return extensions


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
    if not data:
        raise ValueError("empty input")

    outer = _Reader(data, "record")
    if data[0] == CONTENT_TYPE_HANDSHAKE:
        outer.read(1)
        outer.read(2)  # legacy_record_version
        handshake = _Reader(outer.vector(2), "handshake message")
    elif data[0] == HANDSHAKE_CLIENT_HELLO:
        handshake = outer
    else:
        raise ValueError(
            f"not a handshake record or ClientHello: first byte is 0x{data[0]:02x}"
        )

    msg_type = handshake.uint(1)
    if msg_type != HANDSHAKE_CLIENT_HELLO:
        raise ValueError(f"handshake type is 0x{msg_type:02x}, expected 0x01")

    body = _Reader(handshake.vector(3), "ClientHello body")

    legacy_version = body.uint(2)
    random = body.read(RANDOM_SIZE)
    session_id = body.vector(1)

    cipher_bytes = body.vector(2)
    if len(cipher_bytes) % 2:
        raise ValueError(f"cipher_suites has odd length {len(cipher_bytes)}")
    cipher_suites = [
        int.from_bytes(cipher_bytes[i : i + 2], "big")
        for i in range(0, len(cipher_bytes), 2)
    ]

    compression_methods = list(body.vector(1))

    # Absent in SSLv3-era hellos, present in everything current.
    extensions = _parse_extensions(body.vector(2)) if body.remaining else []

    if body.remaining:
        raise ValueError(f"{body.remaining} trailing bytes after extensions")

    consumed = len(data) - outer.remaining
    return ClientHello(
        legacy_version=legacy_version,
        random=random,
        session_id=session_id,
        cipher_suites=cipher_suites,
        compression_methods=compression_methods,
        extensions=extensions,
        raw=data[:consumed],
    )
