"""ClientHello construction."""

from __future__ import annotations

import os
from typing import Callable, Sequence

from .profiles import firefox157
from .wire import u8, u16, u24, extension, vector

HANDSHAKE_CLIENT_HELLO = 0x01
CONTENT_TYPE_HANDSHAKE = 0x16
RANDOM_SIZE = 32

Rng = Callable[[int], bytes]


class Context:
    """Per-connection state handed to a profile's payload generators."""

    __slots__ = ("hostname", "_rng")

    def __init__(self, hostname: str, rng: Rng) -> None:
        self.hostname = hostname
        self._rng = rng

    def random(self, n: int) -> bytes:
        data = self._rng(n)
        if len(data) != n:
            raise ValueError(f"rng returned {len(data)} bytes, expected {n}")
        return data

    def choice(self, options: Sequence[int]) -> int:
        return options[self.random(1)[0] % len(options)]


def build_extensions(profile, ctx: Context) -> bytes:
    out = bytearray()
    for ext_type, payload in profile.EXTENSIONS:
        data = payload(ctx) if callable(payload) else payload
        out += extension(ext_type, data)
    return bytes(out)


def build_client_hello(
    hostname: str,
    *,
    profile=firefox157,
    rng: Rng | None = None,
) -> bytes:
    """Build a complete TLS record containing a ClientHello.

    Args:
        hostname: the name to put in the `server_name` extension.
        profile: a module describing the client to imitate.
        rng: returns n random bytes; defaults to `os.urandom`.

    Returns:
        The record, ready to write to a socket.
    """
    ctx = Context(hostname, rng or os.urandom)

    ciphers = b"".join(u16(suite) for suite in profile.CIPHER_SUITES)

    body = (
        u16(profile.LEGACY_VERSION)
        + ctx.random(RANDOM_SIZE)
        + vector(ctx.random(profile.SESSION_ID_SIZE), 1)
        + vector(ciphers, 2)
        + vector(bytes(profile.COMPRESSION_METHODS), 1)
        + vector(build_extensions(profile, ctx), 2)
    )

    handshake = u8(HANDSHAKE_CLIENT_HELLO) + u24(len(body)) + body
    return u8(CONTENT_TYPE_HANDSHAKE) + u16(profile.RECORD_VERSION) + vector(handshake, 2)
