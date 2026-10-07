"""ClientHello construction."""

from __future__ import annotations

import os
from typing import Callable, Sequence

from .model import Extension
from .profiles import firefox157
from .wire import u8, u16, u24, extension, vector

HANDSHAKE_CLIENT_HELLO = 0x01
CONTENT_TYPE_HANDSHAKE = 0x16
RANDOM_SIZE = 32
EXT_KEY_SHARE = 51
EXT_COOKIE = 44
EXT_PRE_SHARED_KEY = 41

Rng = Callable[[int], bytes]


class Context:
    """Per-connection state handed to a profile's payload generators."""

    __slots__ = ("hostname", "key_exchange", "_rng")

    def __init__(self, hostname: str, rng: Rng, key_exchange=None) -> None:
        self.hostname = hostname
        self.key_exchange = key_exchange
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
    key_exchange=None,
) -> bytes:
    """Build a complete TLS record containing a ClientHello.

    Args:
        hostname: the name to put in the `server_name` extension.
        profile: a module describing the client to imitate.
        rng: returns n random bytes; defaults to `os.urandom`.
        key_exchange: supplies the key_share entries. A profile creates its
            own when this is None; pass one to keep the private keys.

    Returns:
        The record, ready to write to a socket.
    """
    ctx = Context(hostname, rng or os.urandom, key_exchange)

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


def serialise(hello, record_version: int = 0x0301) -> bytes:
    """Rebuild the wire bytes of a parsed ClientHello."""
    ciphers = b"".join(u16(suite) for suite in hello.cipher_suites)
    extensions = b"".join(extension(e.type, e.data) for e in hello.extensions)
    body = (
        u16(hello.legacy_version)
        + hello.random
        + vector(hello.session_id, 1)
        + vector(ciphers, 2)
        + vector(bytes(hello.compression_methods), 1)
        + vector(extensions, 2)
    )
    handshake = u8(HANDSHAKE_CLIENT_HELLO) + u24(len(body)) + body
    return u8(CONTENT_TYPE_HANDSHAKE) + u16(record_version) + vector(handshake, 2)


def retry_hello(original: bytes, group: int, share: bytes,
                cookie: bytes | None = None) -> bytes:
    """The second ClientHello a HelloRetryRequest asks for.

    RFC 8446 section 4.1.2: it must equal the first except for the key_share,
    which carries one entry for the group the server chose, plus the server's
    cookie if it sent one. Rebuilding from the original bytes rather than
    re-emitting from the profile is what guarantees "except".

    The cookie's position is UNMEASURED. No capture of a browser answering a
    HelloRetryRequest exists here, so it goes last, which is legal and may
    not be what Firefox does.
    """
    from .parser import parse_client_hello

    hello = parse_client_hello(original)
    entry = u16(group) + vector(share, 2)
    rebuilt = []
    for existing in hello.extensions:
        if existing.type == EXT_KEY_SHARE:
            rebuilt.append(Extension(EXT_KEY_SHARE, vector(entry, 2)))
        else:
            rebuilt.append(existing)
    if cookie is not None and not any(e.type == EXT_COOKIE for e in rebuilt):
        rebuilt.append(Extension(EXT_COOKIE, cookie))
    hello.extensions = rebuilt
    return serialise(hello, int.from_bytes(original[1:3], "big"))


def with_psk(original: bytes, tickets, suite) -> bytes:
    """Add a pre_shared_key extension offering `tickets`.

    The extension has to be last, and its binders are an HMAC over the
    ClientHello that contains them: everything up to where the binders
    begin. So the message is built once with the right lengths and empty
    binders, hashed, and the binders written into the space already
    reserved. RFC 8446 section 4.2.11.2.
    """
    from .keyschedule import psk_binder
    from .parser import parse_client_hello

    hello = parse_client_hello(original)
    if any(e.type == EXT_PRE_SHARED_KEY for e in hello.extensions):
        raise ValueError("this ClientHello already offers a pre-shared key")

    identities = b"".join(
        vector(t.identity, 2) + t.obfuscated_age().to_bytes(4, "big")
        for t in tickets
    )
    placeholder = b"".join(vector(bytes(suite.hash_size), 1) for _ in tickets)
    hello.extensions = list(hello.extensions) + [
        Extension(EXT_PRE_SHARED_KEY, vector(identities, 2) + vector(placeholder, 2))
    ]

    record = serialise(hello, int.from_bytes(original[1:3], "big"))
    message = record[5:]
    # The binders, and the two-byte length in front of them, are the tail.
    tail = 2 + len(placeholder)
    truncated = message[:-tail]

    binders = b"".join(
        vector(psk_binder(suite, t.psk, truncated), 1) for t in tickets
    )
    if len(binders) != len(placeholder):
        raise ValueError("binders did not fill the space reserved for them")
    return record[:-len(binders)] + binders
