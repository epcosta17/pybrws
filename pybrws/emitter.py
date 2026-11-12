"""ClientHello construction."""

from __future__ import annotations

import os
from typing import Callable, Sequence

from .keyexchange import KeyExchange
from .model import Extension, GREASE_DRAW
from .profiles import ProfileError, firefox157
from .wire import u8, u16, u24, extension, vector

HANDSHAKE_CLIENT_HELLO = 0x01
CONTENT_TYPE_HANDSHAKE = 0x16
RANDOM_SIZE = 32
EXT_KEY_SHARE = 51
EXT_COOKIE = 44
EXT_PRE_SHARED_KEY = 41
EXT_SESSION_TICKET = 35
EXT_ENCRYPTED_CLIENT_HELLO = 65037

Rng = Callable[[int], bytes]


class Context:
    """Per-connection state handed to a profile's payload generators."""

    __slots__ = ("hostname", "key_exchange", "_rng", "_grease", "_memo")

    def __init__(self, hostname: str, rng: Rng, key_exchange=None) -> None:
        self.hostname = hostname
        self.key_exchange = key_exchange
        self._rng = rng
        self._grease: dict[str, int] = {}
        self._memo: dict[str, object] = {}

    def random(self, n: int) -> bytes:
        data = self._rng(n)
        if len(data) != n:
            raise ValueError(f"rng returned {len(data)} bytes, expected {n}")
        return data

    def choice(self, options: Sequence[int]) -> int:
        return options[self.random(1)[0] % len(options)]

    def once(self, key: str, factory):
        """Compute `factory()` the first time and reuse it after.

        For per-connection values a profile has to agree with itself about:
        the extension order and the payload lookup are separate calls, and a
        value drawn twice would differ between them.
        """
        if key not in self._memo:
            self._memo[key] = factory()
        return self._memo[key]

    def grease(self, slot: str) -> int:
        """A GREASE value for `slot`, drawn once per connection.

        Memoised by slot because the draws are not all independent. Chrome
        puts a fresh value at the front of its cipher suites, its signature
        algorithms, its supported versions, and at both ends of its extension
        list -- five independent draws -- but `supported_groups` and
        `key_share` share one, measured identical in all six captures, which
        the protocol requires: the key_share entry has to name a group the
        client offered.

        So `ctx.grease("groups")` asked twice gives the same value, and
        `ctx.grease("cipher")` is a different draw.
        """
        if slot not in self._grease:
            self._grease[slot] = GREASE_DRAW[
                self.random(1)[0] % len(GREASE_DRAW)]
        return self._grease[slot]


def build_extensions(profile, ctx: Context) -> bytes:
    """The extensions block, in whatever order the profile says.

    Two kinds of profile. One stores an ordered list, because its browser
    sends the same order every time -- Firefox over TCP. The other draws an
    order per connection and answers for one extension at a time, because its
    browser shuffles: Chrome on every protocol, and Firefox over QUIC. A
    profile of the second kind supplies `extension_order` and `payload_for`.

    Keeping the stored kind is not backwards compatibility for its own sake:
    a stored order is a stronger claim than a drawn one, and flattening both
    into a draw would lose the distinction that was measured.

    A payload of None leaves the extension out: server_name for an IP
    literal, which RFC 6066 forbids and neither browser sends.
    """
    if hasattr(profile, "extension_order"):
        pairs = ((ext_type, profile.payload_for(ext_type, ctx))
                 for ext_type in profile.extension_order(ctx))
    else:
        pairs = ((ext_type, payload(ctx) if callable(payload) else payload)
                 for ext_type, payload in profile.EXTENSIONS)
    out = bytearray()
    for ext_type, data in pairs:
        if data is not None:
            out += extension(ext_type, data)
    return bytes(out)


def _cannot_build(profile, error: Exception) -> ProfileError:
    """A profile whose own values or functions cannot make a hello."""
    name = getattr(profile, "NAME", None) or getattr(profile, "__name__", "?")
    return ProfileError("cannot build a hello from profile %r: %s: %s"
                        % (name, type(error).__name__, error))


def key_exchange_for(profile):
    """The key exchange for the profile's own KEY_SHARE_GROUPS, or None.

    It is the one `handshake.connect` makes and the one `build_client_hello`
    makes when it is given none, so the hello `pybrws verify` builds is the
    hello a connection sends. Groups come from the profile passed in, not
    from whichever module its key_share function was written in: a copy of
    firefox157 that names other groups keeps firefox157's function.

    Raises:
        ProfileError: a group no key exchange here knows.
    """
    groups = getattr(profile, "KEY_SHARE_GROUPS", None)
    if not groups:
        return None
    try:
        return KeyExchange([group for group, _ in groups])
    except Exception as error:
        raise _cannot_build(profile, error) from error


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
        key_exchange: supplies the key_share entries. When it is None, the
            one `key_exchange_for(profile)` makes, as `handshake.connect`
            does; pass one to keep the private keys.

    Returns:
        The record, ready to write to a socket.

    Raises:
        ProfileError: the profile's values or functions cannot make a hello,
            such as a firefox157 key_share handed groups firefox157 does not
            send. The message names the profile and the error.
    """
    if key_exchange is None:
        key_exchange = key_exchange_for(profile)
    try:
        return _build(hostname, profile, rng or os.urandom, key_exchange)
    except Exception as error:
        raise _cannot_build(profile, error) from error


def _build(hostname: str, profile, rng: Rng, key_exchange) -> bytes:
    ctx = Context(hostname, rng, key_exchange)

    # A profile whose cipher list carries a per-connection GREASE value
    # supplies a callable; one with a fixed list supplies the list.
    suites = (profile.CIPHER_SUITES(ctx) if callable(profile.CIPHER_SUITES)
              else profile.CIPHER_SUITES)
    ciphers = b"".join(u16(suite) for suite in suites)

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


def retry_hello(original: bytes, group: int | None, share: bytes | None,
                cookie: bytes | None = None, *, binder_context: bytes = b"",
                tickets=None, suite=None) -> bytes:
    """The second ClientHello a HelloRetryRequest asks for.

    RFC 8446 section 4.1.2: it must equal the first except for the key_share,
    which carries one entry for the group the server chose, plus the server's
    cookie if it sent one, plus a pre_shared_key brought up to date. Rebuilding
    from the original bytes rather than re-emitting from the profile is what
    guarantees "except".

    `group=None` is a retry that only carries a cookie: the key shares stay.

    A PSK cannot be copied across. Its binder signs the transcript, and the
    transcript now starts with the first hello's hash and the retry request,
    which is what `binder_context` holds; its age has moved on too. So any old
    pre_shared_key is removed, and with `tickets` it is re-attached, last,
    with fresh ages and binders over the new transcript (RFC 8446 4.2.11.2).
    Without `tickets` it stays removed, which the RFC allows for a PSK the
    server's suite cannot use.

    The cookie's position is UNMEASURED. No capture of a browser answering a
    HelloRetryRequest exists here, so it goes at the end of everything but
    the pre_shared_key, which RFC 8446 requires to be last.
    """
    from .parser import parse_client_hello

    hello = parse_client_hello(original)
    rebuilt = []
    for existing in hello.extensions:
        if existing.type == EXT_PRE_SHARED_KEY:
            continue
        if existing.type == EXT_KEY_SHARE and group is not None:
            entry = u16(group) + vector(share, 2)
            rebuilt.append(Extension(EXT_KEY_SHARE, vector(entry, 2)))
        else:
            rebuilt.append(existing)
    if cookie is not None and not any(e.type == EXT_COOKIE for e in rebuilt):
        rebuilt.append(Extension(EXT_COOKIE, cookie))
    hello.extensions = rebuilt
    record = serialise(hello, int.from_bytes(original[1:3], "big"))
    if tickets:
        return _attach_psk(record, tickets, suite, binder_context)
    return record


def grow_ech(data: bytes, extra: int, rng: Callable[[int], bytes]) -> bytes:
    """Return a greased ECH extension with `extra` more payload bytes.

    The payload is random either way, so lengthening it is appending
    more of the same; what matters is that the two length prefixes in
    front of it stay correct.
    """
    enc_size = int.from_bytes(data[6:8], "big")
    cut = 8 + enc_size
    declared = int.from_bytes(data[cut:cut + 2], "big")
    payload = data[cut + 2:]
    if len(payload) != declared:
        raise ValueError(
            "encrypted_client_hello declares %d payload bytes but carries %d"
            % (declared, len(payload))
        )
    return data[:cut] + vector(payload + rng(extra), 2)


def with_psk(original: bytes, tickets, suite, *, profile=firefox157,
             rng: Callable[[int], bytes] = os.urandom) -> bytes:
    """Add a pre_shared_key extension offering `tickets`.

    The extension has to be last, and its binders are an HMAC over the
    ClientHello that contains them: everything up to where the binders
    begin. So the message is built once with the right lengths and empty
    binders, hashed, and the binders written into the space already
    reserved. RFC 8446 section 4.2.11.2.

    session_ticket is dropped on the way, which the RFC does not ask for but
    the browser does.
    """
    from .parser import parse_client_hello

    hello = parse_client_hello(original)
    if any(e.type == EXT_PRE_SHARED_KEY for e in hello.extensions):
        raise ValueError("this ClientHello already offers a pre-shared key")

    # Measured: Firefox does not merely append the extension, it *swaps*
    # session_ticket for it, so a resumed hello carries the same number of
    # extensions as a fresh one. Appending without dropping would leave us at
    # eighteen against its seventeen, which puts the extension count in JA4 at
    # t13d1518h2 against the browser's t13d1517h2 -- a tell a server can read
    # by counting, without hashing anything.
    # fixtures/reference-firefox-157-windows-resumed.hex
    kept = [e for e in hello.extensions if e.type != EXT_SESSION_TICKET]

    # The greased ECH payload stands in for an encrypted inner ClientHello,
    # which now carries a pre_shared_key of its own, so the browser's grows
    # too. Leaving it alone would make the resumed hello hundreds of bytes
    # shorter than the capture.
    growth = getattr(profile, "ech_growth_for_psk", None)
    if growth is not None:
        extra = growth(_psk_extension_size(tickets, suite) + 4)
        kept = [
            Extension(e.type, grow_ech(e.data, extra, rng))
            if e.type == EXT_ENCRYPTED_CLIENT_HELLO else e
            for e in kept
        ]

    hello.extensions = kept
    record = serialise(hello, int.from_bytes(original[1:3], "big"))
    return _attach_psk(record, tickets, suite)


def _psk_extension_size(tickets, suite) -> int:
    """The pre_shared_key payload's size: identities, then binders."""
    identities = sum(2 + len(t.identity) + 4 for t in tickets)
    binders = sum(1 + suite.hash_size for _ in tickets)
    return 2 + identities + 2 + binders


def _attach_psk(record: bytes, tickets, suite, binder_context: bytes = b"") -> bytes:
    """Append a pre_shared_key offering `tickets`, binders filled in.

    The binders are an HMAC over the transcript up to where they begin, so
    the hello is serialised once with the right lengths and empty binders,
    hashed together with `binder_context` -- empty for a first hello, the
    first hello's hash and the HelloRetryRequest for a second one -- and the
    binders written into the space reserved for them. The ages are computed
    now, which on a second hello is the point.
    """
    from .keyschedule import psk_binder
    from .parser import parse_client_hello

    hello = parse_client_hello(record)
    identities = b"".join(
        vector(t.identity, 2) + t.obfuscated_age().to_bytes(4, "big")
        for t in tickets
    )
    placeholder = b"".join(vector(bytes(suite.hash_size), 1) for _ in tickets)
    psk = Extension(EXT_PRE_SHARED_KEY,
                    vector(identities, 2) + vector(placeholder, 2))
    hello.extensions = list(hello.extensions) + [psk]

    record = serialise(hello, int.from_bytes(record[1:3], "big"))
    message = record[5:]
    # The binders, and the two-byte length in front of them, are the tail.
    tail = 2 + len(placeholder)
    truncated = message[:-tail]

    binders = b"".join(
        vector(psk_binder(suite, t.psk, binder_context + truncated), 1)
        for t in tickets
    )
    if len(binders) != len(placeholder):
        raise ValueError("binders did not fill the space reserved for them")
    return record[:-len(binders)] + binders
