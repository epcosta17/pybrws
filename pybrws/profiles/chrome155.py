"""Chrome 155 on Windows.

The second browser, and the first test of whether `profiles/` is an
abstraction or Firefox with extra steps. It is an abstraction now, but it had
to change to become one: Chrome draws its extension order per connection, so
a profile cannot be an ordered list, and it greases six separate lists, so the
emitter had to learn that a cipher list can be a function of the connection.

Measured from six ClientHello captures in one run of `catch_hello.py
--count 6`, plus `catch_h2.py` and `catch_request.py`. What differs from
Firefox is nearly everything:

- **The extension order is drawn**, with a greased extension pinned at each
  end and the other eighteen shuffled between them. Six captures gave six
  orders and one set.
- **Six greased lists**, each with the value at the head: the cipher suites,
  `signature_algorithms`, `supported_groups`, `supported_versions`, the
  `key_share`, and both ends of the extension list. Five are independent
  draws; `supported_groups` and `key_share` share one, measured identical in
  all six, which the protocol requires -- the key_share entry has to name a
  group the client offered.
- **Three codepoints IANA has not assigned**: `application_settings`
  (0x44cd), a constant 186-byte list of five-byte identifiers at 0xca34 whose
  shape matches trust anchor ids, and two constant bytes at 0x12e0 whose
  purpose is unknown. Named here from their shape, not from a standard.
- **A different HTTP/2 fingerprint in every field.** Not one value matches
  Firefox's, down to which settings are sent at all.
- **Mixed header casing over HTTP/1.1.** The client hints are lower case and
  everything else is capitalised, which is a fingerprint and not a style.

Not measured, and so not here: resumption, HelloRetryRequest, the image and
cookie-carrying request variants, and anything over QUIC. Chrome's QUIC
hello was seen once in a capture that was taken for Firefox -- eleven
extensions and Google transport parameters -- and that is all.
"""

from __future__ import annotations

import os
from typing import Callable

from .. import headers as header_tools
from ..keyexchange import KeyExchange
from ..model import GREASE_DRAW
from ..wire import u8, u16, vector

LEGACY_VERSION = 0x0303
RECORD_VERSION = 0x0301
SESSION_ID_SIZE = 32
COMPRESSION_METHODS = (0x00,)

# Fifteen real suites with a greased one at the head. Firefox offers the same
# fifteen in a different order and without the GREASE.
REAL_CIPHER_SUITES = (
    0x1301, 0x1302, 0x1303,
    0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
    0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
)

# Five groups behind the greased one. No secp521r1, which Firefox offers.
REAL_SUPPORTED_GROUPS = (0x11EC, 0x001D, 0x0017, 0x0018)

# The post-quantum share and x25519. Firefox sends a third, secp256r1, which
# is why its key_share is 1327 bytes against this one's 1263.
KEY_SHARE_GROUPS = ((0x11EC, 1216), (0x001D, 32))

REAL_SUPPORTED_VERSIONS = (0x0304, 0x0303)

EXT_SERVER_NAME = 0
EXT_STATUS_REQUEST = 5
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_SIGNED_CERTIFICATE_TIMESTAMP = 18
EXT_EXTENDED_MASTER_SECRET = 23
EXT_COMPRESS_CERTIFICATE = 27
EXT_SESSION_TICKET = 35
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_KEY_SHARE = 51
EXT_CHROME_0X12E0 = 4832
EXT_APPLICATION_SETTINGS = 17613
EXT_TRUST_ANCHORS = 51764
EXT_ENCRYPTED_CLIENT_HELLO = 65037
EXT_RENEGOTIATION_INFO = 65281

# Payloads identical across all six captures, byte for byte.
STATIC_PAYLOADS: dict[int, bytes] = {
    EXT_STATUS_REQUEST: bytes.fromhex("0100000000"),
    EXT_EC_POINT_FORMATS: bytes.fromhex("0100"),
    EXT_ALPN: bytes.fromhex("000c02683208687474702f312e31"),   # h2, http/1.1
    EXT_SIGNED_CERTIFICATE_TIMESTAMP: b"",
    EXT_EXTENDED_MASTER_SECRET: b"",
    # Brotli alone. Firefox offers zlib, zstd and brotli.
    EXT_COMPRESS_CERTIFICATE: bytes.fromhex("020002"),
    EXT_SESSION_TICKET: b"",
    EXT_PSK_KEY_EXCHANGE_MODES: bytes.fromhex("0101"),
    EXT_APPLICATION_SETTINGS: bytes.fromhex("0003026832"),      # h2
    EXT_CHROME_0X12E0: bytes.fromhex("36b0"),
    EXT_RENEGOTIATION_INFO: bytes.fromhex("00"),
    # 0xca34. A two-byte length then a list of five-byte identifiers, each
    # `82df1302` plus one varying byte. Identical in all six captures, so it
    # is a property of the build rather than of the connection.
    EXT_TRUST_ANCHORS: bytes.fromhex(
        "00b80582df1302010582df1302060582df13020d0582df13"
        "020e0582df13020f0582df1302120582df1302130582df13"
        "021408839a648c9b2d010708839a648c9b2d010808839a64"
        "8c9b2d010908839a648c9b2d010a08839a648c9b2d010b08"
        "839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d"
        "011208839a648c9b2d011304d679090104d679090404d679"
        "090504d679090604d679090704d679090804d679090a04d6"
        "79090b04d679090c04d679090d04d679090f"
    ),
}

# The real signature algorithms, behind a greased one. The first three are
# not in the TLS 1.3 registry's common set and are copied as measured.
REAL_SIGNATURE_ALGORITHMS = (
    0x0904, 0x0905, 0x0906,
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
)

# Always first and always last, with an independent greased value each.
PINNED_FIRST = "extension_first"
PINNED_LAST = "extension_last"

SHUFFLED = (
    EXT_SERVER_NAME, EXT_STATUS_REQUEST, EXT_SUPPORTED_GROUPS,
    EXT_EC_POINT_FORMATS, EXT_SIGNATURE_ALGORITHMS, EXT_ALPN,
    EXT_SIGNED_CERTIFICATE_TIMESTAMP, EXT_EXTENDED_MASTER_SECRET,
    EXT_COMPRESS_CERTIFICATE, EXT_SESSION_TICKET, EXT_SUPPORTED_VERSIONS,
    EXT_PSK_KEY_EXCHANGE_MODES, EXT_KEY_SHARE, EXT_CHROME_0X12E0,
    EXT_APPLICATION_SETTINGS, EXT_TRUST_ANCHORS, EXT_ENCRYPTED_CLIENT_HELLO,
    EXT_RENEGOTIATION_INFO,
)

# Greased ECH. kdf and aead are fixed, unlike Firefox which draws the aead;
# config_id and the payload are random, and the payload *length* varies.
ECH_OUTER = 0x00
ECH_KDF_ID = 0x0001
ECH_AEAD_ID = 0x0001
ECH_ENC_SIZE = 32

# Observed payload lengths across six captures: 144 twice, 208 three times,
# 240 once. The rest of the hello measured exactly 1751 bytes every time, so
# this is the only thing moving the total. Six samples cannot establish the
# set or the distribution, so this is a draw over what was seen and is marked
# as undermeasured. More captures of the hello alone would settle it.
ECH_PAYLOAD_SIZES = (144, 208, 240)

# Two constants, not one, because they are two different facts.
#
# CAPTURED_ACCEPT_LANGUAGE is what the capture holds, and the fixture tests
# compare against it. It is the locale of the machine the capture was taken
# on, which makes it a fingerprint of a person rather than of a browser:
# shipping it would mark every request as coming from one particular Chrome
# in Mexico.
#
# ACCEPT_LANGUAGE is what this profile actually sends. The common default,
# which is the point -- a header meant to blend in should not be unusual.
# Overwriting the captured value with it would have lost the measurement and
# quietly broken the comparison the tests do.
CAPTURED_ACCEPT_LANGUAGE = "en-MX,en-GB;q=0.9,en-US;q=0.8,en;q=0.7"
ACCEPT_LANGUAGE = "en-US,en;q=0.9"

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
SEC_CH_UA = ('"Google Chrome";v="155", "Chromium";v="155", '
             '"Not(A:Brand";v="24"')
ACCEPT_NAVIGATION = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,"
    "image/avif,image/webp,image/apng,*/*;q=0.8,"
    "application/signed-exchange;v=b3;q=0.7"
)


# -- the hello ---------------------------------------------------------------


def CIPHER_SUITES(ctx) -> tuple[int, ...]:
    return (ctx.grease("cipher"),) + REAL_CIPHER_SUITES


def pinned_pair(ctx) -> tuple[int, int]:
    """The two greased extension types, guaranteed to differ.

    RFC 8446 section 4.2 forbids a ClientHello from carrying the same
    extension type twice, so the two draws cannot be allowed to collide --
    which they do one time in sixteen. The six captures never show a
    collision, as they cannot.

    Getting this wrong produced a hello one byte shorter than any captured
    one, because the two pinned extensions carry different payloads and the
    collision made both take the first one's. A length no capture shows is
    the cheapest possible tell.

    Deterministic for a given context: the draws are memoised, so calling
    this twice gives the same pair.
    """
    first = ctx.grease(PINNED_FIRST)
    # Drawn from the fifteen that are not `first`, rather than redrawn until
    # it happens to differ. Redrawing works with a real rng and hangs or
    # raises with a fixed one, and a fixed one is exactly what replaying a
    # capture uses.
    others = tuple(value for value in GREASE_DRAW if value != first)
    last = ctx.once(PINNED_LAST, lambda: others[_below(ctx, len(others))])
    return first, last


def extension_order(ctx) -> list[int]:
    """One connection's order: greased, eighteen drawn, greased.

    Six captures gave six distinct orders over one set, so storing an order
    would record a sample as though it were a constant. A server that sees
    the same order from two connections learns more from that than from the
    order itself.
    """
    drawn = list(SHUFFLED)
    for index in range(len(drawn) - 1, 0, -1):
        pick = _below(ctx, index + 1)
        drawn[index], drawn[pick] = drawn[pick], drawn[index]
    first, last = pinned_pair(ctx)
    return [first] + drawn + [last]


def _below(ctx, limit: int) -> int:
    """A uniform integer in [0, limit), by rejection.

    A modulus over a byte biases the low indices, and over eighteen items
    that skew is measurable across enough connections -- and a skew is itself
    a fingerprint.
    """
    if limit <= 1:
        return 0
    span = 256 - (256 % limit)
    # Bounded: an rng that only ever returns a rejected byte would otherwise
    # spin forever, and a test rng can do exactly that. Sixty-four tries make
    # the fallback vanishingly unlikely with real randomness, and turn a hang
    # into a slightly biased answer with the pathological kind.
    for _ in range(64):
        draw = ctx.random(1)[0]
        if draw < span:
            return draw % limit
    return ctx.random(1)[0] % limit


def payload_for(kind: int, ctx) -> bytes:
    if kind in STATIC_PAYLOADS:
        return STATIC_PAYLOADS[kind]
    if kind in GREASE_DRAW:
        # The first greased extension is empty and the last carries one zero
        # byte, in all six captures. Distinguished through pinned_pair rather
        # than by comparing against the first draw alone, which got the last
        # one wrong whenever the two collided.
        first, _last = pinned_pair(ctx)
        return b"" if kind == first else b"\x00"
    if kind == EXT_SERVER_NAME:
        return server_name(ctx.hostname)
    if kind == EXT_SUPPORTED_GROUPS:
        groups = (ctx.grease("groups"),) + REAL_SUPPORTED_GROUPS
        return vector(b"".join(u16(g) for g in groups), 2)
    if kind == EXT_SIGNATURE_ALGORITHMS:
        schemes = (ctx.grease("signature_algorithms"),) + REAL_SIGNATURE_ALGORITHMS
        return vector(b"".join(u16(s) for s in schemes), 2)
    if kind == EXT_SUPPORTED_VERSIONS:
        versions = (ctx.grease("versions"),) + REAL_SUPPORTED_VERSIONS
        return vector(b"".join(u16(v) for v in versions), 1)
    if kind == EXT_KEY_SHARE:
        return key_share(ctx)
    if kind == EXT_ENCRYPTED_CLIENT_HELLO:
        return greased_ech(ctx)
    raise ValueError("chrome155 has no payload for extension %d" % kind)


def server_name(hostname: str) -> bytes:
    host = hostname.encode("idna")
    return vector(u8(0x00) + vector(host, 2), 2)


def key_share(ctx) -> bytes:
    """The greased entry, then the real shares.

    The greased group is the same value `supported_groups` used: a key_share
    for a group that was never offered is a protocol error, and Chrome does
    not make it.
    """
    if ctx.key_exchange is None:
        ctx.key_exchange = KeyExchange([group for group, _ in KEY_SHARE_GROUPS])
    entries = u16(ctx.grease("groups")) + vector(b"\x00", 2)
    for (group, size), (offered, share) in zip(KEY_SHARE_GROUPS,
                                               ctx.key_exchange.client_shares()):
        if offered != group or len(share) != size:
            raise ValueError(
                "key_share for 0x%04x: expected %d bytes from 0x%04x, got %d"
                % (group, size, offered, len(share))
            )
        entries += u16(group) + vector(share, 2)
    return vector(entries, 2)


def greased_ech(ctx) -> bytes:
    size = ECH_PAYLOAD_SIZES[ctx.random(1)[0] % len(ECH_PAYLOAD_SIZES)]
    return (
        u8(ECH_OUTER)
        + u16(ECH_KDF_ID)
        + u16(ECH_AEAD_ID)
        + u8(ctx.random(1)[0])
        + vector(ctx.random(ECH_ENC_SIZE), 2)
        + vector(ctx.random(size), 2)
    )


# -- HTTP/2 ------------------------------------------------------------------

# Not one of these matches Firefox, down to which settings are sent: Chrome
# sends 6 (max header list size) where Firefox sends 5 (max frame size).
H2_SETTINGS = ((1, 65536), (2, 0), (4, 6291456), (6, 262144))
H2_CONNECTION_WINDOW_UPDATE = 15663105
H2_FIRST_STREAM_ID = 1
H2_HEADERS_PRIORITY = {"exclusive": True, "depends_on": 0, "weight": 256}
H2_PSEUDO_ORDER = (":method", ":authority", ":scheme", ":path")

H2_NAVIGATION_HEADERS: tuple[tuple[str, str], ...] = (
    ("cache-control", "max-age=0"),
    ("sec-ch-ua", SEC_CH_UA),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", '"Windows"'),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", USER_AGENT),
    ("accept", ACCEPT_NAVIGATION),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-user", "?1"),
    ("sec-fetch-dest", "document"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("accept-language", ACCEPT_LANGUAGE),
    ("priority", "u=0, i"),
)

# -- HTTP/1.1 ----------------------------------------------------------------

# The casing is measured, not chosen. Chrome sends its client hints in lower
# case and everything else capitalised, which a client that normalises either
# way gets wrong.
H1_HEADERS: tuple[tuple[str, str], ...] = (
    ("Host", "{authority}"),
    ("Connection", "keep-alive"),
    ("Cache-Control", "max-age=0"),
    ("sec-ch-ua", SEC_CH_UA),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", '"Windows"'),
    ("Upgrade-Insecure-Requests", "1"),
    ("User-Agent", USER_AGENT),
    ("Accept", ACCEPT_NAVIGATION),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-User", "?1"),
    ("Sec-Fetch-Dest", "document"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Accept-Language", ACCEPT_LANGUAGE),
)

# A `fetch` POST. The client hints are interleaved with the ordinary headers
# rather than grouped, which is the kind of thing only a capture gives you:
# platform, then User-Agent, then sec-ch-ua, then Content-Type, then mobile.
H1_POST_XHR_HEADERS: tuple[tuple[str, str], ...] = (
    ("Host", "{authority}"),
    ("Connection", "keep-alive"),
    ("Content-Length", "{content_length}"),
    ("sec-ch-ua-platform", '"Windows"'),
    ("User-Agent", USER_AGENT),
    ("sec-ch-ua", SEC_CH_UA),
    ("Content-Type", "{content_type}"),
    ("sec-ch-ua-mobile", "?0"),
    ("Accept", "*/*"),
    ("Origin", "{origin}"),
    ("Sec-Fetch-Site", "same-origin"),
    ("Sec-Fetch-Mode", "cors"),
    ("Sec-Fetch-Dest", "empty"),
    ("Referer", "{referer}"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Accept-Language", ACCEPT_LANGUAGE),
)


ACCEPT_IMAGE = ("image/jxl,image/avif,image/webp,image/apng,image/svg+xml,"
                "image/*,*/*;q=0.8")

# A form POST submitted by script. A form POST is a navigation, so
# Sec-Fetch-Mode is `navigate` and Sec-Fetch-Dest `document`, where the
# `fetch` POST says `cors` and `empty`.
H1_POST_FORM_SCRIPT_HEADERS: tuple[tuple[str, str], ...] = (
    ("Host", "{authority}"),
    ("Connection", "keep-alive"),
    ("Content-Length", "{content_length}"),
    ("Cache-Control", "max-age=0"),
    ("sec-ch-ua", SEC_CH_UA),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", '"Windows"'),
    ("Upgrade-Insecure-Requests", "1"),
    ("Content-Type", "{content_type}"),
    ("User-Agent", USER_AGENT),
    ("Origin", "{origin}"),
    ("Accept", ACCEPT_NAVIGATION),
    ("Sec-Fetch-Site", "same-origin"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Dest", "document"),
    ("Referer", "{referer}"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Accept-Language", ACCEPT_LANGUAGE),
)

# A real click adds exactly one header and changes nothing else, which the
# two captures were compared field by field to establish. Firefox behaves the
# same way, with a different anchor.
H1_POST_FORM_HEADERS = tuple(header_tools.insert_before(
    H1_POST_FORM_SCRIPT_HEADERS, "Sec-Fetch-User", "?1", "Sec-Fetch-Dest"))

# Measured, replacing a derivation that got two things wrong: it omitted the
# priority header, which Chrome's HTTP/1.1 POST has no equivalent of, and it
# could not know where a cookie goes.
H2_POST_XHR_HEADERS: tuple[tuple[str, str], ...] = (
    ("content-length", "{content_length}"),
    ("sec-ch-ua-platform", '"Windows"'),
    ("user-agent", USER_AGENT),
    ("sec-ch-ua", SEC_CH_UA),
    ("content-type", "{content_type}"),
    ("sec-ch-ua-mobile", "?0"),
    ("accept", "*/*"),
    ("origin", "{origin}"),
    ("sec-fetch-site", "same-origin"),
    ("sec-fetch-mode", "cors"),
    ("sec-fetch-dest", "empty"),
    ("referer", "{referer}"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("accept-language", ACCEPT_LANGUAGE),
    ("priority", "u=1, i"),
)

# An image subresource over HTTP/2. Four Sec-Fetch and Accept values differ
# from a navigation, and `priority` is a bare `i` with no `u=`.
H2_IMAGE_HEADERS: tuple[tuple[str, str], ...] = (
    ("sec-ch-ua-platform", '"Windows"'),
    ("user-agent", USER_AGENT),
    ("sec-ch-ua", SEC_CH_UA),
    ("sec-ch-ua-mobile", "?0"),
    ("accept", ACCEPT_IMAGE),
    ("sec-fetch-site", "same-origin"),
    ("sec-fetch-mode", "no-cors"),
    ("sec-fetch-dest", "image"),
    ("referer", "{referer}"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("accept-language", ACCEPT_LANGUAGE),
    ("priority", "i"),
)

# Where a cookie goes. Over HTTP/2 it precedes `priority`, and as with
# Firefox there is one `cookie` field per cookie rather than one joined
# header. Over HTTP/1.1 it is last, after Accept-Language, so there is
# nothing for it to precede -- hence None, which `insert_before` reads as the
# end.
H2_COOKIE_BEFORE = "priority"
H1_COOKIE_BEFORE = None

# Still not measured, and absent rather than guessed: an image subresource
# over HTTP/1.1, and a form POST over HTTP/2 either way.
#
# The HTTP/1.1 image capture was attempted and failed -- `--any-request`
# returned the document again, byte-identical to the navigation capture, so
# there was nothing to record. Over HTTP/2 the same flag worked, which is the
# difference between a tool that selects on sec-fetch-dest and one that
# happened to see the document first.
UNMEASURED = (
    "H1_IMAGE_HEADERS",
    "H2_POST_FORM_HEADERS", "H2_POST_FORM_SCRIPT_HEADERS",
)
