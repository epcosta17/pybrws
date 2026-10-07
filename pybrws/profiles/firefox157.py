"""Firefox 157.0, Windows 10/11, default settings.

Every constant is taken from fixtures/reference-firefox-157-windows.hex.
Payloads that vary per connection are produced by the functions at the bottom.
"""

from __future__ import annotations

from .. import headers as header_tools
from ..keyexchange import KeyExchange
from ..wire import u8, u16, vector

NAME = "firefox157"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0"
)

RECORD_VERSION = 0x0301
LEGACY_VERSION = 0x0303
SESSION_ID_SIZE = 32
COMPRESSION_METHODS = [0x00]

CIPHER_SUITES = [
    0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F,
    0xCCA9, 0xCCA8, 0xC02C, 0xC030, 0xC013,
    0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
]

# (group id, public key size) in the order Firefox offers them.
KEY_SHARE_GROUPS = [
    (0x11EC, 1216),  # X25519MLKEM768
    (0x001D, 32),    # x25519
    (0x0017, 65),    # secp256r1
]

# Greased ECH. kdf_id and the two sizes are fixed; aead_id and config_id are
# drawn per connection.
ECH_OUTER = 0x00
ECH_KDF_ID = 0x0001
ECH_AEAD_IDS = (0x0001, 0x0003)
ECH_ENC_SIZE = 32
ECH_PAYLOAD_SIZE = 240


def server_name(ctx) -> bytes:
    host = ctx.hostname.encode("idna")
    return vector(u8(0x00) + vector(host, 2), 2)


def key_share(ctx) -> bytes:
    if ctx.key_exchange is None:
        ctx.key_exchange = KeyExchange([group for group, _ in KEY_SHARE_GROUPS])
    entries = b""
    for (group, size), (offered, share) in zip(
        KEY_SHARE_GROUPS, ctx.key_exchange.client_shares()
    ):
        if offered != group or len(share) != size:
            raise ValueError(
                f"key_share for 0x{group:04x}: expected {size} bytes from "
                f"0x{offered:04x}, got {len(share)}"
            )
        entries += u16(group) + vector(share, 2)
    return vector(entries, 2)


def greased_ech(ctx) -> bytes:
    return (
        u8(ECH_OUTER)
        + u16(ECH_KDF_ID)
        + u16(ctx.choice(ECH_AEAD_IDS))
        + u8(ctx.random(1)[0])
        + vector(ctx.random(ECH_ENC_SIZE), 2)
        + vector(ctx.random(ECH_PAYLOAD_SIZE), 2)
    )


# Extension type and payload, in wire order. A callable is evaluated per
# connection; bytes are emitted verbatim.
EXTENSIONS: list[tuple[int, bytes | object]] = [
    (0, server_name),
    (23, b""),                                              # extended_master_secret
    (65281, bytes.fromhex("00")),                           # renegotiation_info
    (10, bytes.fromhex("000a11ec001d001700180019")),        # supported_groups
    (11, bytes.fromhex("0100")),                            # ec_point_formats
    (35, b""),                                              # session_ticket
    (16, bytes.fromhex("000c02683208687474702f312e31")),    # alpn: h2, http/1.1
    (5, bytes.fromhex("0100000000")),                       # status_request
    (34, bytes.fromhex("00080403050306030203")),            # delegated_credentials
    (18, b""),                                              # signed_certificate_timestamp
    (51, key_share),
    (43, bytes.fromhex("0403040303")),                      # supported_versions
    (13, bytes.fromhex("001604030503060308040805080604010501060102030201")),
    (45, bytes.fromhex("0101")),                            # psk_key_exchange_modes
    (28, bytes.fromhex("4001")),                            # record_size_limit
    (27, bytes.fromhex("06000100020003")),                  # compress_certificate
    (65037, greased_ech),
]


# --- HTTP/2 ---------------------------------------------------------------
# Measured from tls.peet.ws/api/all. Akamai fingerprint:
#   1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s

H2_SETTINGS = [
    (0x01, 65536),   # HEADER_TABLE_SIZE
    (0x02, 0),       # ENABLE_PUSH
    (0x04, 131072),  # INITIAL_WINDOW_SIZE
    (0x05, 16384),   # MAX_FRAME_SIZE
]
H2_CONNECTION_WINDOW_UPDATE = 12517377
H2_FIRST_STREAM_ID = 3

# Firefox carries priority in the HEADERS frame rather than separate PRIORITY
# frames, which is why the fingerprint's priority section is empty.
H2_HEADERS_PRIORITY = {"exclusive": False, "depends_on": 0, "weight": 42}

H2_PSEUDO_ORDER = (":method", ":path", ":authority", ":scheme")

# Request headers for a top-level navigation, in wire order.
H2_NAVIGATION_HEADERS = [
    ("user-agent", USER_AGENT),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("accept-language", "en-US,en;q=0.9"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("upgrade-insecure-requests", "1"),
    ("sec-fetch-dest", "document"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-site", "none"),
    ("sec-fetch-user", "?1"),
    ("priority", "u=0, i"),
    ("te", "trailers"),
]


# --- HTTP/1.1 -------------------------------------------------------------
# Order and capitalization are the fingerprint at this layer. Measured from
# fixtures/reference-firefox-157-h1.txt, a Firefox 157 navigation captured
# over TLS with tools/catch_request.py.
#
# A cleartext capture will not do: without a trustworthy origin Firefox omits
# the Sec-Fetch-* block and drops br and zstd from Accept-Encoding.
#
# Relative to H2_NAVIGATION_HEADERS this is the same sequence plus Host at the
# front and Connection after Accept-Encoding, minus the `te` header.

H1_HEADERS = [
    ("Host", "{authority}"),
    ("User-Agent", USER_AGENT),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Connection", "keep-alive"),
    ("Upgrade-Insecure-Requests", "1"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
    ("Priority", "u=0, i"),
]


# --- Cookies --------------------------------------------------------------
# Measured. fixtures/reference-firefox-157-cookie.txt is a Firefox navigation
# carrying two cookies: they travel in a single `Cookie` header with no
# crumbling, placed after Connection and before Upgrade-Insecure-Requests.
# A test asserts the generated request equals that capture byte for byte.
#
# The HTTP/2 anchor is inferred rather than measured, from the two orders
# being the same sequence apart from Host, Connection and te. Capturing it
# needs an HTTP/2 server, which tools/catch_request.py is not.
#
# Also unmeasured: whether HTTP/2 crumbles cookies into separate headers,
# which HPACK makes worthwhile.

H2_COOKIE_BEFORE = "upgrade-insecure-requests"
H1_COOKIE_BEFORE = "Upgrade-Insecure-Requests"


# Measured from fixtures/reference-firefox-157-post-form.txt and
# fixtures/reference-firefox-157-post-fetch.txt.
#
# The two differ in more than Content-Type. Accept, Priority and all three
# Sec-Fetch values change, Upgrade-Insecure-Requests appears only on the
# navigation, and Referer moves: before Content-Type for fetch, after
# Connection for the form. Content-Length always follows Content-Type and
# precedes Origin.
#
# Measured, and it settles the question the previous entry left open: a form
# submitted by a click carries `Sec-Fetch-User: ?1` and one submitted by
# script does not. Same bytes otherwise. So a form POST is two header sets,
# and which one is right depends on what is being imitated: a person
# pressing a button, or a page submitting on their behalf.
# fixtures/reference-firefox-157-post-click.txt is the clicked one.

H1_POST_FORM_SCRIPT_HEADERS = [
    ("Host", "{authority}"),
    ("User-Agent", USER_AGENT),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Content-Type", "{content_type}"),
    ("Content-Length", "{content_length}"),
    ("Origin", "{origin}"),
    ("Connection", "keep-alive"),
    ("Referer", "{referer}"),
    ("Upgrade-Insecure-Requests", "1"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "same-origin"),
    ("Priority", "u=0, i"),
]

H1_POST_XHR_HEADERS = [
    ("Host", "{authority}"),
    ("User-Agent", USER_AGENT),
    ("Accept", "*/*"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Referer", "{referer}"),
    ("Content-Type", "{content_type}"),
    ("Content-Length", "{content_length}"),
    ("Origin", "{origin}"),
    ("Connection", "keep-alive"),
    ("Sec-Fetch-Dest", "empty"),
    ("Sec-Fetch-Mode", "cors"),
    ("Sec-Fetch-Site", "same-origin"),
    ("Priority", "u=4"),
]


def _as_http2(headers):
    """Derive an HTTP/2 set from an HTTP/1.1 one.

    INFERRED, not measured. The rule is the one the navigation captures
    confirmed: drop Host and Connection, lowercase the names, append `te`.
    Capturing it directly needs an HTTP/2 server, which the capture tool is
    not.
    """
    dropped = {"host", "connection"}
    return [(name.lower(), value) for name, value in headers
            if name.lower() not in dropped] + [("te", "trailers")]


# A click adds one header; everything else is identical.
H1_POST_FORM_HEADERS = header_tools.insert_before(
    H1_POST_FORM_SCRIPT_HEADERS, "Sec-Fetch-User", "?1", "Priority"
)

H2_POST_FORM_SCRIPT_HEADERS = _as_http2(H1_POST_FORM_SCRIPT_HEADERS)
H2_POST_FORM_HEADERS = _as_http2(H1_POST_FORM_HEADERS)
H2_POST_XHR_HEADERS = _as_http2(H1_POST_XHR_HEADERS)
