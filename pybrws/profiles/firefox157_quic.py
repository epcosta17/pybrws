"""Firefox 157 on Windows, over QUIC.

A separate profile rather than a flag on the TCP one, because it is a
separate implementation: Firefox's QUIC is neqo, written in Rust, while its
TLS over TCP is NSS. The two do not agree about much.

Measured from fixtures/reference-firefox-157-quic.hex and five sibling
connections in the same capture. What differs from the TCP profile:

- Fifteen extensions, not seventeen. `ec_point_formats` and `session_ticket`
  follow TLS 1.2 being unavailable; `signed_certificate_timestamp` is simply
  absent, which does not follow from anything obvious.
- **The order is drawn per connection.** Six connections gave six distinct
  orders with identical sets. Only the last two are fixed:
  `quic_transport_parameters` then `encrypted_client_hello`. This is the
  opposite of the TCP profile, whose order is a measured constant.
- Three cipher suites, the TLS 1.3 ones only, since QUIC forbids TLS 1.2.
- An empty legacy session id. The TCP hello sends 32 bytes for middlebox
  compatibility, which QUIC has no need of.
- Five supported groups, against the TCP profile's six.
- `quic_transport_parameters`, which has no TCP equivalent: fourteen values
  in an order of the client's own, not sorted the way a library's are.
"""

from __future__ import annotations

import os
from typing import Callable

from ..wire import u8, u16, vector

# QUIC requires TLS 1.3, so the TLS 1.2 suites the TCP profile offers are not
# merely unnecessary here, they would be wrong. A client sending fifteen
# suites over QUIC has not thought about the protocol.
NAME = "firefox157_quic"

CIPHER_SUITES = (0x1301, 0x1303, 0x1302)

# Empty, where the TCP profile sends 32 bytes.
SESSION_ID_SIZE = 0

# The client's own connection id, three bytes. aioquic defaults to eight,
# which showed up as a five-byte difference in the transport parameters
# extension and nowhere else -- the sort of thing that is invisible until
# something is compared byte for byte.
#
# Measured once, from the one connection whose parameter values were read
# out. Whether neqo always uses three bytes is not established; a capture
# with several connections' ids compared would settle it.
CONNECTION_ID_SIZE = 3

# The client's *initial destination* connection id is a different length from
# its source id, and aioquic uses one setting for both. RFC 9000 section 7.2
# requires the initial destination id to be at least 8 bytes, since it is what
# seeds the Initial keys and an attacker who can guess it can forge packets.
# Three bytes is a protocol violation: Cloudflare tolerated it and Google
# dropped every Initial without a word, which is the correct response.
#
# Eight is the mandated floor, not a measurement. What Firefox actually picks
# is not in the ClientHello, so reading it needs the packet headers from a
# capture rather than the handshake.
INITIAL_DESTINATION_ID_SIZE = 8

# The limits the transport parameters advertise, in the units aioquic's
# configuration wants them. These are not decoration: a client that announces
# a 24 MB connection window and then enforces 1 MB is lying about itself in a
# way that shows up as stalled streams rather than as a fingerprint.
IDLE_TIMEOUT_SECONDS = 30.0          # max_idle_timeout, 30000 ms
MAX_DATA = 25165824                  # initial_max_data
MAX_STREAM_DATA = 12582912           # initial_max_stream_data_bidi_local
MAX_DATAGRAM_FRAME_SIZE = 65535      # max_datagram_frame_size
ALPN_PROTOCOLS = ("h3",)

LEGACY_COMPRESSION_METHODS = (0x00,)

# X25519MLKEM768 first, then the classical ones. No GREASE group, which the
# TCP profile does send.
SUPPORTED_GROUPS = (0x11EC, 0x001D, 0x0017, 0x0018, 0x0019)

# Sizes of the key_share entries, which is what makes a QUIC hello 1900 bytes
# rather than 500: the post-quantum share alone is 1216, and there are three
# shares, not one. 1216 + 32 + 65, with four bytes of header each and two for
# the list, is the 1327-byte extension the capture carries.
#
# Three offered shares is itself notable: the client is paying 1.2 kB to let
# the server pick without a round trip, which is why the hello needs two
# datagrams and why HelloRetryRequest is rare in practice.
KEY_SHARE_GROUPS = ((0x11EC, 1216), (0x001D, 32), (0x0017, 65))

EXT_SERVER_NAME = 0
EXT_STATUS_REQUEST = 5
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_EXTENDED_MASTER_SECRET = 23
EXT_COMPRESS_CERTIFICATE = 27
EXT_RECORD_SIZE_LIMIT = 28
EXT_DELEGATED_CREDENTIALS = 34
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_KEY_SHARE = 51
EXT_QUIC_TRANSPORT_PARAMETERS = 57
EXT_ENCRYPTED_CLIENT_HELLO = 65037
EXT_RENEGOTIATION_INFO = 65281

# The payloads that do not change between connections, exactly as captured.
# A test asserts each against the fixture; a measured constant without one is
# a constant that can be deleted without the suite objecting.
STATIC_PAYLOADS: dict[int, bytes] = {
    EXT_STATUS_REQUEST: bytes.fromhex("0100000000"),
    EXT_SUPPORTED_GROUPS: bytes.fromhex("000a11ec001d001700180019"),
    EXT_SIGNATURE_ALGORITHMS: bytes.fromhex(
        "001604030503060302030804080508060401050106010201"),
    EXT_ALPN: bytes.fromhex("0003026833"),            # h3
    EXT_EXTENDED_MASTER_SECRET: b"",
    EXT_COMPRESS_CERTIFICATE: bytes.fromhex("06000100030002"),
    EXT_RECORD_SIZE_LIMIT: bytes.fromhex("4001"),
    EXT_DELEGATED_CREDENTIALS: bytes.fromhex("00080403050306030203"),
    EXT_SUPPORTED_VERSIONS: bytes.fromhex("020304"),  # TLS 1.3 alone
    EXT_PSK_KEY_EXCHANGE_MODES: bytes.fromhex("0101"),
    EXT_RENEGOTIATION_INFO: bytes.fromhex("00"),
}

# Drawn per connection, so not constants: server_name follows the host,
# key_share follows the keys, the transport parameters carry the connection's
# own id, and the ECH payload is random.
PER_CONNECTION = (EXT_SERVER_NAME, EXT_KEY_SHARE,
                  EXT_QUIC_TRANSPORT_PARAMETERS, EXT_ENCRYPTED_CLIENT_HELLO)

# Always last, in this order, in all six captured connections.
PINNED_TAIL = (EXT_QUIC_TRANSPORT_PARAMETERS, EXT_ENCRYPTED_CLIENT_HELLO)

# Everything else, shuffled. Listed sorted so the source is readable; the
# order here is never what goes on the wire.
SHUFFLED = tuple(sorted(set(STATIC_PAYLOADS) | {EXT_SERVER_NAME, EXT_KEY_SHARE}))

EXTENSION_SET = frozenset(SHUFFLED) | frozenset(PINNED_TAIL)


def extension_order(rng: Callable[[int], bytes] = os.urandom) -> list[int]:
    """One connection's extension order.

    Thirteen shuffled, then the pinned two. Firefox draws a fresh order every
    time, so storing one would reproduce a sample rather than the behaviour:
    a server that sees the same order twice from two connections learns more
    from that than from the order itself.

    A Fisher-Yates shuffle driven by `rng` rather than `random.shuffle`, so a
    test can replay a draw and the profile never touches global state.
    """
    order = list(SHUFFLED)
    for index in range(len(order) - 1, 0, -1):
        pick = _below(rng, index + 1)
        order[index], order[pick] = order[pick], order[index]
    return order + list(PINNED_TAIL)


def _below(rng: Callable[[int], bytes], limit: int) -> int:
    """A uniform integer in [0, limit), by rejection.

    Taking a modulus would bias the low indices, which for thirteen items is
    a measurable skew over enough connections -- and a skew is a fingerprint.
    """
    if limit <= 1:
        return 0
    span = 256 - (256 % limit)
    while True:
        draw = rng(1)[0]
        if draw < span:
            return draw % limit


# quic_transport_parameters, in the captured order. Not sorted by id: 0x1d
# and 0xff02de1a come before 0x20, which is a choice a library would not make
# and aioquic does not.
#
# 0xff02de1a is constant across all six connections and carries the varint
# 1000. It satisfies the 31N+27 reserved pattern, so a decoder calls it
# GREASE, but a value that never changes is not greasing and 1000 is a
# plausible min_ack_delay -- whose registered codepoint, 0xff04de1b, is one
# of a family of 0xff0?de1? drafts. Copied as measured; not identified.
TRANSPORT_PARAMETERS: tuple[tuple[int, bytes], ...] = (
    (0x01, bytes.fromhex("80007530")),      # max_idle_timeout, 30000
    (0x04, bytes.fromhex("81800000")),      # initial_max_data, 25165824
    (0x05, bytes.fromhex("80c00000")),      # bidi_local, 12582912
    (0x06, bytes.fromhex("80100000")),      # bidi_remote, 1048576
    (0x07, bytes.fromhex("80100000")),      # uni, 1048576
    (0x08, bytes.fromhex("4064")),          # initial_max_streams_bidi, 100
    (0x09, bytes.fromhex("4064")),          # initial_max_streams_uni, 100
    (0x0B, bytes.fromhex("14")),            # max_ack_delay, 20
    (0x0E, bytes.fromhex("08")),            # active_connection_id_limit, 8
    (0x0F, b""),                            # initial_source_connection_id
    (0x11, bytes.fromhex("000000011aea6a5a6b3343cf00000001")),
    (0x1D, b""),                            # reset_stream_at, present/absent
    (0xFF02DE1A, bytes.fromhex("43e8")),
    (0x20, bytes.fromhex("8000ffff")),      # max_datagram_frame_size, 65535
)

# The one parameter whose value belongs to the connection rather than to the
# profile: it must be the source connection id actually in use, or the peer
# rejects the handshake.
PARAMETER_SOURCE_CONNECTION_ID = 0x0F

# version_information, decoded: chosen version 1, then available versions
# 0x1aea6a5a, 0x6b3343cf (QUIC v2, RFC 9369) and 0x00000001. The first
# available looks like a greased version and may well be drawn per
# connection; one capture cannot say, so it is copied and marked.
VERSION_INFORMATION_MAY_VARY = True


def _varint(value: int) -> bytes:
    """A QUIC variable-length integer, in the shortest form that fits."""
    if value < 0:
        raise ValueError("a transport parameter id cannot be negative")
    for size, prefix, ceiling in ((1, 0x00, 1 << 6), (2, 0x40, 1 << 14),
                                  (4, 0x80, 1 << 30), (8, 0xC0, 1 << 62)):
        if value < ceiling:
            encoded = value.to_bytes(size, "big")
            return bytes([encoded[0] | prefix]) + encoded[1:]
    raise ValueError("%d does not fit in a QUIC varint" % value)


def transport_parameters(connection_id: bytes) -> bytes:
    """The extension payload, with the connection's own id filled in."""
    out = bytearray()
    for identifier, value in TRANSPORT_PARAMETERS:
        if identifier == PARAMETER_SOURCE_CONNECTION_ID:
            value = connection_id
        out += _varint(identifier) + _varint(len(value)) + value
    return bytes(out)


# Greased ECH, as on TCP: the same fixed payload size, which the capture
# confirms at 240 bytes over QUIC too.
ECH_OUTER = 0x00
ECH_KDF_ID = 0x0001
ECH_AEAD_IDS = (0x0001, 0x0003)
ECH_ENC_SIZE = 32
ECH_PAYLOAD_SIZE = 240


def greased_ech(rng: Callable[[int], bytes] = os.urandom) -> bytes:
    return (
        u8(ECH_OUTER)
        + u16(ECH_KDF_ID)
        + u16(ECH_AEAD_IDS[rng(1)[0] % len(ECH_AEAD_IDS)])
        + u8(rng(1)[0])
        + vector(rng(ECH_ENC_SIZE), 2)
        + vector(rng(ECH_PAYLOAD_SIZE), 2)
    )


def server_name(hostname: str) -> bytes:
    host = hostname.encode("idna")
    return vector(u8(0x00) + vector(host, 2), 2)


# --- the HTTP/3 request ------------------------------------------------------
#
# Measured, from fixtures/reference-firefox-157-quic-request.txt. Getting it
# needed Firefox's own SSLKEYLOGFILE: a request travels under handshake keys,
# so unlike a ClientHello it cannot be read out of a capture on its own.
#
# The pseudo-header order is NOT the HTTP/2 one. Over TCP Firefox sends
#   :method :path :authority :scheme
# and over QUIC it sends
#   :method :scheme :authority :path
# which is the same lesson as the shuffled extension order: neqo is not NSS,
# and nothing measured on one of Firefox's stacks transfers to the other
# without being measured again. This project had quietly assumed otherwise,
# and curl_cffi had it right.
H3_PSEUDO_ORDER = (":method", ":scheme", ":authority", ":path")

# The header set is the HTTP/2 navigation set with two changes: `te` is gone,
# which follows from `te: trailers` being an HTTP/2 mechanism, and `alt-used`
# appears after accept-encoding.
#
# `alt-used` carries the authority and is RFC 7838: a client sends it when it
# reached the origin through an alternative service, which is how a browser
# gets to HTTP/3 at all -- Alt-Svc on an earlier TCP connection. A client
# that dials h3 directly, as this one does, has not technically used an
# alternative service. It is included because it is what was measured and
# because the direct path is itself the unusual thing; whether Firefox omits
# it when an HTTPS DNS record sends it straight to h3 is not measured.
H3_ALT_USED = "Alt-Used"

H3_NAVIGATION_HEADERS: tuple[tuple[str, str], ...] = (
    ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) "
                   "Gecko/20100101 Firefox/157.0"),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    (H3_ALT_USED, ""),                  # filled with the authority per request
    ("Upgrade-Insecure-Requests", "1"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
    ("Priority", "u=0, i"),
)


def navigation_headers(authority: str) -> list[tuple[str, str]]:
    """The measured navigation set, with alt-used carrying the authority."""
    return [(name, authority if name == H3_ALT_USED else value)
            for name, value in H3_NAVIGATION_HEADERS]
