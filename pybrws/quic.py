"""Reading QUIC Initial packets, which anyone can decrypt.

QUIC does not run over TLS, it carries TLS 1.3 inside. The handshake travels
in CRYPTO frames inside Initial packets, and those packets are protected with
keys derived from a salt printed in RFC 9001 section 5.2 and the connection ID
that is right there in the header. Nothing secret goes into them, so an
observer -- or a fingerprinting service -- reads the ClientHello as easily as
it reads one off TCP. That is the whole reason this module exists: to see what
a browser sends over QUIC without needing the browser to trust anything.

What is implemented is the client's first flight: removing header protection,
decrypting the payload, and reassembling the CRYPTO stream. A ClientHello is
larger than the 1200-byte datagram QUIC starts with, so it always arrives in
at least two packets and reassembly is not optional.

References are to RFC 9000 (transport) and RFC 9001 (TLS), named per function.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .keyschedule import CIPHER_SUITES, hkdf_expand_label, hkdf_extract

# RFC 9001 section 5.2. Version 1 only; a different version uses a different
# salt, and v2 exists, so the version is checked rather than assumed.
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
VERSION_1 = 0x00000001

# Initial packets always use TLS_AES_128_GCM_SHA256 (RFC 9001 section 5.2),
# whatever the ClientHello goes on to offer.
INITIAL_SUITE = CIPHER_SUITES[0x1301]
KEY_SIZE = 16
IV_SIZE = 12
SAMPLE_SIZE = 16
TAG_SIZE = 16

LONG_HEADER = 0x80
FIXED_BIT = 0x40
PACKET_TYPE_MASK = 0x30
TYPE_INITIAL = 0x00

FRAME_PADDING = 0x00
FRAME_PING = 0x01
FRAME_ACK = 0x02
FRAME_ACK_ECN = 0x03
FRAME_CRYPTO = 0x06
FRAME_CONNECTION_CLOSE = 0x1C

HANDSHAKE_CLIENT_HELLO = 0x01


class QuicError(Exception):
    pass


def varint(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a variable-length integer. RFC 9000 section 16.

    The top two bits of the first byte say how many bytes the whole thing
    takes, and the remaining bits are part of the value.

    Returns:
        The value and the offset just past it.
    """
    if offset >= len(data):
        raise QuicError("truncated varint")
    prefix = data[offset] >> 6
    length = 1 << prefix
    if offset + length > len(data):
        raise QuicError("varint runs past the end of the packet")
    value = data[offset] & 0x3F
    for index in range(1, length):
        value = (value << 8) | data[offset + index]
    return value, offset + length


@dataclass
class InitialKeys:
    """One direction's Initial keys. RFC 9001 section 5.2."""

    key: bytes
    iv: bytes
    header_protection: bytes

    @classmethod
    def derive(cls, connection_id: bytes, *, client: bool = True) -> "InitialKeys":
        """Derive from the client's original destination connection ID.

        Both directions come from the same secret, which is extracted from a
        published salt and a connection ID the header carries in the clear.
        That is what makes these packets readable by anyone.
        """
        initial = hkdf_extract(INITIAL_SUITE, INITIAL_SALT_V1, connection_id)
        label = b"client in" if client else b"server in"
        secret = hkdf_expand_label(INITIAL_SUITE, initial, label, b"",
                                   INITIAL_SUITE.hash_size)
        return cls(
            key=hkdf_expand_label(INITIAL_SUITE, secret, b"quic key", b"", KEY_SIZE),
            iv=hkdf_expand_label(INITIAL_SUITE, secret, b"quic iv", b"", IV_SIZE),
            header_protection=hkdf_expand_label(
                INITIAL_SUITE, secret, b"quic hp", b"", KEY_SIZE
            ),
        )

    def mask(self, sample: bytes) -> bytes:
        """The header protection mask. RFC 9001 section 5.4.3.

        AES-128-ECB over a sample of the ciphertext. ECB is correct here and
        only here: it encrypts exactly one block and the output is used as a
        keystream, not as a mode of operation.
        """
        if len(sample) != SAMPLE_SIZE:
            raise QuicError("header protection needs a %d-byte sample"
                            % SAMPLE_SIZE)
        encryptor = Cipher(algorithms.AES(self.header_protection),
                           modes.ECB()).encryptor()
        return encryptor.update(sample) + encryptor.finalize()

    def nonce(self, packet_number: int) -> bytes:
        """The AEAD nonce: the IV with the packet number XORed into its tail."""
        counter = packet_number.to_bytes(IV_SIZE, "big")
        return bytes(a ^ b for a, b in zip(self.iv, counter))


@dataclass
class InitialPacket:
    """One decrypted Initial packet."""

    version: int
    destination_id: bytes
    source_id: bytes
    token: bytes
    packet_number: int
    payload: bytes
    consumed: int  # where the next packet in the same datagram starts


def parse_long_header(data: bytes) -> tuple[dict, int]:
    """Read the unprotected part of a long header. RFC 9000 section 17.2."""
    if len(data) < 7:
        raise QuicError("too short for a long header")
    first = data[0]
    if not first & LONG_HEADER:
        raise QuicError("not a long header packet")
    if not first & FIXED_BIT:
        # Set in every QUIC v1 packet; if it is clear this is some other
        # protocol sharing the port, which happens on 443.
        raise QuicError("fixed bit is clear; not QUIC v1")
    if first & PACKET_TYPE_MASK != TYPE_INITIAL:
        raise QuicError("not an Initial packet")

    version = int.from_bytes(data[1:5], "big")
    offset = 5
    dcid_length = data[offset]
    offset += 1
    destination_id = data[offset:offset + dcid_length]
    offset += dcid_length
    scid_length = data[offset]
    offset += 1
    source_id = data[offset:offset + scid_length]
    offset += scid_length

    token_length, offset = varint(data, offset)
    token = data[offset:offset + token_length]
    offset += token_length

    length, offset = varint(data, offset)
    return {
        "version": version,
        "destination_id": destination_id,
        "source_id": source_id,
        "token": token,
        "length": length,
    }, offset


def decrypt_initial(data: bytes, keys: InitialKeys | None = None) -> InitialPacket:
    """Decrypt one Initial packet from the start of `data`.

    Args:
        data: a UDP payload beginning with an Initial packet. A datagram may
            coalesce several packets, so the result says where this one ended.
        keys: Initial keys, derived from the header's destination connection
            ID when not given. That default is only right for the client's
            first flight, where the destination ID *is* the original one; a
            server's reply is keyed by the same ID, so pass keys explicitly
            once a Retry or a new ID is in play.
    """
    header, offset = parse_long_header(data)
    if header["version"] != VERSION_1:
        raise QuicError("unsupported QUIC version 0x%08x" % header["version"])

    end = offset + header["length"]
    if end > len(data):
        raise QuicError("packet length runs past the datagram")
    if keys is None:
        keys = InitialKeys.derive(header["destination_id"])

    # RFC 9001 section 5.4.2: the sample starts four bytes past the packet
    # number, which is the largest a packet number can be.
    sample_start = offset + 4
    mask = keys.mask(data[sample_start:sample_start + SAMPLE_SIZE])

    first = data[0] ^ (mask[0] & 0x0F)
    pn_length = (first & 0x03) + 1
    pn_bytes = bytes(
        b ^ m for b, m in zip(data[offset:offset + pn_length], mask[1:1 + pn_length])
    )
    packet_number = int.from_bytes(pn_bytes, "big")

    # The header is authenticated, so it has to be reassembled unprotected.
    aad = bytes([first]) + data[1:offset] + pn_bytes
    ciphertext = data[offset + pn_length:end]
    if len(ciphertext) < TAG_SIZE:
        raise QuicError("payload is shorter than the authentication tag")

    decryptor = Cipher(
        algorithms.AES(keys.key),
        modes.GCM(keys.nonce(packet_number), ciphertext[-TAG_SIZE:]),
    ).decryptor()
    decryptor.authenticate_additional_data(aad)
    payload = decryptor.update(ciphertext[:-TAG_SIZE]) + decryptor.finalize()

    return InitialPacket(
        version=header["version"],
        destination_id=header["destination_id"],
        source_id=header["source_id"],
        token=header["token"],
        packet_number=packet_number,
        payload=payload,
        consumed=end,
    )


def crypto_frames(payload: bytes) -> list[tuple[int, bytes]]:
    """Every CRYPTO frame in a decrypted payload, as (offset, data).

    Only the frame types an Initial packet can carry are understood, which is
    a short list: RFC 9000 section 17.2.2 allows CRYPTO, ACK, PADDING, PING
    and CONNECTION_CLOSE and nothing else.
    """
    found = []
    index = 0
    while index < len(payload):
        kind = payload[index]
        index += 1
        if kind == FRAME_PADDING or kind == FRAME_PING:
            continue
        if kind == FRAME_CRYPTO:
            offset, index = varint(payload, index)
            length, index = varint(payload, index)
            found.append((offset, payload[index:index + length]))
            index += length
            continue
        if kind in (FRAME_ACK, FRAME_ACK_ECN):
            _largest, index = varint(payload, index)
            _delay, index = varint(payload, index)
            count, index = varint(payload, index)
            _first, index = varint(payload, index)
            for _ in range(count):
                _gap, index = varint(payload, index)
                _range, index = varint(payload, index)
            if kind == FRAME_ACK_ECN:
                for _ in range(3):
                    _value, index = varint(payload, index)
            continue
        if kind == FRAME_CONNECTION_CLOSE:
            _code, index = varint(payload, index)
            _frame_type, index = varint(payload, index)
            length, index = varint(payload, index)
            index += length
            continue
        raise QuicError("frame type 0x%02x is not allowed in an Initial packet"
                        % kind)
    return found


@dataclass
class CryptoStream:
    """CRYPTO frames reassembled in offset order.

    A ClientHello does not fit in the 1200 bytes QUIC starts with, so it
    arrives split across packets, and the pieces may be reordered. Holding
    them by offset and only reporting a contiguous run keeps a gap from
    looking like a complete message.
    """

    pieces: dict[int, bytes] = field(default_factory=dict)

    def add(self, offset: int, data: bytes) -> None:
        if data:
            self.pieces[offset] = data

    @property
    def contiguous(self) -> bytes:
        out = bytearray()
        for offset in sorted(self.pieces):
            if offset > len(out):
                break  # a gap: everything past it is not ours to report yet
            piece = self.pieces[offset]
            if offset + len(piece) > len(out):
                out += piece[len(out) - offset:]
        return bytes(out)

    @property
    def complete(self) -> bool:
        """Whether the run holds a whole handshake message."""
        data = self.contiguous
        if len(data) < 4:
            return False
        return len(data) >= 4 + int.from_bytes(data[1:4], "big")

    def message(self) -> bytes:
        """The first complete handshake message, header included."""
        if not self.complete:
            raise QuicError("the CRYPTO stream holds %d bytes and no complete "
                            "message" % len(self.contiguous))
        data = self.contiguous
        return data[:4 + int.from_bytes(data[1:4], "big")]


def client_hello_from_datagrams(datagrams) -> bytes:
    """Pull a ClientHello out of a sequence of UDP payloads.

    Datagrams that are not QUIC v1 Initial packets are skipped rather than
    raising, because a capture of port 443 holds other things.
    """
    stream = CryptoStream()
    for datagram in datagrams:
        offset = 0
        while offset < len(datagram):
            try:
                packet = decrypt_initial(datagram[offset:])
            except (QuicError, InvalidTag):
                # Not a QUIC v1 Initial, or not keyed by this connection ID.
                # A capture of port 443 holds plenty of both.
                break
            for crypto_offset, data in crypto_frames(packet.payload):
                stream.add(crypto_offset, data)
            if packet.consumed <= 0:
                break
            offset += packet.consumed
        if stream.complete:
            break
    message = stream.message()
    if message[0] != HANDSHAKE_CLIENT_HELLO:
        raise QuicError("the first CRYPTO message is type %d, not a "
                        "ClientHello" % message[0])
    return message


# RFC 9000 section 18.2, plus the later ones named where they come from.
# A client picks these values for itself, and sends them in an order of its
# own choosing, so the list is a fingerprint in the same way an extension
# list is -- and one nothing on TCP has an equivalent of.
TRANSPORT_PARAMETERS: dict[int, str] = {
    # RFC 9000 section 18.2.
    0x00: "original_destination_connection_id",
    0x01: "max_idle_timeout",
    0x02: "stateless_reset_token",
    0x03: "max_udp_payload_size",
    0x04: "initial_max_data",
    0x05: "initial_max_stream_data_bidi_local",
    0x06: "initial_max_stream_data_bidi_remote",
    0x07: "initial_max_stream_data_uni",
    0x08: "initial_max_streams_bidi",
    0x09: "initial_max_streams_uni",
    0x0A: "ack_delay_exponent",
    0x0B: "max_ack_delay",
    0x0C: "disable_active_migration",
    0x0D: "preferred_address",
    0x0E: "active_connection_id_limit",
    0x0F: "initial_source_connection_id",
    0x10: "retry_source_connection_id",
    # Registered later. Taken from the IANA registry rather than from reading
    # a packet and guessing: min_ack_delay in particular is 0xff04de1b, and
    # an earlier draft codepoint for it looks a lot like one Firefox sends.
    0x11: "version_information",
    0x1D: "reset_stream_at",
    0x20: "max_datagram_frame_size",
    0x3E: "initial_max_path_id",
    0x173E: "discard",
    0x219E: "scone_supported",
    0x26AB: "google handshake message",
    0x2AB2: "grease_quic_bit",
    0x3127: "initial_rtt",
    0x3128: "google_connection_options",
    0x3129: "user_agent",
    0x4752: "google_version",
    0xFF73DB: "version_information_draft",
    0x219BBCD0: "google_debug_1",
    0xFF04DE1B: "min_ack_delay",
    0x4143434213370002: "bdp_frame",
}

# RFC 9000 section 18.1: ids of this form are reserved to be ignored, which
# is how a client checks that a server tolerates the unknown. Firefox sends
# one, so collapsing them to a single identity matters for comparison in the
# same way GREASE cipher suites do.
GREASE_PARAMETER_BASE = 27
GREASE_PARAMETER_STEP = 31


def is_grease_parameter(identifier: int) -> bool:
    """Whether an id is one of the reserved, ignore-me values."""
    return (identifier >= GREASE_PARAMETER_BASE
            and (identifier - GREASE_PARAMETER_BASE) % GREASE_PARAMETER_STEP == 0)


def parameter_name(identifier: int) -> str:
    # The registered table wins. The GREASE formula covers a third of the id
    # space, so a registered parameter can satisfy it by coincidence and
    # checking GREASE first would rename it.
    known = TRANSPORT_PARAMETERS.get(identifier)
    if known is not None:
        return known
    if is_grease_parameter(identifier):
        return "GREASE"
    return "unknown(%d)" % identifier


def parse_transport_parameters(data: bytes) -> list[tuple[int, bytes]]:
    """Decode the quic_transport_parameters extension, keeping wire order.

    Order is kept because it is part of what is being measured; a dict would
    throw away the thing worth looking at.
    """
    out: list[tuple[int, bytes]] = []
    index = 0
    while index < len(data):
        identifier, index = varint(data, index)
        length, index = varint(data, index)
        if index + length > len(data):
            raise QuicError("transport parameter 0x%x runs past the extension"
                            % identifier)
        out.append((identifier, data[index:index + length]))
        index += length
    return out
