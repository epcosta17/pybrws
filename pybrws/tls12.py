"""TLS 1.2, for the hosts that decline 1.3.

The profile has always offered twelve TLS 1.2 suites, because Firefox does and
removing them would change the fingerprint. Until now a server that took one
of them got refused, which made those hosts unreachable: a WAF sweep found
`gls-group.eu` and `proximus.be` falling out that way, and `httpbin.org` has
been on the gap list since the beginning.

Almost nothing carries over from the 1.3 code. The differences that matter:

- **Key derivation is a PRF, not HKDF.** RFC 5246 section 5: P_hash chained
  over HMAC, with the suite's own hash. One master secret of 48 bytes rather
  than a schedule of secrets per stage.
- **The server signs its key exchange**, in ServerKeyExchange, rather than
  signing the transcript in CertificateVerify. And it may sign with
  rsa_pkcs1, which 1.3 forbids and 1.2 uses everywhere.
- **Records carry their content type in the clear** and, for GCM, an explicit
  8-byte nonce ahead of the ciphertext. The additional data is the sequence
  number and the header rather than the header alone.
- **ChangeCipherSpec is a real message** and resets the sequence number.
- **Finished is 12 bytes** from the PRF, whatever the hash size.
- **extended_master_secret changes the derivation**, and Firefox sends the
  extension, so it is not optional here. RFC 7627.

Implemented: ECDHE with AES-GCM and ChaCha20-Poly1305, which is every suite a
current server actually picks -- all three test hosts choose
ECDHE-RSA-AES128-GCM-SHA256. The CBC suites and the static-RSA ones are
offered in the hello and refused with a clear message if a server picks one,
which is better than a silent wrong answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .certs import ECDSA, ED25519, RSA_PKCS1, RSA_PSS, CertificateError
from .parser import _Reader
from .wire import u8, u16, vector

VERSION_1_2 = 0x0303

HANDSHAKE_SERVER_HELLO = 0x02
HANDSHAKE_CERTIFICATE = 0x0B
HANDSHAKE_SERVER_KEY_EXCHANGE = 0x0C
HANDSHAKE_CERTIFICATE_REQUEST = 0x0D
HANDSHAKE_SERVER_HELLO_DONE = 0x0E
HANDSHAKE_CLIENT_KEY_EXCHANGE = 0x10
HANDSHAKE_FINISHED = 0x14

MASTER_SECRET_SIZE = 48
VERIFY_DATA_SIZE = 12
CURVE_TYPE_NAMED = 0x03

EXT_EXTENDED_MASTER_SECRET = 23


class Tls12Error(Exception):
    pass


@dataclass(frozen=True)
class Suite:
    """One TLS 1.2 cipher suite.

    `fixed_iv_size` and `explicit_nonce_size` are the whole difference between
    the two AEAD constructions 1.2 has. GCM (RFC 5288) splits the nonce: four
    bytes from the key block and eight sent in every record.
    ChaCha20-Poly1305 (RFC 7905) does what 1.3 does, twelve bytes from the key
    block XORed with the sequence number and nothing on the wire.
    """

    id: int
    name: str
    digest: Callable[[], hashes.HashAlgorithm]
    aead: type
    key_size: int
    fixed_iv_size: int
    explicit_nonce_size: int
    authentication: str

    @property
    def hash_size(self) -> int:
        return self.digest().digest_size


SUITES: dict[int, Suite] = {
    0xC02B: Suite(0xC02B, "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                  hashes.SHA256, AESGCM, 16, 4, 8, "ecdsa"),
    0xC02F: Suite(0xC02F, "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                  hashes.SHA256, AESGCM, 16, 4, 8, "rsa"),
    0xC02C: Suite(0xC02C, "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                  hashes.SHA384, AESGCM, 32, 4, 8, "ecdsa"),
    0xC030: Suite(0xC030, "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                  hashes.SHA384, AESGCM, 32, 4, 8, "rsa"),
    0xCCA9: Suite(0xCCA9, "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                  hashes.SHA256, ChaCha20Poly1305, 32, 12, 0, "ecdsa"),
    0xCCA8: Suite(0xCCA8, "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                  hashes.SHA256, ChaCha20Poly1305, 32, 12, 0, "rsa"),
}

# Offered in the hello because Firefox offers them, and refused by name if a
# server picks one, so the failure says what happened.
UNIMPLEMENTED = {
    0xC013: "ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0x009C: "RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "RSA_WITH_AES_128_CBC_SHA",
    0x0035: "RSA_WITH_AES_256_CBC_SHA",
}


def suite_for(suite_id: int) -> Suite:
    if suite_id in SUITES:
        return SUITES[suite_id]
    if suite_id in UNIMPLEMENTED:
        raise Tls12Error(
            "server chose 0x%04x (%s), which is offered for the fingerprint's "
            "sake and not implemented: it is either CBC or static RSA, and no "
            "current server needs either" % (suite_id, UNIMPLEMENTED[suite_id])
        )
    raise Tls12Error("server chose 0x%04x, which was never offered" % suite_id)


# -- the PRF ------------------------------------------------------------------


def p_hash(digest, secret: bytes, seed: bytes, length: int) -> bytes:
    """RFC 5246 section 5. HMAC chained until there are enough bytes."""
    out = b""
    a = seed
    while len(out) < length:
        ctx = hmac.HMAC(secret, digest())
        ctx.update(a)
        a = ctx.finalize()
        ctx = hmac.HMAC(secret, digest())
        ctx.update(a + seed)
        out += ctx.finalize()
    return out[:length]


def prf(suite: Suite, secret: bytes, label: bytes, seed: bytes,
        length: int) -> bytes:
    return p_hash(suite.digest, secret, label + seed, length)


def master_secret(suite: Suite, pre_master: bytes, client_random: bytes,
                  server_random: bytes) -> bytes:
    return prf(suite, pre_master, b"master secret",
               client_random + server_random, MASTER_SECRET_SIZE)


def extended_master_secret(suite: Suite, pre_master: bytes,
                           session_hash: bytes) -> bytes:
    """RFC 7627. Binds the master secret to the handshake that produced it.

    Firefox sends the extension, so a server that echoes it expects this
    derivation and deriving the other way produces a Finished the server
    rejects -- with bad_record_mac, which says nothing about the cause.
    """
    return prf(suite, pre_master, b"extended master secret", session_hash,
               MASTER_SECRET_SIZE)


def key_block(suite: Suite, master: bytes, client_random: bytes,
              server_random: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """The write keys and fixed IVs, in the order RFC 5246 lays them out.

    Note the randoms are the other way round here than in the master secret:
    server first. Getting that backwards gives two endpoints that each think
    the other's records are corrupt.
    """
    needed = 2 * suite.key_size + 2 * suite.fixed_iv_size
    block = prf(suite, master, b"key expansion",
                server_random + client_random, needed)
    at = 0
    client_key = block[at:at + suite.key_size]; at += suite.key_size
    server_key = block[at:at + suite.key_size]; at += suite.key_size
    client_iv = block[at:at + suite.fixed_iv_size]; at += suite.fixed_iv_size
    server_iv = block[at:at + suite.fixed_iv_size]
    return client_key, server_key, client_iv, server_iv


def finished_verify_data(suite: Suite, master: bytes, label: bytes,
                         handshake_hash: bytes) -> bytes:
    """Twelve bytes, whatever the hash size. RFC 5246 section 7.4.9."""
    return prf(suite, master, label, handshake_hash, VERIFY_DATA_SIZE)


def handshake_hash(suite: Suite, messages: bytes) -> bytes:
    digest = hashes.Hash(suite.digest())
    digest.update(messages)
    return digest.finalize()


# -- record protection --------------------------------------------------------


class Cipher:
    """One direction of a TLS 1.2 AEAD record stream."""

    def __init__(self, suite: Suite, key: bytes, fixed_iv: bytes) -> None:
        self.suite = suite
        self.aead = suite.aead(key)
        self.fixed_iv = fixed_iv
        self.sequence = 0

    def _nonce(self, explicit: bytes) -> bytes:
        if self.suite.explicit_nonce_size:
            return self.fixed_iv + explicit
        # RFC 7905: no explicit nonce, the sequence number is XORed in.
        counter = self.sequence.to_bytes(len(self.fixed_iv), "big")
        return bytes(a ^ b for a, b in zip(self.fixed_iv, counter))

    def _additional_data(self, content_type: int, plaintext_length: int) -> bytes:
        # The plaintext length, not the record's. A 1.3 implementation uses
        # the header alone and no sequence number, which is the other reason
        # the record layer cannot be shared.
        return (self.sequence.to_bytes(8, "big") + u8(content_type)
                + u16(VERSION_1_2) + u16(plaintext_length))

    def encrypt(self, content_type: int, plaintext: bytes) -> bytes:
        """A complete record, header included.

        The same signature as the TLS 1.3 cipher's, so the record layer can
        hold either without knowing which. What differs underneath is that
        the content type stays in the clear here rather than being hidden
        inside the ciphertext.
        """
        explicit = (self.sequence.to_bytes(self.suite.explicit_nonce_size, "big")
                    if self.suite.explicit_nonce_size else b"")
        nonce = self._nonce(explicit)
        aad = self._additional_data(content_type, len(plaintext))
        sealed = self.aead.encrypt(nonce, plaintext, aad)
        self.sequence += 1
        payload = explicit + sealed
        return u8(content_type) + u16(VERSION_1_2) + u16(len(payload)) + payload

    def decrypt(self, header: bytes, payload: bytes) -> tuple[int, bytes]:
        """The content type and plaintext, taking the type from the header."""
        content_type = header[0]
        size = self.suite.explicit_nonce_size
        if len(payload) < size:
            raise Tls12Error("record is shorter than its explicit nonce")
        explicit, sealed = payload[:size], payload[size:]
        nonce = self._nonce(explicit)
        plaintext_length = len(sealed) - 16
        if plaintext_length < 0:
            raise Tls12Error("record is shorter than its authentication tag")
        aad = self._additional_data(content_type, plaintext_length)
        opened = self.aead.decrypt(nonce, sealed, aad)
        self.sequence += 1
        return content_type, opened

    def reset(self) -> None:
        self.sequence = 0


# -- messages -----------------------------------------------------------------


@dataclass
class ServerKeyExchange:
    group: int
    peer_point: bytes
    scheme: int
    signature: bytes
    signed_params: bytes


def parse_server_key_exchange(body: bytes) -> ServerKeyExchange:
    """RFC 4492 section 5.4, with the 1.2 signature algorithm field."""
    if len(body) < 4:
        raise Tls12Error("ServerKeyExchange is too short")
    if body[0] != CURVE_TYPE_NAMED:
        raise Tls12Error(
            "ServerKeyExchange uses curve type %d; only named curves (3) are "
            "implemented, the others having been deprecated for a decade"
            % body[0]
        )
    group = int.from_bytes(body[1:3], "big")
    point_length = body[3]
    at = 4 + point_length
    if len(body) < at + 4:
        raise Tls12Error("ServerKeyExchange is truncated")
    peer_point = body[4:at]
    # Everything up to here is what the signature covers.
    signed_params = body[:at]
    scheme = int.from_bytes(body[at:at + 2], "big")
    signature_length = int.from_bytes(body[at + 2:at + 4], "big")
    signature = body[at + 4:at + 4 + signature_length]
    if len(signature) != signature_length:
        raise Tls12Error("ServerKeyExchange signature is truncated")
    return ServerKeyExchange(group, peer_point, scheme, signature, signed_params)


def verify_key_exchange(leaf, exchange: ServerKeyExchange, client_random: bytes,
                        server_random: bytes) -> None:
    """Check the signature over the key exchange parameters.

    This is what 1.2 has instead of CertificateVerify, and it is the only
    thing tying the ephemeral key to the certificate. Skipping it leaves the
    connection open to anyone in the path.

    Unlike the 1.3 version there is no context string, and rsa_pkcs1 is
    allowed: 1.3 forbids it and 1.2 servers use it constantly.
    """
    signed = client_random + server_random + exchange.signed_params
    key = leaf.public_key()
    scheme = exchange.scheme
    try:
        if scheme in RSA_PSS:
            algorithm = RSA_PSS[scheme]()
            key.verify(exchange.signature, signed,
                       padding.PSS(mgf=padding.MGF1(algorithm),
                                   salt_length=algorithm.digest_size),
                       algorithm)
        elif scheme in RSA_PKCS1:
            algorithm = RSA_PKCS1[scheme]()
            key.verify(exchange.signature, signed, padding.PKCS1v15(), algorithm)
        elif scheme in ECDSA:
            key.verify(exchange.signature, signed, ec.ECDSA(ECDSA[scheme]()))
        elif scheme == ED25519:
            key.verify(exchange.signature, signed)
        else:
            raise CertificateError(
                "server signed its key exchange with scheme 0x%04x, which is "
                "not implemented" % scheme
            )
    except InvalidSignature as exc:
        raise CertificateError(
            "the ServerKeyExchange signature is invalid, so the ephemeral key "
            "is not the certificate holder's"
        ) from exc


def client_key_exchange(public_point: bytes) -> bytes:
    """The body of a ClientKeyExchange for ECDHE: the point, length-prefixed."""
    return vector(public_point, 1)


def parse_certificate(body: bytes) -> list[bytes]:
    """The DER certificates in a TLS 1.2 Certificate message, leaf first.

    Not the same message as 1.3's: there is no certificate_request_context in
    front and no extensions after each certificate. Reusing the 1.3 parser
    reads the first three bytes of the list length as a context and everything
    after as garbage.
    """
    entries = _Reader(_Reader(body, "Certificate").vector(3), "certificate_list")
    chain = []
    while entries.remaining:
        chain.append(entries.vector(3))
    if not chain:
        raise Tls12Error("the server sent an empty certificate list")
    return chain


def empty_certificate() -> bytes:
    """The body of a Certificate message offering nothing.

    What a browser sends when a server asks for a client certificate and it
    has none to give. The alternative is what this client did until now:
    treat CertificateRequest as unexpected and drop the connection, which made
    every host that asks unreachable.
    """
    return vector(b"", 3)
