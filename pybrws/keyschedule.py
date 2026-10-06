"""TLS 1.3 key schedule. RFC 8446 sections 7.1 and 7.3."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .wire import u8, u16


@dataclass(frozen=True)
class CipherSuite:
    id: int
    name: str
    digest: Callable[[], hashes.HashAlgorithm]
    aead: type
    key_size: int
    iv_size: int = 12

    @property
    def hash_size(self) -> int:
        return self.digest().digest_size


CIPHER_SUITES = {
    0x1301: CipherSuite(0x1301, "TLS_AES_128_GCM_SHA256", hashes.SHA256, AESGCM, 16),
    0x1302: CipherSuite(0x1302, "TLS_AES_256_GCM_SHA384", hashes.SHA384, AESGCM, 32),
    0x1303: CipherSuite(
        0x1303, "TLS_CHACHA20_POLY1305_SHA256", hashes.SHA256, ChaCha20Poly1305, 32
    ),
}


def transcript_hash(suite: CipherSuite, messages: bytes) -> bytes:
    digest = hashes.Hash(suite.digest())
    digest.update(messages)
    return digest.finalize()


def hkdf_extract(suite: CipherSuite, salt: bytes, ikm: bytes) -> bytes:
    ctx = hmac.HMAC(salt or bytes(suite.hash_size), suite.digest())
    ctx.update(ikm)
    return ctx.finalize()


def hkdf_expand(suite: CipherSuite, secret: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        ctx = hmac.HMAC(secret, suite.digest())
        ctx.update(block + info + u8(counter))
        block = ctx.finalize()
        out += block
        counter += 1
    return out[:length]


def hkdf_expand_label(
    suite: CipherSuite, secret: bytes, label: bytes, context: bytes, length: int
) -> bytes:
    full = b"tls13 " + label
    info = u16(length) + u8(len(full)) + full + u8(len(context)) + context
    return hkdf_expand(suite, secret, info, length)


def derive_secret(
    suite: CipherSuite, secret: bytes, label: bytes, messages: bytes
) -> bytes:
    return hkdf_expand_label(
        suite, secret, label, transcript_hash(suite, messages), suite.hash_size
    )


def traffic_keys(suite: CipherSuite, secret: bytes) -> tuple[bytes, bytes]:
    """Derive the AEAD key and static IV for one traffic secret."""
    key = hkdf_expand_label(suite, secret, b"key", b"", suite.key_size)
    iv = hkdf_expand_label(suite, secret, b"iv", b"", suite.iv_size)
    return key, iv


def finished_verify_data(
    suite: CipherSuite, traffic_secret: bytes, messages: bytes
) -> bytes:
    key = hkdf_expand_label(suite, traffic_secret, b"finished", b"", suite.hash_size)
    ctx = hmac.HMAC(key, suite.digest())
    ctx.update(transcript_hash(suite, messages))
    return ctx.finalize()


class KeySchedule:
    """Walks the three stages of the TLS 1.3 secret derivation."""

    def __init__(self, suite: CipherSuite) -> None:
        self.suite = suite
        zeros = bytes(suite.hash_size)
        self.early_secret = hkdf_extract(suite, zeros, zeros)
        self.handshake_secret: bytes | None = None
        self.master_secret: bytes | None = None

    def handshake(self, shared_secret: bytes, transcript: bytes) -> tuple[bytes, bytes]:
        """Derive the client and server handshake traffic secrets.

        Args:
            shared_secret: output of the key exchange.
            transcript: ClientHello through ServerHello.
        """
        suite = self.suite
        derived = derive_secret(suite, self.early_secret, b"derived", b"")
        self.handshake_secret = hkdf_extract(suite, derived, shared_secret)
        return (
            derive_secret(suite, self.handshake_secret, b"c hs traffic", transcript),
            derive_secret(suite, self.handshake_secret, b"s hs traffic", transcript),
        )

    def application(self, transcript: bytes) -> tuple[bytes, bytes]:
        """Derive the client and server application traffic secrets.

        Args:
            transcript: ClientHello through the server's Finished.
        """
        if self.handshake_secret is None:
            raise ValueError("handshake secrets have not been derived yet")
        suite = self.suite
        derived = derive_secret(suite, self.handshake_secret, b"derived", b"")
        self.master_secret = hkdf_extract(suite, derived, bytes(suite.hash_size))
        return (
            derive_secret(suite, self.master_secret, b"c ap traffic", transcript),
            derive_secret(suite, self.master_secret, b"s ap traffic", transcript),
        )
