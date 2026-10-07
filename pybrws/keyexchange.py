"""Key exchange for the groups a browser profile offers.

Group ids and wire layouts follow RFC 8446 for the classical groups and
draft-kwiatkowski-tls-ecdhe-mlkem for the hybrid. In X25519MLKEM768 the
ML-KEM encapsulation key precedes the X25519 public key, and the shared
secrets concatenate in the same order.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519

X25519 = 0x001D
SECP256R1 = 0x0017
SECP384R1 = 0x0018
SECP521R1 = 0x0019
X25519MLKEM768 = 0x11EC

# A HelloRetryRequest may ask for any group the ClientHello advertised, not
# only the ones it sent a share for.
CURVES = {
    SECP256R1: ec.SECP256R1,
    SECP384R1: ec.SECP384R1,
    SECP521R1: ec.SECP521R1,
}

MLKEM768_PUBLIC_SIZE = 1184
MLKEM768_CIPHERTEXT_SIZE = 1088
X25519_SIZE = 32

_RAW = (ser.Encoding.Raw, ser.PublicFormat.Raw)
_POINT = (ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)


class KeyExchange:
    """The private keys behind one ClientHello's key_share extension."""

    def __init__(self, groups: list[int]) -> None:
        self.groups = list(groups)
        self._x25519: dict[int, x25519.X25519PrivateKey] = {}
        self._ec: dict[int, ec.EllipticCurvePrivateKey] = {}
        self._mlkem: dict[int, mlkem.MLKEM768PrivateKey] = {}

        for group in self.groups:
            if group in (X25519, X25519MLKEM768):
                self._x25519[group] = x25519.X25519PrivateKey.generate()
            if group == X25519MLKEM768:
                self._mlkem[group] = mlkem.MLKEM768PrivateKey.generate()
            if group in CURVES:
                self._ec[group] = ec.generate_private_key(CURVES[group]())
            if group not in CURVES and group not in (X25519, X25519MLKEM768):
                raise ValueError(f"unsupported group 0x{group:04x}")

    def public_share(self, group: int) -> bytes:
        if group == X25519:
            return self._x25519[group].public_key().public_bytes(*_RAW)
        if group in CURVES:
            return self._ec[group].public_key().public_bytes(*_POINT)
        if group == X25519MLKEM768:
            return (
                self._mlkem[group].public_key().public_bytes_raw()
                + self._x25519[group].public_key().public_bytes(*_RAW)
            )
        raise ValueError(f"unsupported group 0x{group:04x}")

    def client_shares(self) -> list[tuple[int, bytes]]:
        return [(group, self.public_share(group)) for group in self.groups]

    def shared_secret(self, group: int, peer_share: bytes) -> bytes:
        """Derive the shared secret from the server's key_share entry."""
        if group == X25519:
            peer = x25519.X25519PublicKey.from_public_bytes(peer_share)
            return self._x25519[group].exchange(peer)

        if group in CURVES:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(
                CURVES[group](), peer_share
            )
            return self._ec[group].exchange(ec.ECDH(), peer)

        if group == X25519MLKEM768:
            expected = MLKEM768_CIPHERTEXT_SIZE + X25519_SIZE
            if len(peer_share) != expected:
                raise ValueError(
                    f"X25519MLKEM768 server share is {len(peer_share)} bytes, "
                    f"expected {expected}"
                )
            ciphertext = peer_share[:MLKEM768_CIPHERTEXT_SIZE]
            peer_x = peer_share[MLKEM768_CIPHERTEXT_SIZE:]
            mlkem_secret = self._mlkem[group].decapsulate(ciphertext)
            peer = x25519.X25519PublicKey.from_public_bytes(peer_x)
            return mlkem_secret + self._x25519[group].exchange(peer)

        raise ValueError(f"unsupported group 0x{group:04x}")


def supported(group: int) -> bool:
    """Can a share be produced for this group?"""
    return group in CURVES or group in (X25519, X25519MLKEM768)
