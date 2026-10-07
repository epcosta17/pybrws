"""Tests for pybrws.keyexchange."""

import unittest

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519

from pybrws.keyexchange import (
    MLKEM768_CIPHERTEXT_SIZE,
    SECP256R1,
    X25519,
    X25519MLKEM768,
    KeyExchange,
)
from pybrws.profiles import firefox157

RAW = (ser.Encoding.Raw, ser.PublicFormat.Raw)


class TestShareSizes(unittest.TestCase):
    def test_sizes_match_the_firefox_profile(self):
        kx = KeyExchange([group for group, _ in firefox157.KEY_SHARE_GROUPS])
        sizes = {group: len(share) for group, share in kx.client_shares()}
        self.assertEqual(sizes, dict(firefox157.KEY_SHARE_GROUPS))

    def test_hybrid_puts_mlkem_first(self):
        kx = KeyExchange([X25519MLKEM768])
        share = kx.public_share(X25519MLKEM768)
        # The trailing 32 bytes must be a usable X25519 public key.
        x25519.X25519PublicKey.from_public_bytes(share[-32:])
        mlkem.MLKEM768PublicKey.from_public_bytes(share[:-32])

    def test_rejects_unknown_group(self):
        # 0x0100 is ffdhe2048, which the profile does not advertise and this
        # client cannot produce. secp384r1 used to stand here and now works,
        # because a HelloRetryRequest may ask for any advertised group.
        with self.assertRaises(ValueError):
            KeyExchange([0x0100])

    def test_every_advertised_group_can_be_produced(self):
        from pybrws.keyexchange import supported
        from pybrws.parser import _Reader

        payload = dict(firefox157.EXTENSIONS)[10]
        groups = _Reader(_Reader(payload).vector(2))
        advertised = [groups.uint(2) for _ in range(groups.remaining // 2)]
        unsupported = [g for g in advertised if not supported(g)]
        self.assertEqual(unsupported, [],
                         "a retry can ask for any of these")


class TestSharedSecret(unittest.TestCase):
    def test_x25519(self):
        kx = KeyExchange([X25519])
        server = x25519.X25519PrivateKey.generate()
        theirs = server.exchange(
            x25519.X25519PublicKey.from_public_bytes(kx.public_share(X25519))
        )
        ours = kx.shared_secret(X25519, server.public_key().public_bytes(*RAW))
        self.assertEqual(ours, theirs)

    def test_secp256r1(self):
        kx = KeyExchange([SECP256R1])
        server = ec.generate_private_key(ec.SECP256R1())
        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), kx.public_share(SECP256R1)
        )
        theirs = server.exchange(ec.ECDH(), peer)
        ours = kx.shared_secret(
            SECP256R1,
            server.public_key().public_bytes(
                ser.Encoding.X962, ser.PublicFormat.UncompressedPoint
            ),
        )
        self.assertEqual(ours, theirs)

    def test_hybrid_round_trip(self):
        kx = KeyExchange([X25519MLKEM768])
        share = kx.public_share(X25519MLKEM768)

        # Stand in for the server: encapsulate to our ML-KEM key, and do X25519.
        their_mlkem_secret, ciphertext = mlkem.MLKEM768PublicKey.from_public_bytes(
            share[:-32]
        ).encapsulate()
        server_x = x25519.X25519PrivateKey.generate()
        their_x_secret = server_x.exchange(
            x25519.X25519PublicKey.from_public_bytes(share[-32:])
        )

        ours = kx.shared_secret(
            X25519MLKEM768, ciphertext + server_x.public_key().public_bytes(*RAW)
        )
        self.assertEqual(ours, their_mlkem_secret + their_x_secret)
        self.assertEqual(len(ours), 64)

    def test_rejects_wrong_sized_hybrid_share(self):
        kx = KeyExchange([X25519MLKEM768])
        with self.assertRaises(ValueError):
            kx.shared_secret(X25519MLKEM768, b"\x00" * (MLKEM768_CIPHERTEXT_SIZE + 31))


if __name__ == "__main__":
    unittest.main()
