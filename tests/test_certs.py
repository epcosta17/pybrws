"""Tests for pybrws.certs."""

import datetime
import tempfile
import unittest
import zlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID
from cryptography.x509.verification import Store

from pybrws.certs import (
    SIGNATURE_CONTEXT,
    CertificateError,
    decompress_certificate,
    parse_certificate,
    system_store,
    verify_chain,
    verify_signature,
)
from pybrws.proxy import CertificateAuthority


def vector(data: bytes, length_bytes: int) -> bytes:
    return len(data).to_bytes(length_bytes, "big") + data


def certificate_message(chain: list[bytes]) -> bytes:
    entries = b"".join(vector(der, 3) + vector(b"", 2) for der in chain)
    return vector(b"", 1) + vector(entries, 3)


class TestParsing(unittest.TestCase):
    def test_round_trip(self):
        chain = [b"first-der", b"second-der"]
        self.assertEqual(parse_certificate(certificate_message(chain)), chain)

    def test_per_certificate_extensions_are_skipped(self):
        entries = vector(b"leaf", 3) + vector(b"\x00\x05\x00\x00", 2)
        body = vector(b"", 1) + vector(entries, 3)
        self.assertEqual(parse_certificate(body), [b"leaf"])

    def test_an_empty_list_is_rejected(self):
        with self.assertRaises(CertificateError):
            parse_certificate(certificate_message([]))


class TestDecompression(unittest.TestCase):
    def compressed(self, plain: bytes, algorithm: int, blob: bytes = None,
                   claimed: int = None) -> bytes:
        blob = zlib.compress(plain) if blob is None else blob
        length = len(plain) if claimed is None else claimed
        return (algorithm.to_bytes(2, "big") + length.to_bytes(3, "big")
                + vector(blob, 3))

    def test_zlib(self):
        plain = certificate_message([b"der"])
        self.assertEqual(decompress_certificate(self.compressed(plain, 1)), plain)

    def test_brotli(self):
        import brotli

        plain = certificate_message([b"der"])
        blob = brotli.compress(plain)
        self.assertEqual(decompress_certificate(self.compressed(plain, 2, blob)),
                         plain)

    def test_a_wrong_length_is_rejected(self):
        # The server states the decompressed size; a mismatch means one of
        # the two sides is confused and the bytes should not be trusted.
        plain = certificate_message([b"der"])
        with self.assertRaises(CertificateError):
            decompress_certificate(self.compressed(plain, 1, claimed=len(plain) + 1))

    def test_an_unknown_algorithm_is_rejected(self):
        with self.assertRaises(CertificateError):
            decompress_certificate(self.compressed(b"x", 99))


class TestChainVerification(unittest.TestCase):
    """A local CA stands in for the interception this is meant to catch."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.ca = CertificateAuthority(Path(cls.tmp.name))
        cls.trusted = Store([cls.ca.certificate])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def leaf_der(self, hostname="example.test"):
        leaf, key = self.ca._leaf(hostname)
        return leaf.public_bytes(serialization.Encoding.DER), key

    def test_a_leaf_from_a_trusted_ca_is_accepted(self):
        der, _ = self.leaf_der()
        self.assertIsNotNone(verify_chain([der], "example.test", self.trusted))

    def test_the_same_leaf_is_rejected_by_the_system_store(self):
        # The whole point: a well-formed certificate is not a trusted one.
        der, _ = self.leaf_der()
        with self.assertRaises(CertificateError):
            verify_chain([der], "example.test", system_store())

    def test_a_hostname_mismatch_is_rejected(self):
        der, _ = self.leaf_der("example.test")
        with self.assertRaises(CertificateError):
            verify_chain([der], "other.test", self.trusted)

    def test_an_empty_chain_is_rejected(self):
        with self.assertRaises(Exception):
            verify_chain([], "example.test", self.trusted)


class TestSignatureVerification(unittest.TestCase):
    TRANSCRIPT = bytes(range(32))

    def signed(self):
        return SIGNATURE_CONTEXT + self.TRANSCRIPT

    def self_signed(self, key, algorithm):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a.test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, algorithm)
        )

    def test_ecdsa(self):
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = self.self_signed(key, hashes.SHA256())
        signature = key.sign(self.signed(), ec.ECDSA(hashes.SHA256()))
        verify_signature(leaf, 0x0403, signature, self.TRANSCRIPT)

    def test_a_tampered_transcript_fails(self):
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = self.self_signed(key, hashes.SHA256())
        signature = key.sign(self.signed(), ec.ECDSA(hashes.SHA256()))
        with self.assertRaises(CertificateError):
            verify_signature(leaf, 0x0403, signature, bytes(32))

    def test_rsa_pss(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = self.self_signed(key, hashes.SHA256())
        signature = key.sign(
            self.signed(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        verify_signature(leaf, 0x0804, signature, self.TRANSCRIPT)

    def test_rsa_pkcs1_is_refused_rather_than_accepted(self):
        # TLS 1.3 forbids it here; accepting it quietly would hide a server
        # doing the wrong thing.
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = self.self_signed(key, hashes.SHA256())
        signature = key.sign(self.signed(), padding.PKCS1v15(), hashes.SHA256())
        with self.assertRaises(CertificateError) as caught:
            verify_signature(leaf, 0x0401, signature, self.TRANSCRIPT)
        self.assertIn("forbids", str(caught.exception))

    def test_an_unknown_scheme_is_refused(self):
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = self.self_signed(key, hashes.SHA256())
        with self.assertRaises(CertificateError):
            verify_signature(leaf, 0xFFFF, b"x", self.TRANSCRIPT)


class TestSystemStore(unittest.TestCase):
    def test_it_loads(self):
        self.assertIsNotNone(system_store())


if __name__ == "__main__":
    unittest.main()
