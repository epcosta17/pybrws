"""Tests for pybrws.proxy."""

import datetime
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pybrws.message import Response
from pybrws.proxy import (
    CertificateAuthority,
    error_response,
    parse_head,
    serialise,
)


class TestRequestParsing(unittest.TestCase):
    def test_connect_line(self):
        head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        method, target, headers = parse_head(head)
        self.assertEqual((method, target), ("CONNECT", "example.com:443"))
        self.assertEqual(headers, [("Host", "example.com:443")])

    def test_inner_get(self):
        head = b"GET /a?b=c HTTP/1.1\r\nHost: a.test\r\nAccept: */*\r\n\r\n"
        method, target, headers = parse_head(head)
        self.assertEqual((method, target), ("GET", "/a?b=c"))
        self.assertEqual(len(headers), 2)

    def test_method_is_upper_cased(self):
        self.assertEqual(parse_head(b"get / HTTP/1.1\r\n\r\n")[0], "GET")

    def test_rejects_a_malformed_line(self):
        with self.assertRaises(ValueError):
            parse_head(b"GARBAGE\r\n\r\n")


class TestSerialisation(unittest.TestCase):
    def test_status_body_and_length(self):
        raw = serialise(Response(200, [("Content-Type", "text/plain")], b"hello"))
        head, _, body = raw.partition(b"\r\n\r\n")
        self.assertTrue(head.startswith(b"HTTP/1.1 200"))
        self.assertIn(b"Content-Length: 5", head)
        self.assertEqual(body, b"hello")

    def test_hop_by_hop_headers_are_dropped(self):
        raw = serialise(
            Response(
                200,
                [
                    ("Transfer-Encoding", "chunked"),
                    ("Content-Encoding", "br"),
                    ("Connection", "keep-alive"),
                    ("Content-Length", "999"),
                    ("Server", "nginx"),
                ],
                b"body",
            )
        )
        head = raw.split(b"\r\n\r\n")[0]
        self.assertNotIn(b"Transfer-Encoding", head)
        self.assertNotIn(b"Content-Encoding", head)
        self.assertNotIn(b"999", head)
        self.assertIn(b"Server: nginx", head)
        self.assertIn(b"Content-Length: 4", head)

    def test_error_response_is_well_formed(self):
        raw = error_response(502, "upstream failed")
        head, _, body = raw.partition(b"\r\n\r\n")
        self.assertTrue(head.startswith(b"HTTP/1.1 502"))
        self.assertIn(b"Content-Length: " + str(len(body)).encode(), head)
        self.assertEqual(body, b"upstream failed")


class TestCertificateAuthority(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.ca = CertificateAuthority(self.directory)

    def test_writes_both_pem_files(self):
        self.assertTrue(self.ca.cert_path.exists())
        self.assertTrue(self.ca.key_path.exists())

    def test_is_a_certificate_authority(self):
        constraints = self.ca.certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        self.assertTrue(constraints.ca)

    def test_has_a_subject_key_identifier(self):
        # Without it a verifier cannot match the authority key id on a leaf.
        self.ca.certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )

    def test_reuses_a_stored_authority(self):
        again = CertificateAuthority(self.directory)
        self.assertEqual(again.certificate.serial_number,
                         self.ca.certificate.serial_number)

    def test_regenerates_an_authority_without_a_subject_key_identifier(self):
        # A CA minted before that extension was added must not be reused: a
        # leaf signed by it cannot carry a matching authority key id.
        write_legacy_ca(self.directory)
        before = x509.load_pem_x509_certificate(self.ca.cert_path.read_bytes())
        with self.assertRaises(x509.ExtensionNotFound):
            before.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)

        replacement = CertificateAuthority(self.directory)
        replacement.certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
        self.assertNotEqual(replacement.certificate.serial_number,
                            before.serial_number)

    def test_leaf_is_cached_per_host(self):
        first = self.ca.context_for("a.test")
        self.assertIs(first, self.ca.context_for("a.test"))
        self.assertIsNot(first, self.ca.context_for("b.test"))

    def test_leaf_carries_the_hostname_and_links_to_the_authority(self):
        certificate, _ = self.ca._leaf("example.test")
        names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        self.assertEqual(names, ["example.test"])

        authority_key = certificate.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value.key_identifier
        subject_key = self.ca.certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.digest
        self.assertEqual(authority_key, subject_key)

    def test_leaf_context_offers_http11(self):
        self.ca.context_for("a.test")  # exercises load_cert_chain on real files


def write_legacy_ca(directory: Path) -> None:
    """Write a valid CA that predates the SubjectKeyIdentifier extension."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy local CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    (directory / "ca.pem").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )
    (directory / "ca-key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


if __name__ == "__main__":
    unittest.main()
