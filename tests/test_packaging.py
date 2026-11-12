"""What a plain `pip install pybrws` carries, and where trust anchors come from."""

from __future__ import annotations

import contextlib
import ssl
import tempfile
import tomllib
import unittest
import warnings
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization

import certifi

from pybrws import certs
from tests import hostile

ROOT = Path(__file__).resolve().parent.parent


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


class PackagingMetadata(unittest.TestCase):
    def test_a_plain_install_has_what_a_request_needs(self):
        project = _pyproject()["project"]
        for dependency in ("cryptography>=50", "hpack", "brotli",
                           "publicsuffixlist", "idna", "certifi",
                           "zstandard; python_version < '3.14'"):
            self.assertIn(dependency, project["dependencies"])
        self.assertEqual(project["scripts"]["pybrws"], "pybrws.cli:main")
        self.assertEqual(project["urls"]["Documentation"],
                         "https://pybrws.readthedocs.io/")
        self.assertIn("Development Status :: 3 - Alpha", project["classifiers"])
        for author in project["authors"]:
            self.assertNotIn("email", author)
        self.assertIn("HTTP/2", project["description"])
        self.assertIn("HTTP/3", project["description"])

    def test_no_notebook_or_comparison_packages(self):
        extras = _pyproject()["project"]["optional-dependencies"]
        for name, requirements in extras.items():
            for requirement in requirements:
                for banned in ("jupyterlab", "nbclient", "curl_cffi"):
                    self.assertNotIn(banned, requirement, name)


class DefaultStore(unittest.TestCase):
    """Mozilla's roots (the certifi bundle) plus the platform's."""

    def setUp(self):
        ca, _, tmp = hostile.trusted_ca()
        self.addCleanup(tmp.cleanup)
        self.platform_der = ca.certificate.public_bytes(serialization.Encoding.DER)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.mozilla = {c.public_bytes(serialization.Encoding.DER)
                            for c in x509.load_pem_x509_certificates(
                                Path(certifi.where()).read_bytes())}

    def anchors(self, platform, bundle=None):
        """The DER of every anchor default_store() hands to Store."""
        context = mock.Mock()
        context.get_ca_certs.return_value = platform
        seen = []

        def record(anchors):
            seen.extend(a.public_bytes(serialization.Encoding.DER)
                        for a in anchors)
            return mock.sentinel.store

        patches = [mock.patch("pybrws.certs.ssl.create_default_context",
                              return_value=context),
                   mock.patch("pybrws.certs.Store", side_effect=record)]
        if bundle is not None:
            patches.append(mock.patch("certifi.where", return_value=str(bundle)))
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            certs.default_store()
        return seen

    def test_the_union_holds_the_platform_root_and_every_mozilla_root(self):
        seen = self.anchors([self.platform_der])
        self.assertIn(self.platform_der, seen)
        self.assertTrue(self.mozilla <= set(seen))

    def test_an_empty_platform_store_gives_mozilla_roots_only(self):
        self.assertEqual(set(self.anchors([])), self.mozilla)

    def test_an_unreadable_or_empty_bundle_gives_the_platform_root_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.pem"
            empty.write_bytes(b"")
            for bundle in (Path(tmp) / "missing.pem", empty):
                self.assertEqual(self.anchors([self.platform_der], bundle),
                                 [self.platform_der])

    def test_no_roots_anywhere_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.pem"
            empty.write_bytes(b"")
            with self.assertRaises(certs.CertificateError):
                self.anchors([], empty)

    def test_a_root_in_both_is_counted_once(self):
        some_mozilla_root = sorted(self.mozilla)[0]
        seen = self.anchors([some_mozilla_root])
        self.assertEqual(seen.count(some_mozilla_root), 1)
        self.assertEqual(len(seen), len(set(seen)))

    def test_a_malformed_bundle_entry_costs_only_itself(self):
        good = self.platform_der
        pem = ssl.DER_cert_to_PEM_cert(good)
        broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "mixed.pem"
            bundle.write_text(broken + pem, encoding="ascii")
            self.assertEqual(self.anchors([], bundle), [good])

    def test_system_store_is_the_platform_alone(self):
        context = mock.Mock()
        context.get_ca_certs.return_value = []
        with mock.patch("pybrws.certs.ssl.create_default_context",
                        return_value=context), \
                mock.patch("certifi.where") as where:
            with self.assertRaises(certs.CertificateError):
                certs.system_store()
            where.assert_not_called()


if __name__ == "__main__":
    unittest.main()
