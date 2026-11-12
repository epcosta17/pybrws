"""What a plain `pip install pybrws` carries, and where trust anchors come from."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path
from unittest import mock

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


class TrustFallback(unittest.TestCase):
    def _context(self, anchors):
        context = mock.Mock()
        context.get_ca_certs.return_value = anchors
        return context

    def test_certifi_only_when_the_platform_has_no_roots(self):
        with mock.patch("pybrws.certs.ssl.create_default_context",
                        return_value=self._context([])), \
                mock.patch("certifi.where", wraps=certifi.where) as where:
            self.assertIsInstance(certs.system_store(), certs.Store)
            where.assert_called()

        ca, _, tmp = hostile.trusted_ca()
        self.addCleanup(tmp.cleanup)
        der = ca.certificate.public_bytes(serialization.Encoding.DER)
        with mock.patch("pybrws.certs.ssl.create_default_context",
                        return_value=self._context([der])), \
                mock.patch("certifi.where", wraps=certifi.where) as where:
            self.assertIsInstance(certs.system_store(), certs.Store)
            where.assert_not_called()


if __name__ == "__main__":
    unittest.main()
