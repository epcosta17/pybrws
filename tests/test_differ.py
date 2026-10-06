"""Tests for pybrws.differ."""

import unittest

from pybrws.differ import diff
from pybrws.parser import parse_client_hello

from .vectors import MINIMAL, SWAPPED_CIPHERS


class TestDiff(unittest.TestCase):
    def test_identical_means_empty(self):
        a = parse_client_hello(MINIMAL)
        b = parse_client_hello(MINIMAL)
        self.assertEqual(diff(a, b), [])

    def test_catches_cipher_order(self):
        target = parse_client_hello(MINIMAL)
        mine = parse_client_hello(SWAPPED_CIPHERS)
        found = diff(target, mine)
        self.assertTrue(found, "swapped cipher suites must be reported")
        self.assertTrue(
            any("cipher" in d.field for d in found),
            f"expected a cipher_suites difference, got {[d.field for d in found]}",
        )

    def test_differences_are_printable(self):
        target = parse_client_hello(MINIMAL)
        mine = parse_client_hello(SWAPPED_CIPHERS)
        for d in diff(target, mine):
            self.assertIsInstance(str(d), str)


if __name__ == "__main__":
    unittest.main()
