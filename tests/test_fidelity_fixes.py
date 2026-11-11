"""Fidelity and tooling fixes: F1 and M1 of the 2026-11-11 review."""

from __future__ import annotations

import glob
import os
import unittest
from pathlib import Path

from pybrws.emitter import build_client_hello
from pybrws.hexio import load_hex
from pybrws.parser import _Reader, parse_client_hello
from pybrws.profiles import chrome155

from tests.hostile import x25519_like

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CHROME_CAPTURES = [parse_client_hello(load_hex(path))
                   for path in sorted(glob.glob(str(FIXTURES / "chrome-*.hex")))]


def ech_enc(hello) -> bytes:
    """The `enc` field of a greased outer ECH extension."""
    reader = _Reader(hello.extension(65037).data)
    reader.uint(1), reader.uint(2), reader.uint(2), reader.uint(1)
    return reader.vector(2)


def generated(count: int):
    return [parse_client_hello(build_client_hello("example.com", profile=chrome155))
            for _ in range(count)]


class TestChromeEchKey(unittest.TestCase):
    """F1: all six Chrome captures carry a valid X25519 public key in the
    greased ECH `enc` (1 chance in 4096 at random); the profile sent random
    bytes, three quarters of which no observer would take for a key."""

    def test_captures_carry_x25519_keys(self):
        # Guards the check itself, on what was measured.
        self.assertEqual(len(CHROME_CAPTURES), 6)
        self.assertTrue(all(x25519_like(ech_enc(h)) for h in CHROME_CAPTURES))

    def test_the_check_tells_random_bytes_apart(self):
        passed = sum(x25519_like(os.urandom(32)) for _ in range(2000))
        self.assertLess(passed, 700)   # about 500 expected

    def test_generated_enc_is_an_x25519_key(self):
        self.assertTrue(all(x25519_like(ech_enc(h)) for h in generated(2000)))

    def test_each_connection_draws_its_own_key(self):
        encs = [ech_enc(h) for h in generated(50)]
        self.assertEqual(len(set(encs)), 50)

    def test_hello_lengths_unchanged(self):
        self.assertEqual({len(h.raw) for h in generated(300)}, {1925, 1989, 2021})


if __name__ == "__main__":
    unittest.main()
