"""Tests for pybrws.parser."""

import unittest

from pybrws.parser import parse_client_hello

from .vectors import MINIMAL


class TestParseMinimal(unittest.TestCase):
    def setUp(self):
        self.ch = parse_client_hello(MINIMAL)

    def test_legacy_version(self):
        self.assertEqual(self.ch.legacy_version, 0x0303)

    def test_random_is_32_bytes(self):
        self.assertEqual(len(self.ch.random), 32)
        self.assertEqual(self.ch.random[:4], bytes.fromhex("00010203"))

    def test_empty_session_id(self):
        self.assertEqual(self.ch.session_id, b"")

    def test_cipher_suites_preserve_wire_order(self):
        self.assertEqual(self.ch.cipher_suites, [0x1301, 0xC02B])

    def test_compression_methods(self):
        self.assertEqual(self.ch.compression_methods, [0])

    def test_extensions_in_wire_order(self):
        self.assertEqual(self.ch.extension_types(), [0, 43])
        self.assertEqual(self.ch.extensions[0].name, "server_name")
        self.assertEqual(self.ch.extensions[0].data, b"")
        self.assertEqual(self.ch.extensions[1].data, bytes.fromhex("020304"))

    def test_lookup_helper(self):
        self.assertIsNotNone(self.ch.extension(43))
        self.assertIsNone(self.ch.extension(28))

    def test_raw_is_preserved(self):
        self.assertEqual(self.ch.raw, MINIMAL)

    def test_summary_renders(self):
        self.assertIn("supported_versions", self.ch.summary())


class TestRejectsGarbage(unittest.TestCase):
    def test_empty(self):
        with self.assertRaises(ValueError):
            parse_client_hello(b"")

    def test_not_a_handshake_record(self):
        with self.assertRaises(ValueError):
            parse_client_hello(bytes.fromhex("17030100050102030405"))

    def test_truncated(self):
        with self.assertRaises(ValueError):
            parse_client_hello(MINIMAL[:20])


if __name__ == "__main__":
    unittest.main()
