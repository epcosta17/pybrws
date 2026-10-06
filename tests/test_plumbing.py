"""Tests for the data model and hex I/O helpers."""

import tempfile
import unittest
from pathlib import Path

from pybrws.hexio import hexdump, load_hex, save_hex
from pybrws.model import extension_name, is_grease

from .vectors import MINIMAL


class TestModel(unittest.TestCase):
    def test_grease_detection(self):
        self.assertTrue(is_grease(0x0A0A))
        self.assertTrue(is_grease(0xFAFA))
        self.assertFalse(is_grease(0x0000))
        self.assertFalse(is_grease(0x002B))

    def test_extension_names(self):
        self.assertEqual(extension_name(0), "server_name")
        self.assertEqual(extension_name(43), "supported_versions")
        self.assertEqual(extension_name(28), "record_size_limit")
        self.assertEqual(extension_name(0x1A1A), "GREASE")
        self.assertIn("unknown", extension_name(9999))


class TestHexIO(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.hex"
            save_hex(path, MINIMAL)
            self.assertEqual(load_hex(path), MINIMAL)

    def test_tolerates_junk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.hex"
            path.write_text("16 03:01  # a comment\n003c\n", encoding="utf-8")
            self.assertEqual(load_hex(path), bytes.fromhex("1603 01003c"))

    def test_hexdump_shape(self):
        out = hexdump(MINIMAL[:16])
        self.assertTrue(out.startswith("00000000  16 03 01 00 3c"))


if __name__ == "__main__":
    unittest.main()
