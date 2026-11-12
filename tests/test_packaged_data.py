"""The reference captures shipped inside the package."""

import os
import tempfile
import unittest
from pathlib import Path

from pybrws.data import FILES, read_bytes
from pybrws.hexio import load_hex, parse_hex

ROOT = Path(__file__).resolve().parent.parent


class PackagedDataTests(unittest.TestCase):
    def test_packaged_captures_match_the_fixtures(self):
        for name in FILES:
            with self.subTest(name=name):
                self.assertEqual(read_bytes(name), (ROOT / "fixtures" / name).read_bytes())

    def test_data_is_found_from_any_directory(self):
        before = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            decoy = Path(tmp) / "fixtures"
            decoy.mkdir()
            (decoy / "chrome-1.hex").write_bytes(b"decoy")
            os.chdir(tmp)
            try:
                got = read_bytes("chrome-1.hex")
            finally:
                os.chdir(before)
        self.assertEqual(got, (ROOT / "fixtures" / "chrome-1.hex").read_bytes())

    def test_parse_hex_matches_load_hex(self):
        path = ROOT / "fixtures" / "chrome-1.hex"
        self.assertEqual(parse_hex(path.read_text(encoding="utf-8")), load_hex(path))


if __name__ == "__main__":
    unittest.main()
