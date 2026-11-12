"""pybrws.profiles.load: built-in names, a reader's own file, the contract."""

from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

import pybrws.profiles.firefox157 as firefox157_module
from pybrws.emitter import build_client_hello
from pybrws.parser import parse_client_hello
from pybrws.profiles import (REQUIRED_TCP, ProfileError, chrome155,
                             firefox157, firefox157_quic, load)
from tests.profile_files import write_profile


class TestProfileLoader(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_builtin_names(self):
        self.assertIs(load("firefox157"), firefox157)
        self.assertIs(load("chrome155"), chrome155)
        self.assertIs(load("firefox157_quic", transport="quic"),
                      firefox157_quic)
        self.assertIs(load(firefox157), firefox157)

    def test_wrong_transport_says_which_flag(self):
        with self.assertRaises(ProfileError) as caught:
            load("firefox157_quic")
        self.assertIn("add --http3", str(caught.exception))
        with self.assertRaises(ProfileError) as caught:
            load("chrome155", transport="quic")
        self.assertIn("drop --http3", str(caught.exception))

    def test_profile_from_a_file(self):
        path = write_profile(self.dir)
        for spec in (path, str(path)):
            profile = load(spec)
            self.assertEqual(profile.NAME, "my-firefox")
            mine = parse_client_hello(build_client_hello(
                "example.com", profile=profile, rng=random.Random(1).randbytes))
            ref_bytes = build_client_hello(
                "example.com", profile=firefox157,
                rng=random.Random(1).randbytes)
            ref = parse_client_hello(ref_bytes)
            self.assertEqual(mine.cipher_suites, ref.cipher_suites)
            self.assertEqual(mine.extension_types(), ref.extension_types())
            self.assertEqual(len(build_client_hello(
                "example.com", profile=profile,
                rng=random.Random(1).randbytes)), len(ref_bytes))

    def test_missing_names_are_listed(self):
        path = write_profile(self.dir, 'NAME = "x"\n')
        with self.assertRaises(ProfileError) as caught:
            load(path)
        self.assertIn("CIPHER_SUITES", str(caught.exception))
        self.assertIn("H2_SETTINGS", str(caught.exception))

    def test_an_extension_order_is_required(self):
        lines = ["from pybrws.profiles import firefox157 as _f"]
        lines += [name + " = _f." + name for name in REQUIRED_TCP]
        path = write_profile(self.dir, "\n".join(lines) + "\n")
        with self.assertRaises(ProfileError) as caught:
            load(path)
        self.assertIn("EXTENSIONS, or extension_order and payload_for",
                      str(caught.exception))

    def test_relative_imports_are_explained(self):
        text = Path(firefox157_module.__file__).read_text(encoding="utf-8")
        path = write_profile(self.dir, text)
        with self.assertRaises(ProfileError) as caught:
            load(path)
        self.assertIn("absolute imports", str(caught.exception))

    def test_windows_style_paths_are_paths(self):
        for spec in ("C:\\nowhere\\my.py", "sub\\my_profile"):
            with self.assertRaises(ProfileError) as caught:
                load(spec)
            self.assertIn("no profile file", str(caught.exception))
            self.assertNotIn("unknown profile", str(caught.exception))

    def test_unknown_name_lists_choices(self):
        with self.assertRaises(ProfileError) as caught:
            load("netscape4")
        self.assertIn("firefox157", str(caught.exception))
        self.assertIn("chrome155", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
