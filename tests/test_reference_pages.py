"""The reference pages: the example profile, the contract, the command line."""
from __future__ import annotations

import ast
import random
import re
import sys
import unittest
from pathlib import Path

from pybrws import cli, profiles
from pybrws.emitter import build_client_hello
from pybrws.parser import parse_client_hello
from pybrws.profiles import firefox157

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "docs" / "examples" / "my_firefox.py"
EXTENSION_NAMES = ("EXTENSIONS", "extension_order", "payload_for")


def _page(name: str) -> str:
    return (ROOT / "docs" / name).read_text(encoding="utf-8")


def _mentions(text: str, name: str) -> bool:
    # Whole names: MAX_DATA must not be found inside MAX_DATAGRAM_FRAME_SIZE.
    return re.search(r"(?<!\w)" + re.escape(name) + r"(?!\w)", text) is not None


def _hello(profile) -> bytes:
    return build_client_hello("example.com", profile=profile,
                              rng=random.Random(1).randbytes)


def _load_example():
    # Loading runs the file. Its bytecode would land in docs/examples, and the
    # site build copies everything under docs/ into the site.
    saved, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        return profiles.load(EXAMPLE)
    finally:
        sys.dont_write_bytecode = saved


class ReferencePagesTests(unittest.TestCase):
    def test_the_example_profile_loads(self):
        profile = _load_example()
        self.assertNotEqual(profile.NAME, firefox157.NAME)
        mine, ref = _hello(profile), _hello(firefox157)
        self.assertEqual(len(mine), len(ref))
        self.assertEqual(parse_client_hello(mine).extension_types(),
                         parse_client_hello(ref).extension_types())

    def test_the_example_profile_spells_out_the_contract(self):
        # The file teaches the contract, so every required name is assigned
        # in it by name, with absolute imports and no `import *`.
        tree = ast.parse(EXAMPLE.read_text(encoding="utf-8"))
        assigned = {target.id for node in tree.body
                    if isinstance(node, ast.Assign)
                    for target in node.targets if isinstance(target, ast.Name)}
        for name in profiles.REQUIRED_TCP + ("EXTENSIONS",):
            with self.subTest(name=name):
                self.assertIn(name, assigned)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                with self.subTest(module=node.module):
                    self.assertEqual(node.level, 0)
                    self.assertNotIn("*", [alias.name for alias in node.names])

    def test_profiles_page_lists_the_contract(self):
        text = _page("profiles.md")
        names = profiles.REQUIRED_TCP + profiles.REQUIRED_QUIC + EXTENSION_NAMES
        for name in dict.fromkeys(names):
            with self.subTest(name=name):
                self.assertTrue(_mentions(text, name))

    def test_cli_page_covers_every_subcommand(self):
        text = _page("cli.md")
        commands = ["pybrws " + name for name in cli.SUBCOMMANDS]
        commands += ["pybrws capture " + kind for kind in cli.CAPTURE_KINDS]
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(_mentions(text, command))
        for flag in ("--max-filesize", "--profile", "--capture"):
            with self.subTest(flag=flag):
                self.assertIn(flag, text)


if __name__ == "__main__":
    unittest.main()
