"""`pybrws verify --local --capture FILE`: any profile against your own hello."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from pybrws import cli
from pybrws.tools import verify
from tests.profile_files import write_profile

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
FIREFOX = str(FIXTURES / "reference-firefox-157-windows-fresh.hex")
CHROME = str(FIXTURES / "chrome-1.hex")


def run(main, argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(argv)
    return code, out.getvalue()


class VerifyCaptureTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.profile = str(write_profile(Path(tmp.name)))

    def test_custom_profile_against_its_own_capture(self):
        code, out = run(verify.main, ["--local", "--profile", self.profile,
                                      "--capture", FIREFOX])
        self.assertEqual(code, 0, out)
        self.assertIn("same string as the capture", out)

    def test_same_through_the_cli(self):
        code, out = run(cli.main, ["verify", "--local", "--profile",
                                   self.profile, "--capture", FIREFOX])
        self.assertEqual(code, 0, out)

    def test_mismatched_capture_fails(self):
        code, out = run(verify.main, ["--local", "--profile", "firefox157",
                                      "--capture", CHROME])
        self.assertEqual(code, 1)
        self.assertIn("differs", out)
        self.assertIn("cipher suites", out)

    def test_file_profile_without_capture_is_refused(self):
        with self.assertRaises(SystemExit) as caught:
            verify.main(["--local", "--profile", self.profile])
        self.assertIn("--capture", str(caught.exception))

    def test_builtin_name_with_capture_uses_that_file(self):
        code, out = run(verify.main, ["--local", "--profile", "firefox157",
                                      "--capture", FIREFOX])
        self.assertEqual(code, 0, out)

    def test_capture_without_local_is_refused(self):
        with self.assertRaises(SystemExit) as caught:
            verify.main(["--capture", FIREFOX])
        self.assertIn("--local", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
