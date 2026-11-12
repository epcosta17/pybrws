"""`pybrws <subcommand>`: the method's tools behind the one command."""

from __future__ import annotations

import contextlib
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pybrws import cli
from pybrws.cli import CAPTURE_KINDS, SUBCOMMANDS, main
from pybrws.message import Response
from tests.profile_files import write_profile


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(argv)
        except SystemExit as exit_:
            code = exit_.code
            if isinstance(code, str):   # a message: what the shell prints on stderr
                err.write(code)
                code = 1
    return code, out.getvalue(), err.getvalue()


class TestSubcommands(unittest.TestCase):
    def test_verify_local_through_the_cli(self):
        for extra in ([], ["--profile", "chrome155"]):
            code, out, _ = run(["verify", "--local", *extra])
            self.assertEqual(code, 0)
            self.assertIn("same string as the capture", out)

    def test_ja4_through_the_cli(self):
        code, out, _ = run(["ja4", "--profile", "chrome155"])
        self.assertEqual(code, 0)
        self.assertRegex(out, r"t13d\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}")

    def test_capture_lists_its_kinds(self):
        code, out, err = run(["capture", "--help"])
        self.assertEqual(code, 0)
        for kind in ("hello", "request", "h2", "quic", "resumed"):
            self.assertIn(kind, out + err)
        code, out, err = run(["capture", "nope"])
        self.assertNotEqual(code, 0)
        for kind in ("hello", "request", "h2", "quic", "resumed"):
            self.assertIn(kind, out + err)

    def test_url_first_argument_is_a_fetch(self):
        # Dispatch only: what the fetch CLI makes of the argument is its own.
        for argument in ("https://verify/", "example.com"):
            with mock.patch.object(cli, "request",
                                   return_value=Response(200, [], b"")) as fake:
                run(["-s", "-I", argument])
            fake.assert_called_once()
            self.assertEqual(fake.call_args.args[0], argument)

    def test_missing_extra_is_one_line(self):
        modules = {name: None for name in list(sys.modules)
                   if name.split(".")[0] in ("httpx", "aioquic")}
        modules.update(httpx=None, aioquic=None)
        with mock.patch.dict(sys.modules):
            sys.modules.update(modules)
            sys.modules.pop("pybrws.tools.ab_test", None)
            with self.assertRaises(SystemExit) as caught:
                main(["ab", "--targets", "https://127.0.0.1:9/", "--no-log"])
            self.assertIn("pybrws[measure]", str(caught.exception))
            self.assertNotIn("\n", str(caught.exception))
            with self.assertRaises(SystemExit) as caught:
                main(["--http3", "https://127.0.0.1:9/"])
            self.assertIn("pybrws[http3]", str(caught.exception))

    def test_help_lists_the_subcommands(self):
        code, out, err = run(["--help"])
        for name in (*SUBCOMMANDS, "capture"):
            self.assertIn(name, out)

    def test_fetch_takes_a_profile_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_profile(Path(directory))
            with mock.patch.object(cli, "request",
                                   return_value=Response(200, [], b"")) as fake:
                run(["-s", "-I", "--profile", str(path), "https://a.test/"])
        self.assertEqual(fake.call_args.kwargs["profile"].NAME, "my-firefox")

    def test_tables_match_the_brief(self):
        self.assertEqual(set(SUBCOMMANDS), {"read-quic", "ja4", "verify", "probe",
                                            "ab", "isolate", "waf"})
        self.assertEqual(set(CAPTURE_KINDS),
                         {"hello", "request", "h2", "quic", "resumed"})
        self.assertEqual(cli.EXTRA_FOR, {"httpx": "measure", "aioquic": "http3"})


if __name__ == "__main__":
    unittest.main()
