"""The method's tools, as modules of the package: pybrws.tools.

An installed wheel has no tools/ directory and no fixtures/ beside it. So
each tool has to import without doing anything and take its arguments
through main(argv). Where it used to fall back to a built-in list of sites,
it stops with a message naming the argument it needs. The scripts in tools/
stay as wrappers, so a checkout runs them the way it always has.
"""

from __future__ import annotations

import contextlib
import importlib
import inspect
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent

#: Each tool that keeps a wrapper in tools/, and the subcommand it runs as
#: once installed. _selfsigned is a helper the capture tools share.
COMMAND = {
    "catch_hello": "capture hello",
    "catch_request": "capture request",
    "catch_h2": "capture h2",
    "catch_quic": "capture quic",
    "catch_resumed": "capture resumed",
    "read_quic": "read-quic",
    "ja4": "ja4",
    "verify": "verify",
    "probe_fingerprint": "probe",
    "ab_test": "ab",
    "isolate": "isolate",
    "detect_waf": "waf",
}

#: Run in a fresh interpreter, so nothing another test imported first can
#: hide what the import does. It fails if the import moved sys.path, which
#: every one of the old scripts did.
IMPORT_ONE = (
    "import importlib, sys\n"
    "before = list(sys.path)\n"
    "importlib.import_module(sys.argv[1])\n"
    "if sys.path != before:\n"
    "    sys.exit('importing ' + sys.argv[1] + ' changed sys.path')\n"
)


def tool(name: str):
    return importlib.import_module("pybrws.tools." + name)


class TestToolPackage(unittest.TestCase):

    def test_every_method_tool_imports_cleanly(self):
        environment = {key: value for key, value in os.environ.items()
                       if key != "PYBRWS_PROXY"}
        for name in COMMAND:
            with self.subTest(tool=name):
                done = subprocess.run(
                    [sys.executable, "-c", IMPORT_ONE, "pybrws.tools." + name],
                    cwd=ROOT, env=environment, capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.stdout, "")
                self.assertEqual(done.stderr, "")

    def test_every_main_takes_argv(self):
        for name in COMMAND:
            with self.subTest(tool=name):
                parameters = inspect.signature(tool(name).main).parameters
                self.assertIs(parameters["argv"].default, None)

    def test_help_exits_zero(self):
        for name, command in COMMAND.items():
            with self.subTest(tool=name):
                shown = io.StringIO()
                with contextlib.redirect_stdout(shown), \
                        self.assertRaises(SystemExit) as stopped:
                    tool(name).main(["--help"])
                self.assertEqual(stopped.exception.code, 0)
                self.assertIn("usage: pybrws " + command, shown.getvalue())

    def test_isolate_needs_a_proxy_and_targets(self):
        isolate = tool("isolate")
        # httpx stands in as missing: the arguments are checked first, so a
        # missing extra cannot hide a missing argument.
        with mock.patch.dict(os.environ), \
                mock.patch.dict(sys.modules, {"httpx": None}):
            os.environ.pop("PYBRWS_PROXY", None)
            with self.assertRaises(SystemExit) as stopped:
                isolate.main([])
            self.assertIn("--proxy", str(stopped.exception))

            with self.assertRaises(SystemExit) as stopped:
                isolate.main(["--proxy", "http://127.0.0.1:9"])
            self.assertIn("--targets", str(stopped.exception))

            # The environment variable stands in for --proxy.
            os.environ["PYBRWS_PROXY"] = "http://127.0.0.1:9"
            with self.assertRaises(SystemExit) as stopped:
                isolate.main([])
            self.assertIn("--targets", str(stopped.exception))

    def test_ab_needs_targets(self):
        with mock.patch.dict(sys.modules, {"httpx": None}), \
                self.assertRaises(SystemExit) as stopped:
            tool("ab_test").main(["--no-log"])
        self.assertIn("--targets", str(stopped.exception))

    def test_ab_history_needs_no_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "log.jsonl"
            log.write_text(json.dumps({
                "run": "2026-11-12T00:00:00+00:00", "host": "example.com",
                "client": "pybrws", "status": 200, "served": True,
            }) + "\n", encoding="utf-8")
            shown = io.StringIO()
            with contextlib.redirect_stdout(shown):
                code = tool("ab_test").main(["--history", "--log", str(log)])
        self.assertEqual(code, 0)
        self.assertIn("1/1 served", shown.getvalue())

    def test_waf_needs_urls(self):
        with self.assertRaises(SystemExit) as stopped:
            tool("detect_waf").main([])
        self.assertIn("--urls", str(stopped.exception))

    def test_ab_log_defaults_to_the_working_directory(self):
        self.assertEqual(tool("ab_test").DEFAULT_LOG, Path("ab-test-log.jsonl"))

    def test_the_old_script_paths_still_run(self):
        for extra in ([], ["--profile", "chrome155"]):
            with self.subTest(arguments=extra):
                done = subprocess.run(
                    [sys.executable, "tools/verify.py", "--local", *extra],
                    cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertIn("same string as the capture", done.stdout)

        # tools/h3_compare.py imports catch_quic by its old name and reaches
        # into its module state, so the wrapper has to be the module itself.
        self.addCleanup(sys.path.__setitem__, slice(None), list(sys.path))
        self.addCleanup(sys.modules.pop, "catch_quic", None)
        sys.modules.pop("catch_quic", None)
        sys.path.insert(0, str(ROOT / "tools"))
        import pybrws.tools.catch_quic
        self.assertIs(importlib.import_module("catch_quic"),
                      pybrws.tools.catch_quic)


if __name__ == "__main__":
    unittest.main()
