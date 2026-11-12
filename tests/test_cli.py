"""Tests for pybrws.cli."""

import argparse
import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pybrws import cli, handshake, quic_impersonate
from tests.profile_files import write_profile
from pybrws.cli import build_parser, parse_header, render_head, resolve_profile
from pybrws.handshake import TruncatedStream
from pybrws.headers import merge
from pybrws.message import Response
from pybrws.profiles import chrome155, firefox157


class TestHeaderArgument(unittest.TestCase):
    def test_splits_on_the_first_colon(self):
        self.assertEqual(parse_header("Accept: text/html"), ("Accept", "text/html"))

    def test_value_may_contain_colons(self):
        self.assertEqual(
            parse_header("Referer: https://a.test/x"), ("Referer", "https://a.test/x")
        )

    def test_rejects_a_missing_colon(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_header("NoColonHere")


class TestMergeHeaders(unittest.TestCase):
    def test_no_overrides_returns_the_profile_list(self):
        self.assertEqual(merge(firefox157.H2_NAVIGATION_HEADERS, []),
                         list(firefox157.H2_NAVIGATION_HEADERS))

    def test_override_replaces_in_place_without_reordering(self):
        merged = merge(
            firefox157.H2_NAVIGATION_HEADERS, [("accept-language", "es-MX")]
        )
        names = [name for name, _ in merged]
        self.assertEqual(names, [n for n, _ in firefox157.H2_NAVIGATION_HEADERS])
        self.assertEqual(dict(merged)["accept-language"], "es-MX")

    def test_unknown_header_is_appended(self):
        merged = merge(firefox157.H2_NAVIGATION_HEADERS, [("X-Trace", "1")])
        self.assertEqual(merged[-1], ("X-Trace", "1"))
        self.assertEqual(len(merged), len(firefox157.H2_NAVIGATION_HEADERS) + 1)

    def test_http1_list_keeps_its_capitalisation(self):
        merged = merge(firefox157.H1_HEADERS, [("accept", "*/*")])
        self.assertIn(("Accept", "*/*"), merged)
        self.assertEqual(merged[0][0], "Host")


class TestProfileLookup(unittest.TestCase):
    def test_known_profile(self):
        self.assertIs(resolve_profile("firefox157", False), firefox157)

    def test_the_other_tcp_profile_is_reachable(self):
        # It existed for weeks and the CLI could not select it, because the
        # package exported one name and the lookup read that list.
        self.assertIs(resolve_profile("chrome155", False), chrome155)

    def test_unknown_profile_lists_the_options(self):
        with self.assertRaises(SystemExit) as caught:
            resolve_profile("nope", False)
        self.assertIn("firefox157", str(caught.exception))
        self.assertIn("chrome155", str(caught.exception))

    def test_quic_profile_is_not_offered_over_tcp(self):
        # Sending it over TCP would build three cipher suites and QUIC
        # transport parameters onto a TCP connection: a hello no browser
        # sends, which is worse than refusing.
        with self.assertRaises(SystemExit) as caught:
            resolve_profile("firefox157_quic", False)
        self.assertIn("--http3", str(caught.exception))

    def test_tcp_profile_is_not_offered_over_quic(self):
        with self.assertRaises(SystemExit) as caught:
            resolve_profile("chrome155", True)
        self.assertIn("drop --http3", str(caught.exception))

    def test_the_name_people_type_first_is_answered(self):
        # No underscore is the obvious guess, and the error should say what
        # to do rather than only that the guess was wrong.
        with self.assertRaises(SystemExit) as caught:
            resolve_profile("firefox157quic", False)
        self.assertIn("--http3", str(caught.exception))


class TestRendering(unittest.TestCase):
    def test_head_includes_status_and_headers(self):
        response = Response(200, [("Server", "nginx")], http_version="HTTP/1.1")
        self.assertEqual(render_head(response), "HTTP/1.1 200\nServer: nginx")

    def test_head_defaults_to_h2_when_no_version_is_recorded(self):
        self.assertTrue(render_head(Response(404)).startswith("h2 404"))


class TestParser(unittest.TestCase):
    def test_defaults(self):
        args = build_parser().parse_args(["https://a.test/"])
        self.assertEqual(args.url, "https://a.test/")
        self.assertIsNone(args.request, "the method is decided from -d")
        self.assertIsNone(args.profile,
                          "the default depends on the transport")
        self.assertFalse(args.http3)
        self.assertTrue(args.location, "a browser follows redirects by default")

    def test_no_location_opts_out(self):
        args = build_parser().parse_args(["--no-location", "https://a.test/"])
        self.assertFalse(args.location)

    def test_repeatable_headers(self):
        args = build_parser().parse_args(
            ["-H", "A: 1", "-H", "B: 2", "https://a.test/"]
        )
        self.assertEqual(args.header, [("A", "1"), ("B", "2")])


class TestErrors(unittest.TestCase):
    def test_a_truncated_stream_is_one_line(self):
        # A peer that closes without close_notify: an error the client
        # reports, not a traceback.
        cut = TruncatedStream("the peer closed the connection without "
                              "close_notify; anything being read may be "
                              "truncated")
        with mock.patch.object(cli, "request", side_effect=cut):
            with self.assertRaises(SystemExit) as caught:
                cli.main(["-s", "https://example.com/"])
        message = str(caught.exception.code)
        self.assertTrue(message.startswith("TruncatedStream: the peer closed"))
        self.assertNotIn("\n", message)


class TestAProfileThatCannotBuildAHello(unittest.TestCase):
    """A profile whose values or functions refuse to make a hello is a
    finding about the profile: one line, and no socket opened."""

    def fetch(self, text: str, name: str) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_profile(Path(tmp), text, name)
            no_socket = AssertionError("a socket was opened")
            with mock.patch.object(handshake, "open_socket",
                                   side_effect=no_socket), \
                    self.assertRaises(SystemExit) as caught:
                cli.main(["-s", "--profile", str(path),
                          "https://example.com/"])
        message = str(caught.exception.code)
        self.assertNotIn("\n", message)
        return message

    def test_groups_firefox157s_key_share_cannot_lay_out(self):
        message = self.fetch("from pybrws.profiles.firefox157 import *\n"
                             "NAME = 'x25519_first'\n"
                             "KEY_SHARE_GROUPS = [(0x001D, 32), (0x11EC, 1216)]\n",
                             "x25519_first.py")
        self.assertRegex(message,
                         r"^ProfileError: cannot build a hello from profile "
                         r"'x25519_first': ValueError: key_share for 0x11ec: "
                         r"expected 1216 bytes from 0x001d, got 32 "
                         r"\(firefox157\.py:\d+\)$")

    def test_a_group_no_key_exchange_knows(self):
        message = self.fetch("from pybrws.profiles.firefox157 import *\n"
                             "NAME = 'unknown_group'\n"
                             "KEY_SHARE_GROUPS = [(0x11EC, 1216), (0x9999, 32)]\n",
                             "unknown_group.py")
        self.assertRegex(message,
                         r"^ProfileError: cannot build a hello from profile "
                         r"'unknown_group': ValueError: unsupported group "
                         r"0x9999 \(keyexchange\.py:\d+\)$")


class TestVerboseLeavesThePasswordOut(unittest.TestCase):
    """-v output is what gets pasted into an issue, so its proxy line names
    the proxy and its user, and not the password."""

    def test_the_proxy_line_has_no_password(self):
        shown = io.StringIO()
        with mock.patch.object(cli, "request",
                               return_value=Response(200, [], b"")), \
                contextlib.redirect_stderr(shown), \
                contextlib.redirect_stdout(io.StringIO()):
            cli.main(["-v", "-s", "-I", "-x",
                      "http://alice:s3cret@proxy.example.com:8080",
                      "https://example.com/"])
        self.assertIn("> proxy: http://alice@proxy.example.com:8080\n",
                      shown.getvalue())
        self.assertNotIn("s3cret", shown.getvalue())

    def test_a_proxy_that_cannot_be_read_is_still_one_line(self):
        # -v reads the proxy to describe it, so a malformed one has to stop
        # in the same line the request would have stopped in.
        opened = []

        def refuse(sock, *args):
            opened.append(args)
            raise OSError("refused by the test")

        with mock.patch("socket.socket.connect", refuse), \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as caught:
            cli.main(["-v", "-x", "ftp://proxy.example.com",
                      "https://example.com/"])
        self.assertEqual(caught.exception.code,
                         "ProxyError: unsupported proxy scheme 'ftp'")
        self.assertEqual(opened, [])


@unittest.skipIf(importlib.util.find_spec("aioquic") is None,
                 "aioquic is not installed")
class TestAnAioquicWhoseSeamsMoved(unittest.TestCase):
    """quic_impersonate checks every aioquic seam it patches before the first
    connection. When one has moved, `pybrws --http3` ends in one line that
    names the aioquic pybrws is tested with, and nothing is sent."""

    def test_it_is_one_line_naming_the_aioquic_tested(self):
        import aioquic.tls as tls

        seam = tls.push_client_hello
        del tls.push_client_hello
        try:
            no_connection = AssertionError("a connection was opened")
            with mock.patch.dict(quic_impersonate._originals, clear=True), \
                    mock.patch("aioquic.asyncio.connect",
                               side_effect=no_connection), \
                    self.assertRaises(SystemExit) as caught:
                cli.main(["-s", "--http3", "https://example.com/"])
        finally:
            tls.push_client_hello = seam
        self.assertEqual(caught.exception.code,
                         "NotInstalled: aioquic.tls has no push_client_hello; "
                         "the seams have moved (pybrws is tested with "
                         "aioquic 1.3.0)")


if __name__ == "__main__":
    unittest.main()
