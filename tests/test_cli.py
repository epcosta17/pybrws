"""Tests for pybrws.cli."""

import argparse
import unittest

from pybrws.cli import build_parser, parse_header, render_head, resolve_profile
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


if __name__ == "__main__":
    unittest.main()
