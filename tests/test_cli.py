"""Tests for pybrws.cli."""

import argparse
import unittest

from pybrws.cli import (
    build_parser,
    merge_headers,
    parse_header,
    render_head,
    resolve_profile,
)
from pybrws.message import Response
from pybrws.profiles import firefox157


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
    def test_no_overrides_leaves_the_profile_alone(self):
        self.assertIsNone(merge_headers(firefox157, [], http2=True))

    def test_override_replaces_in_place_without_reordering(self):
        merged = merge_headers(
            firefox157, [("accept-language", "es-MX")], http2=True
        )
        names = [name for name, _ in merged]
        self.assertEqual(names, [n for n, _ in firefox157.H2_NAVIGATION_HEADERS])
        self.assertEqual(dict(merged)["accept-language"], "es-MX")

    def test_unknown_header_is_appended(self):
        merged = merge_headers(firefox157, [("X-Trace", "1")], http2=True)
        self.assertEqual(merged[-1], ("X-Trace", "1"))
        self.assertEqual(len(merged), len(firefox157.H2_NAVIGATION_HEADERS) + 1)

    def test_http1_list_keeps_its_capitalisation(self):
        merged = merge_headers(firefox157, [("accept", "*/*")], http2=False)
        self.assertIn(("Accept", "*/*"), merged)
        self.assertEqual(merged[0][0], "Host")


class TestProfileLookup(unittest.TestCase):
    def test_known_profile(self):
        self.assertIs(resolve_profile("firefox157"), firefox157)

    def test_unknown_profile_lists_the_options(self):
        with self.assertRaises(SystemExit) as caught:
            resolve_profile("nope")
        self.assertIn("firefox157", str(caught.exception))


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
        self.assertEqual(args.request, "GET")
        self.assertEqual(args.profile, "firefox157")
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
