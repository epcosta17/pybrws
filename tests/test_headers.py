"""Tests for pybrws.headers and the body/response helpers in pybrws.message."""

import json
import unittest

from pybrws import headers as header_tools
from pybrws.message import Response, encode_body
from pybrws.profiles import firefox157

BASE = [("Host", "a.test"), ("Accept", "text/html"), ("Connection", "keep-alive")]


class TestMerge(unittest.TestCase):
    def test_nothing_to_merge_copies_the_base(self):
        merged = header_tools.merge(BASE, None)
        self.assertEqual(merged, BASE)
        self.assertIsNot(merged, BASE)

    def test_replacement_keeps_position_and_capitalisation(self):
        merged = header_tools.merge(BASE, {"accept": "*/*"})
        self.assertEqual(merged, [("Host", "a.test"), ("Accept", "*/*"),
                                  ("Connection", "keep-alive")])

    def test_new_header_goes_last(self):
        merged = header_tools.merge(BASE, {"X-Trace": "1"})
        self.assertEqual(merged[-1], ("X-Trace", "1"))
        self.assertEqual(len(merged), len(BASE) + 1)

    def test_none_drops_a_header(self):
        merged = header_tools.merge(BASE, {"Connection": None})
        self.assertEqual([n for n, _ in merged], ["Host", "Accept"])

    def test_dropping_an_absent_header_is_harmless(self):
        self.assertEqual(header_tools.merge(BASE, {"X-Nope": None}), BASE)

    def test_accepts_pairs_as_well_as_a_mapping(self):
        self.assertEqual(header_tools.merge(BASE, [("accept", "*/*")]),
                         header_tools.merge(BASE, {"accept": "*/*"}))

    def test_a_real_profile_keeps_its_order(self):
        merged = header_tools.merge(
            firefox157.H2_NAVIGATION_HEADERS, {"accept-language": "es-MX"}
        )
        self.assertEqual([n for n, _ in merged],
                         [n for n, _ in firefox157.H2_NAVIGATION_HEADERS])


class TestLookups(unittest.TestCase):
    def test_get_is_case_insensitive(self):
        self.assertEqual(header_tools.get(BASE, "ACCEPT"), "text/html")
        self.assertIsNone(header_tools.get(BASE, "missing"))

    def test_has(self):
        self.assertTrue(header_tools.has(BASE, "connection"))
        self.assertFalse(header_tools.has(BASE, "cookie"))

    def test_insert_before(self):
        out = header_tools.insert_before(BASE, "Cookie", "a=1", "Connection")
        self.assertEqual([n for n, _ in out],
                         ["Host", "Accept", "Cookie", "Connection"])

    def test_insert_before_a_missing_anchor_appends(self):
        out = header_tools.insert_before(BASE, "Cookie", "a=1", "Nope")
        self.assertEqual(out[-1], ("Cookie", "a=1"))


class TestEncodeBody(unittest.TestCase):
    def test_nothing(self):
        self.assertEqual(encode_body(), (b"", None))

    def test_bytes_pass_through_without_a_type(self):
        self.assertEqual(encode_body(data=b"raw"), (b"raw", None))

    def test_string_is_encoded(self):
        self.assertEqual(encode_body(data="hola"), (b"hola", None))

    def test_mapping_is_form_encoded(self):
        body, content_type = encode_body(data={"a": "1", "b": "two words"})
        self.assertEqual(body, b"a=1&b=two+words")
        self.assertEqual(content_type, "application/x-www-form-urlencoded")

    def test_json_is_serialised_compactly(self):
        body, content_type = encode_body(json={"a": 1})
        self.assertEqual(body, b'{"a":1}')
        self.assertEqual(content_type, "application/json")

    def test_both_at_once_is_rejected(self):
        with self.assertRaises(ValueError):
            encode_body(data=b"x", json={"a": 1})


class TestResponseHelpers(unittest.TestCase):
    def test_json(self):
        self.assertEqual(Response(200, [], json.dumps({"a": 1}).encode()).json(),
                         {"a": 1})

    def test_charset_defaults_to_utf8(self):
        self.assertEqual(Response(200, []).charset, "utf-8")

    def test_charset_is_read_from_the_content_type(self):
        response = Response(200, [("Content-Type", "text/html; charset=latin-1")])
        self.assertEqual(response.charset, "latin-1")

    def test_text_honours_the_declared_charset(self):
        response = Response(200, [("Content-Type", "text/plain; charset=latin-1")],
                            "café".encode("latin-1"))
        self.assertEqual(response.text(), "café")

    def test_ok_covers_success_and_redirects(self):
        self.assertTrue(Response(200, []).ok)
        self.assertTrue(Response(302, []).ok)
        self.assertFalse(Response(403, []).ok)
        self.assertFalse(Response(500, []).ok)


if __name__ == "__main__":
    unittest.main()
