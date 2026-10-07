"""The POST header sets must equal the browser captures, byte for byte."""

import unittest
from pathlib import Path

from pybrws.http1 import Http1Connection
from pybrws.profiles import firefox157

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
AUTHORITY = "pybrws.127.0.0.1.nip.io:4443"
ORIGIN = "https://pybrws.127.0.0.1.nip.io:4443"


class FakeTls:
    alpn = "http/1.1"

    def send(self, data):
        pass

    def recv(self):
        raise EOFError


def build(headers, body, content_type):
    return Http1Connection(FakeTls()).build_request(
        "POST", "/submit", AUTHORITY, headers, body,
        {"origin": ORIGIN, "referer": ORIGIN + "/", "content_type": content_type},
    )


class TestFormPost(unittest.TestCase):
    REFERENCE = FIXTURES / "reference-firefox-157-post-form.txt"

    def test_byte_identical(self):
        built = build(firefox157.H1_POST_FORM_HEADERS, b"field=value",
                      "application/x-www-form-urlencoded")
        self.assertEqual(built, self.REFERENCE.read_bytes())

    def test_a_navigation_post_carries_upgrade_insecure_requests(self):
        self.assertIn("Upgrade-Insecure-Requests: 1", self.REFERENCE.read_text())

    def test_referer_follows_connection(self):
        text = self.REFERENCE.read_text()
        self.assertLess(text.index("Connection:"), text.index("Referer:"))


class TestXhrPost(unittest.TestCase):
    REFERENCE = FIXTURES / "reference-firefox-157-post-fetch.txt"

    def test_byte_identical(self):
        built = build(firefox157.H1_POST_XHR_HEADERS, b'{"field":"value"}',
                      "application/json")
        self.assertEqual(built, self.REFERENCE.read_bytes())

    def test_an_xhr_post_omits_upgrade_insecure_requests(self):
        self.assertNotIn("Upgrade-Insecure-Requests", self.REFERENCE.read_text())

    def test_referer_precedes_content_type(self):
        # The opposite of the form capture, which is why these are two sets
        # and not one with a swapped Accept.
        text = self.REFERENCE.read_text()
        self.assertLess(text.index("Referer:"), text.index("Content-Type:"))


class TestTheTwoDiffer(unittest.TestCase):
    def setUp(self):
        self.form = dict(firefox157.H1_POST_FORM_HEADERS)
        self.xhr = dict(firefox157.H1_POST_XHR_HEADERS)

    def test_accept(self):
        self.assertEqual(self.xhr["Accept"], "*/*")
        self.assertTrue(self.form["Accept"].startswith("text/html"))

    def test_fetch_metadata(self):
        self.assertEqual(
            (self.xhr["Sec-Fetch-Dest"], self.xhr["Sec-Fetch-Mode"]),
            ("empty", "cors"),
        )
        self.assertEqual(
            (self.form["Sec-Fetch-Dest"], self.form["Sec-Fetch-Mode"]),
            ("document", "navigate"),
        )

    def test_priority(self):
        self.assertEqual(self.xhr["Priority"], "u=4")
        self.assertEqual(self.form["Priority"], "u=0, i")

    def test_both_send_an_origin(self):
        # Its absence is the loudest thing a hand-built POST gets wrong.
        self.assertIn("Origin", self.xhr)
        self.assertIn("Origin", self.form)

    def test_content_length_follows_content_type_in_both(self):
        for headers in (firefox157.H1_POST_FORM_HEADERS,
                        firefox157.H1_POST_XHR_HEADERS):
            names = [name for name, _ in headers]
            self.assertEqual(names[names.index("Content-Type") + 1], "Content-Length")


class TestDerivedHttp2Sets(unittest.TestCase):
    """Inferred from the HTTP/1.1 sets, by the rule the navigation confirmed."""

    def test_host_and_connection_are_dropped(self):
        names = [name for name, _ in firefox157.H2_POST_XHR_HEADERS]
        self.assertNotIn("host", names)
        self.assertNotIn("connection", names)

    def test_names_are_lowercase(self):
        for name, _ in firefox157.H2_POST_FORM_HEADERS:
            self.assertEqual(name, name.lower())

    def test_te_is_appended(self):
        self.assertEqual(firefox157.H2_POST_XHR_HEADERS[-1], ("te", "trailers"))

    def test_the_rest_of_the_order_is_preserved(self):
        http1 = [n.lower() for n, _ in firefox157.H1_POST_XHR_HEADERS
                 if n.lower() not in ("host", "connection")]
        http2 = [n for n, _ in firefox157.H2_POST_XHR_HEADERS if n != "te"]
        self.assertEqual(http1, http2)


if __name__ == "__main__":
    unittest.main()
