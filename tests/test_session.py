"""Tests for pybrws.session."""

import unittest

from pybrws.client import UnsupportedUrl
from pybrws.cookies import Cookie
from pybrws.message import Response
from pybrws.profiles import firefox157
from pybrws.session import Session, insert_header, split_url


class TestSplitUrl(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(split_url("https://a.test/"), ("a.test", 443, "a.test", "/"))

    def test_empty_path_becomes_root(self):
        self.assertEqual(split_url("https://a.test")[3], "/")

    def test_query_is_kept(self):
        self.assertEqual(split_url("https://a.test/s?q=1&r=2")[3], "/s?q=1&r=2")

    def test_non_default_port_appears_in_the_authority(self):
        host, port, authority, _ = split_url("https://a.test:8443/x")
        self.assertEqual((host, port, authority), ("a.test", 8443, "a.test:8443"))

    def test_rejects_plain_http(self):
        with self.assertRaises(UnsupportedUrl):
            split_url("http://a.test/")


class TestInsertHeader(unittest.TestCase):
    BASE = [("a", "1"), ("b", "2"), ("c", "3")]

    def test_inserts_before_the_named_header(self):
        self.assertEqual(
            insert_header(self.BASE, "cookie", "k=v", "b"),
            [("a", "1"), ("cookie", "k=v"), ("b", "2"), ("c", "3")],
        )

    def test_match_is_case_insensitive(self):
        result = insert_header(self.BASE, "cookie", "k=v", "B")
        self.assertEqual(result[1], ("cookie", "k=v"))

    def test_appends_when_the_anchor_is_missing(self):
        result = insert_header(self.BASE, "cookie", "k=v", "nope")
        self.assertEqual(result[-1], ("cookie", "k=v"))

    def test_replaces_an_existing_header_rather_than_duplicating(self):
        base = self.BASE + [("Cookie", "old=1")]
        result = insert_header(base, "cookie", "new=2", "b")
        self.assertEqual([n for n, _ in result].count("cookie"), 1)
        self.assertNotIn(("Cookie", "old=1"), result)

    def test_order_is_otherwise_untouched(self):
        result = insert_header(self.BASE, "cookie", "k=v", "c")
        self.assertEqual([n for n, _ in result], ["a", "b", "cookie", "c"])


class TestHeaderAssembly(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.addCleanup(self.session.close)

    def test_no_cookies_leaves_the_profile_list_alone(self):
        built = self.session._headers_for("a.test", "/", True, None)
        self.assertEqual(built, list(firefox157.H2_NAVIGATION_HEADERS))

    def test_cookie_lands_at_the_profile_slot_for_http2(self):
        self.session.cookies.set(Cookie("sid", "1", "a.test", "/"))
        built = self.session._headers_for("a.test", "/", True, None)
        names = [n for n, _ in built]
        self.assertEqual(
            names.index("cookie") + 1,
            names.index(firefox157.H2_COOKIE_BEFORE),
        )

    def test_cookie_uses_http1_capitalisation(self):
        self.session.cookies.set(Cookie("sid", "1", "a.test", "/"))
        built = self.session._headers_for("a.test", "/", False, None)
        names = [n for n, _ in built]
        self.assertIn("Cookie", names)
        self.assertNotIn("cookie", names)

    def test_query_string_is_not_part_of_the_cookie_path(self):
        self.session.cookies.set(Cookie("sid", "1", "a.test", "/search"))
        built = self.session._headers_for("a.test", "/search?q=x", True, None)
        self.assertIn(("cookie", "sid=1"), built)

    def test_overridden_headers_still_receive_the_cookie(self):
        self.session.cookies.set(Cookie("sid", "1", "a.test", "/"))
        built = self.session._headers_for(
            "a.test", "/", True, [("accept", "*/*"), ("upgrade-insecure-requests", "1")]
        )
        self.assertIn(("cookie", "sid=1"), built)


class TestSessionRequests(unittest.TestCase):
    """Drives Session.get with _once replaced, so no network is involved."""

    def setUp(self):
        self.session = Session()
        self.addCleanup(self.session.close)
        self.visited = []

    def scripted(self, responses):
        def _once(url, headers):
            self.visited.append(url)
            return responses[len(self.visited) - 1]

        self.session._once = _once

    def test_returns_a_plain_response(self):
        self.scripted([Response(200, [], b"ok")])
        self.assertEqual(self.session.get("https://a.test/").status, 200)

    def test_follows_redirects_and_records_history(self):
        self.scripted([
            Response(302, [("Location", "/two")]),
            Response(302, [("Location", "https://b.test/three")]),
            Response(200, [], b"done"),
        ])
        response = self.session.get("https://a.test/one")
        self.assertEqual(response.status, 200)
        self.assertEqual(len(response.history), 2)
        self.assertEqual(
            self.visited,
            ["https://a.test/one", "https://a.test/two", "https://b.test/three"],
        )

    def test_zero_budget_returns_the_redirect(self):
        self.scripted([Response(301, [("Location", "/elsewhere")])])
        response = self.session.get("https://a.test/", follow_redirects=0)
        self.assertEqual(response.status, 301)
        self.assertEqual(len(self.visited), 1)

    def test_a_redirect_without_a_location_is_returned_as_is(self):
        self.scripted([Response(302, [])])
        self.assertEqual(self.session.get("https://a.test/").status, 302)


if __name__ == "__main__":
    unittest.main()
