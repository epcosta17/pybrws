"""Tests for pybrws.cookies."""

import time
import unittest

from pybrws.cookies import (
    Cookie,
    CookieJar,
    default_path,
    domain_matches,
    parse_set_cookie,
    path_matches,
)


class TestMatchingRules(unittest.TestCase):
    def test_default_path_is_the_directory(self):
        self.assertEqual(default_path("/a/b/c"), "/a/b")
        self.assertEqual(default_path("/a"), "/")
        self.assertEqual(default_path("/"), "/")
        self.assertEqual(default_path("no-slash"), "/")

    def test_domain_matching(self):
        self.assertTrue(domain_matches("example.com", "example.com"))
        self.assertTrue(domain_matches("www.example.com", "example.com"))
        self.assertTrue(domain_matches("WWW.Example.COM", "example.com"))
        self.assertFalse(domain_matches("example.com", "www.example.com"))
        self.assertFalse(domain_matches("notexample.com", "example.com"))

    def test_path_matching(self):
        self.assertTrue(path_matches("/a/b", "/a"))
        self.assertTrue(path_matches("/a", "/a"))
        self.assertTrue(path_matches("/a/b", "/a/"))
        self.assertFalse(path_matches("/ab", "/a"))
        self.assertFalse(path_matches("/", "/a"))


class TestParsing(unittest.TestCase):
    def parse(self, header, host="www.example.com", path="/dir/page"):
        return parse_set_cookie(header, host, path)

    def test_name_value_and_defaults(self):
        cookie = self.parse("sid=abc")
        self.assertEqual((cookie.name, cookie.value), ("sid", "abc"))
        self.assertEqual(cookie.domain, "www.example.com")
        self.assertEqual(cookie.path, "/dir")
        self.assertTrue(cookie.host_only)
        self.assertFalse(cookie.secure)

    def test_attributes(self):
        cookie = self.parse("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(cookie.path, "/")
        self.assertTrue(cookie.secure)
        self.assertTrue(cookie.http_only)
        self.assertEqual(cookie.same_site, "lax")

    def test_domain_widening_clears_host_only(self):
        cookie = self.parse("sid=abc; Domain=.example.com")
        self.assertEqual(cookie.domain, "example.com")
        self.assertFalse(cookie.host_only)

    def test_domain_cannot_jump_to_another_site(self):
        cookie = self.parse("sid=abc; Domain=evil.test")
        self.assertEqual(cookie.domain, "www.example.com")
        self.assertTrue(cookie.host_only)

    def test_max_age_overrides_expires(self):
        cookie = self.parse(
            "sid=abc; Expires=Wed, 01 Jan 2020 00:00:00 GMT; Max-Age=600"
        )
        self.assertGreater(cookie.expires, time.time() + 500)

    def test_non_positive_max_age_expires_immediately(self):
        self.assertTrue(self.parse("sid=abc; Max-Age=0").expired())

    def test_expires_in_the_past(self):
        self.assertTrue(
            self.parse("sid=abc; Expires=Wed, 01 Jan 2020 00:00:00 GMT").expired()
        )

    def test_unparseable_expires_is_ignored(self):
        self.assertIsNone(self.parse("sid=abc; Expires=not-a-date").expires)

    def test_empty_value_is_allowed(self):
        self.assertEqual(self.parse("sid=").value, "")

    def test_rejects_a_header_without_a_name(self):
        self.assertIsNone(self.parse("novalue"))
        self.assertIsNone(self.parse("=orphan"))


class TestJar(unittest.TestCase):
    def setUp(self):
        self.jar = CookieJar()

    def absorb(self, *headers, host="www.example.com", path="/"):
        return self.jar.absorb(
            [("Set-Cookie", h) for h in headers] + [("Server", "nginx")], host, path
        )

    def test_absorb_counts_only_cookies(self):
        self.assertEqual(self.absorb("a=1", "b=2"), 2)
        self.assertEqual(len(self.jar), 2)

    def test_header_renders_name_value_pairs(self):
        self.absorb("a=1", "b=2")
        self.assertEqual(self.jar.header_for("www.example.com", "/"), "a=1; b=2")

    def test_no_match_returns_none(self):
        self.absorb("a=1")
        self.assertIsNone(self.jar.header_for("other.test", "/"))

    def test_host_only_does_not_reach_subdomains(self):
        self.absorb("a=1", host="example.com")
        self.assertIsNone(self.jar.header_for("www.example.com", "/"))

    def test_domain_cookie_reaches_subdomains(self):
        self.absorb("a=1; Domain=example.com", host="www.example.com")
        self.assertEqual(self.jar.header_for("shop.example.com", "/"), "a=1")

    def test_path_scoping(self):
        self.absorb("deep=1; Path=/admin")
        self.assertIsNone(self.jar.header_for("www.example.com", "/"))
        self.assertEqual(self.jar.header_for("www.example.com", "/admin/x"), "deep=1")

    def test_secure_cookies_are_withheld_from_insecure_requests(self):
        self.absorb("a=1; Secure")
        self.assertIsNone(self.jar.header_for("www.example.com", "/", secure=False))
        self.assertEqual(self.jar.header_for("www.example.com", "/"), "a=1")

    def test_replacement_keeps_the_original_creation_time(self):
        # Ordering depends on creation time, so an update must not reorder.
        self.absorb("a=1", "b=2")
        created = {c.name: c.created for c in self.jar}
        self.absorb("a=9")
        self.assertEqual(self.jar.header_for("www.example.com", "/"), "a=9; b=2")
        self.assertEqual(
            next(c.created for c in self.jar if c.name == "a"), created["a"]
        )

    def test_longer_paths_come_first(self):
        self.absorb("root=1; Path=/")
        self.absorb("deep=1; Path=/a/b")
        self.absorb("mid=1; Path=/a")
        self.assertEqual(
            self.jar.header_for("www.example.com", "/a/b/c"), "deep=1; mid=1; root=1"
        )

    def test_expired_cookies_are_dropped_on_read(self):
        self.absorb("a=1")
        self.jar.set(Cookie("stale", "x", "www.example.com", "/",
                            expires=time.time() - 1))
        self.assertEqual(self.jar.header_for("www.example.com", "/"), "a=1")
        self.assertEqual(len(self.jar), 1)

    def test_a_deleting_set_cookie_removes_the_stored_one(self):
        self.absorb("a=1")
        self.absorb("a=1; Max-Age=0")
        self.assertEqual(len(self.jar), 0)

    def test_same_name_different_path_coexist(self):
        self.absorb("a=root; Path=/")
        self.absorb("a=deep; Path=/x")
        self.assertEqual(len(self.jar), 2)
        self.assertEqual(self.jar.header_for("www.example.com", "/x"), "a=deep; a=root")

    def test_clear(self):
        self.absorb("a=1")
        self.jar.clear()
        self.assertEqual(len(self.jar), 0)


if __name__ == "__main__":
    unittest.main()
