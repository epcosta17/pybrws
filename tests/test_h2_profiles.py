"""The HTTP/2 header sets, against captures taken with tools/catch_h2.py.

These were inferred from the HTTP/1.1 order until the capture server existed.
The fixtures are the decoded field list in wire order, one per line, so the
assertions are about sequence rather than bytes.
"""

import unittest
from pathlib import Path

from pybrws.cookies import Cookie
from pybrws.profiles import firefox157
from pybrws.session import Session

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def fields(name):
    """Field names in order, pseudo-headers dropped."""
    text = (FIXTURES / name).read_text(encoding="utf-8")
    head = text.split("\n\n", 1)[0]
    return [line.split(":", 1)[0] for line in head.splitlines()
            if line and not line.startswith(":")]


class TestNavigation(unittest.TestCase):
    def test_matches_the_profile_exactly(self):
        self.assertEqual(fields("reference-firefox-157-h2.txt"),
                         [n for n, _ in firefox157.H2_NAVIGATION_HEADERS])


class TestPost(unittest.TestCase):
    def test_the_derivation_rule_holds(self):
        # The HTTP/2 POST set is derived from the HTTP/1.1 one. The capture
        # carried cookies from an earlier run, which the profile has no
        # opinion about here.
        captured = [f for f in fields("reference-firefox-157-h2-post.txt")
                    if f != "cookie"]
        self.assertEqual(captured, [n for n, _ in firefox157.H2_POST_XHR_HEADERS])


class TestCookieCrumbling(unittest.TestCase):
    CAPTURE = "reference-firefox-157-h2-cookie.txt"

    def test_firefox_sends_one_field_per_cookie(self):
        self.assertEqual(fields(self.CAPTURE).count("cookie"), 2,
                         "two cookies, two fields, not one joined header")

    def test_the_fields_are_adjacent(self):
        names = fields(self.CAPTURE)
        first = names.index("cookie")
        self.assertEqual(names[first + 1], "cookie")

    def test_they_precede_upgrade_insecure_requests(self):
        names = fields(self.CAPTURE)
        self.assertLess(names.index("cookie"),
                        names.index("upgrade-insecure-requests"))
        self.assertEqual(firefox157.H2_COOKIE_BEFORE, "upgrade-insecure-requests")

    def test_values_are_not_joined(self):
        text = (FIXTURES / self.CAPTURE).read_text(encoding="utf-8")
        self.assertIn("cookie: pybrws_probe=1", text)
        self.assertIn("cookie: pybrws_second=2", text)
        self.assertNotIn("; pybrws_second", text)


class TestSessionReproducesIt(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.addCleanup(self.session.close)
        self.session.cookies.set(Cookie("pybrws_probe", "1", "a.test", "/"))
        self.session.cookies.set(Cookie("pybrws_second", "2", "a.test", "/"))

    def test_http2_crumbles(self):
        built = self.session._headers_for("a.test", "/", True, None)
        cookies = [value for name, value in built if name == "cookie"]
        self.assertEqual(cookies, ["pybrws_probe=1", "pybrws_second=2"])

    def test_http2_places_them_at_the_anchor(self):
        names = [n for n, _ in self.session._headers_for("a.test", "/", True, None)]
        self.assertEqual(names.count("cookie"), 2)
        self.assertEqual(names[names.index("cookie") + 2],
                         firefox157.H2_COOKIE_BEFORE)

    def test_http1_joins_them_instead(self):
        # The HTTP/1.1 capture shows one header carrying both, so the two
        # protocols genuinely differ here and the code must too.
        built = self.session._headers_for("a.test", "/", False, None)
        cookies = [value for name, value in built if name == "Cookie"]
        self.assertEqual(cookies, ["pybrws_probe=1; pybrws_second=2"])


if __name__ == "__main__":
    unittest.main()
