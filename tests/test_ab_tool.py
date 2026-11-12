"""pybrws.tools.ab_test: what counts as served (M1 of the 2026-11-11 review)."""

from __future__ import annotations

import unittest

from pybrws.tools import ab_test


class TestChallengeMarkers(unittest.TestCase):
    """M1: the markers come from small refusal pages and apply to small
    bodies only, as the notebook says content heuristics must. A real page
    that mentions "Access Denied" is a page, and scoring it refused
    understates every arm that reached it."""

    @classmethod
    def setUpClass(cls):
        cls.tool = ab_test

    def test_large_page_mentioning_access_denied_is_served(self):
        body = (b"<html><head><title>Access Denied: a film review</title></head>"
                + b"<p>" + b"x" * 300_000 + b"</p></html>")
        self.assertTrue(self.tool.arrived((200, body)))

    def test_small_challenge_page_is_not_served(self):
        # The size of the Akamai reload shell macys answered with, as a 200.
        body = b"<html>Powered and protected by Akamai</html>".ljust(2843, b" ")
        self.assertEqual(len(body), 2843)
        self.assertFalse(self.tool.arrived((200, body)))

    def test_the_limit(self):
        self.assertEqual(self.tool.CHALLENGE_BODY_LIMIT, 100_000)


if __name__ == "__main__":
    unittest.main()
