"""pybrws.tools.ab_test: what counts as served (M1 of the 2026-11-11 review),
and what each arm sends under --profile."""

from __future__ import annotations

import contextlib
import io
import unittest
from unittest import mock

from pybrws.profiles import chrome155, firefox157
from pybrws.tools import ab_test

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None


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


class TestProfileArms(unittest.TestCase):
    """httpx+ff is the control for the headers, so it has to carry the
    headers the pybrws arm sends, whichever profile that is. And the log's
    `profile` field names what each arm sent. Offline: the arms below are
    stand-ins, and httpx answers from a MockTransport."""

    def logged_profiles(self, profile) -> dict[str, str]:
        def page(target, timeout):
            return 200, b"<html>the page</html>"

        arms = {name: page for name in ab_test.ALL_CLIENTS}
        with mock.patch.object(ab_test, "PROFILE", profile), \
                mock.patch.object(ab_test, "CLIENTS", arms), \
                contextlib.redirect_stdout(io.StringIO()):
            samples = ab_test.run(["https://a.test/"], rounds=1, timeout=1.0,
                                  pause=0)
        return {sample["client"]: sample["profile"] for sample in samples}

    def test_each_arm_logs_the_profile_it_sent(self):
        self.assertEqual(self.logged_profiles(chrome155), {
            "pybrws": "chrome155",
            "httpx+ff": "chrome155",
            "httpx": "firefox157",
            "pybrws-h3": "firefox157_quic",
        })

    def test_the_default_profile_logs_as_it_always_has(self):
        self.assertEqual(self.logged_profiles(firefox157), {
            "pybrws": "firefox157",
            "httpx+ff": "firefox157",
            "httpx": "firefox157",
            "pybrws-h3": "firefox157_quic",
        })

    @unittest.skipIf(httpx is None, "httpx is not installed")
    def test_httpx_ff_carries_the_profile_headers(self):
        for profile in (firefox157, chrome155):
            with self.subTest(profile=profile.NAME):
                sent = []

                def answer(request):
                    sent.append(request.headers.multi_items())
                    return httpx.Response(200, content=b"the page")

                real_client = httpx.Client

                def offline(**options):
                    return real_client(transport=httpx.MockTransport(answer),
                                       **options)

                with mock.patch.object(httpx, "Client", offline), \
                        mock.patch.object(ab_test, "PROFILE", profile):
                    status, _ = ab_test.via_baseline_ff("https://a.test/", 1.0)

                self.assertEqual(status, 200)
                self.assertEqual(sent, [[("host", "a.test")] + [
                    (name.lower(), value)
                    for name, value in profile.H2_NAVIGATION_HEADERS]])


if __name__ == "__main__":
    unittest.main()
