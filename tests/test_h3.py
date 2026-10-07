"""Tests for pybrws.h3 that need no network.

The request layer is the half of HTTP/3 that is not measured yet, so what is
asserted here is mostly that the unmeasured parts are the ones named as
unmeasured, and that the measured parts are wired to the profile rather than
retyped.
"""

import unittest

from pathlib import Path

from pybrws import h3
from pybrws.profiles import firefox157
from pybrws.profiles import firefox157_quic as profile


class TestSplitTarget(unittest.TestCase):
    def test_a_plain_url(self):
        self.assertEqual(h3.split_target("https://a.test/x?y=1"),
                         ("a.test", 443, "a.test", "/x?y=1"))

    def test_an_explicit_port_reaches_the_authority(self):
        self.assertEqual(h3.split_target("https://a.test:4433/"),
                         ("a.test", 4433, "a.test:4433", "/"))

    def test_the_default_port_does_not(self):
        _host, _port, authority, _path = h3.split_target("https://a.test:443/")
        self.assertEqual(authority, "a.test")

    def test_an_empty_path_becomes_a_slash(self):
        self.assertEqual(h3.split_target("https://a.test")[3], "/")

    def test_http_is_refused(self):
        # QUIC has no plaintext mode, so this is not a limitation to work
        # around but a URL that cannot mean anything.
        with self.assertRaises(h3.Http3Error):
            h3.split_target("http://a.test/")

    def test_a_url_with_no_host_is_refused(self):
        with self.assertRaises(h3.Http3Error):
            h3.split_target("https:///path")


class TestPseudoHeaders(unittest.TestCase):
    def test_the_order_comes_from_the_profile(self):
        fields = h3._pseudo("GET", "/p", "a.test")
        self.assertEqual([name.decode() for name, _ in fields],
                         list(h3.PSEUDO_ORDER))

    def test_the_method_is_upper_cased(self):
        fields = dict(h3._pseudo("get", "/", "a.test"))
        self.assertEqual(fields[b":method"], b"GET")

    def test_the_scheme_is_always_https(self):
        fields = dict(h3._pseudo("GET", "/", "a.test"))
        self.assertEqual(fields[b":scheme"], b"https")

    def test_all_four_are_present(self):
        self.assertEqual(len(h3._pseudo("GET", "/", "a.test")), 4)

    def test_the_order_is_measured_and_is_not_the_http2_one(self):
        # This started as the HTTP/2 order, taken on faith. curl_cffi's
        # firefox target disagreed, the capture settled it, and curl_cffi was
        # right. Both are asserted here so the contrast is recorded in one
        # place rather than inferred from two files.
        self.assertEqual(h3.PSEUDO_ORDER,
                         (":method", ":scheme", ":authority", ":path"))
        self.assertEqual(firefox157.H2_PSEUDO_ORDER,
                         (":method", ":path", ":authority", ":scheme"))
        self.assertNotEqual(h3.PSEUDO_ORDER, firefox157.H2_PSEUDO_ORDER)


FIXTURE = (Path(__file__).resolve().parent.parent / "fixtures"
           / "reference-firefox-157-quic-request.txt")


def captured_request() -> list[tuple[str, str]]:
    """The measured request, parsed out of the fixture."""
    fields = []
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition(": ")
        fields.append((name, value))
    return fields


class TestAgainstTheCapture(unittest.TestCase):
    """The measured HTTP/3 navigation request."""

    @classmethod
    def setUpClass(cls):
        cls.captured = captured_request()
        cls.authority = dict(cls.captured)[":authority"]

    def test_the_pseudo_order_matches(self):
        pseudo = [n for n, _ in self.captured if n.startswith(":")]
        self.assertEqual(tuple(pseudo), h3.PSEUDO_ORDER)

    def test_the_header_names_and_order_match(self):
        theirs = [n for n, _ in self.captured if not n.startswith(":")]
        ours = [n.lower() for n, _ in
                profile.navigation_headers(self.authority)]
        self.assertEqual(ours, [n.lower() for n in theirs])

    def test_every_header_value_matches(self):
        theirs = {n.lower(): v for n, v in self.captured
                  if not n.startswith(":")}
        for name, value in profile.navigation_headers(self.authority):
            with self.subTest(header=name):
                self.assertEqual(value, theirs[name.lower()])

    def test_alt_used_carries_the_authority(self):
        # RFC 7838. It is the one value in the set that belongs to the
        # request rather than to the profile.
        filled = dict((n.lower(), v) for n, v in
                      profile.navigation_headers("example.test"))
        self.assertEqual(filled["alt-used"], "example.test")

    def test_alt_used_sits_after_accept_encoding(self):
        names = [n.lower() for n, _ in profile.H3_NAVIGATION_HEADERS]
        self.assertEqual(names[names.index("alt-used") - 1], "accept-encoding")

    def test_te_is_not_sent(self):
        # `te: trailers` is an HTTP/2 mechanism and the capture does not
        # carry it, which the HTTP/2 profile does.
        names = [n.lower() for n, _ in profile.H3_NAVIGATION_HEADERS]
        self.assertNotIn("te", names)
        self.assertIn("te", [n.lower() for n, _
                             in firefox157.H2_NAVIGATION_HEADERS])

    def test_the_shared_headers_keep_their_http2_values_and_order(self):
        # The guess this replaced was not worthless: ten of the eleven
        # headers transferred from HTTP/2 unchanged, in order. The two it got
        # wrong both sit in the first four fields of every request.
        h2 = [(n.lower(), v) for n, v in firefox157.H2_NAVIGATION_HEADERS]
        h3_set = [(n.lower(), v) for n, v
                  in profile.navigation_headers(self.authority)]
        h3_names = {n for n, _ in h3_set}
        h2_names = {n for n, _ in h2}
        shared = h2_names & h3_names
        self.assertEqual(len(shared), 10)
        self.assertEqual([p for p in h2 if p[0] in shared],
                         [p for p in h3_set if p[0] in shared])


class TestTheModuleStandsAlone(unittest.TestCase):
    def test_importing_it_does_not_need_aioquic(self):
        # aioquic is imported inside the functions that use it, so that
        # `import pybrws.h3` works wherever the rest of the client does.
        import sys

        class Block:
            def find_module(self, name, path=None):
                return self if name.split(".")[0] == "aioquic" else None

            def load_module(self, name):
                raise ImportError("aioquic hidden for this check")

        blocker = Block()
        saved = dict(sys.modules)
        for name in list(sys.modules):
            if name.split(".")[0] in ("aioquic", "pybrws"):
                del sys.modules[name]
        sys.meta_path.insert(0, blocker)
        try:
            import pybrws.h3 as reloaded

            self.assertTrue(reloaded.PSEUDO_ORDER)
        finally:
            sys.meta_path.remove(blocker)
            sys.modules.clear()
            sys.modules.update(saved)


if __name__ == "__main__":
    unittest.main()
