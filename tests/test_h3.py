"""Tests for pybrws.h3 that need no network.

The request layer is the half of HTTP/3 that is not measured yet, so what is
asserted here is mostly that the unmeasured parts are the ones named as
unmeasured, and that the measured parts are wired to the profile rather than
retyped.
"""

import unittest

from pybrws import h3
from pybrws.profiles import firefox157


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

    def test_the_order_is_the_http2_one_and_is_not_measured(self):
        # Named rather than silent: this was taken from the TCP profile on
        # faith, and curl_cffi's firefox target disagrees with it, sending
        # :method :scheme :authority :path over HTTP/3. One of the two is
        # wrong about Firefox and only a capture can say which.
        self.assertEqual(h3.PSEUDO_ORDER, firefox157.H2_PSEUDO_ORDER)


class TestDefaultHeaders(unittest.TestCase):
    def test_they_come_from_the_http2_navigation_set(self):
        self.assertIs(h3.DEFAULT_HEADERS, firefox157.H2_NAVIGATION_HEADERS)

    def test_they_are_not_empty(self):
        # Sending only the four pseudo-headers is what an empty list gives,
        # and no browser has ever done that: no Accept, no Accept-Language,
        # no Accept-Encoding. Measured against curl_cffi's firefox147 over
        # HTTP/3, this set matches its header order exactly, which is the one
        # part of the request layer with a second opinion behind it.
        names = [name.lower() for name, _ in h3.DEFAULT_HEADERS]
        for required in ("accept", "accept-language", "accept-encoding",
                         "user-agent"):
            self.assertIn(required, names)


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
