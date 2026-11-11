"""Host names, cookies and redirects, against hostile input.

C1-C8 and F3 of the 2026-11-11 review. No network: loopback servers from
`tests/hostile.py` and scripted transports.
"""

from __future__ import annotations

import time
import unittest

from pybrws.client import split_target
from pybrws.cookies import domain_matches, parse_set_cookie
from pybrws.emitter import build_client_hello
from pybrws.parser import parse_client_hello
from pybrws.profiles import chrome155, firefox157
from pybrws.session import split_url
from pybrws.wire import u8, vector

from tests import hostile


class TestHostNames(unittest.TestCase):
    """C7, C8: an IPv6 literal goes in brackets in an authority, and an
    international name goes on the wire in the A-label form browsers use
    (UTS #46 non-transitional, IDNA 2008), not Python's IDNA 2003."""

    def test_ipv6_authority_is_bracketed(self):
        from pybrws import h3

        for split in (split_target, split_url, h3.split_target):
            with self.subTest(split=split.__module__):
                host, port, authority, path = split("https://[::1]:8443/x")
                self.assertEqual((host, port, authority, path),
                                 ("::1", 8443, "[::1]:8443", "/x"))

    def test_idna_2008(self):
        from pybrws.hosts import ascii_host

        self.assertEqual(ascii_host("faß.de"), "xn--fa-hia.de")

    def test_ascii_names_pass_through(self):
        # IDNA 2008 itself would refuse an underscore; browsers do not.
        from pybrws.hosts import ascii_host

        self.assertEqual(ascii_host("a_b.Example.com"), "a_b.example.com")
        self.assertEqual(ascii_host("::1"), "::1")

    def test_sni_uses_idna_2008(self):
        for profile in (firefox157, chrome155):
            with self.subTest(profile=profile.NAME):
                self.assertIn(b"xn--fa-hia.de",
                              build_client_hello("faß.de", profile=profile))

    def test_ascii_host_server_name_unchanged(self):
        hello = parse_client_hello(build_client_hello("example.com"))
        self.assertEqual(hello.extension(0).data,
                         vector(u8(0) + vector(b"example.com", 2), 2))

    def test_url_authority_uses_the_a_label(self):
        host, _port, authority, _path = split_target("https://faß.de/")
        self.assertEqual((host, authority), ("xn--fa-hia.de", "xn--fa-hia.de"))


class TestIpLiterals(unittest.TestCase):
    """F3: RFC 6066 3 forbids an IP address in server_name, and Firefox sends
    none -- the bare-IP capture in the notebook's phase 1 entry was 1869
    bytes, the 1901 of the reference less its 32-byte server_name. And an IP
    is checked against the certificate's IP address SAN, not as a DNS name."""

    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_ip_literal_hello_has_no_server_name_and_measured_length(self):
        hello = build_client_hello("127.0.0.1", profile=firefox157)
        self.assertNotIn(0, parse_client_hello(hello).extension_types())
        self.assertEqual(len(hello), 1869)

    def test_chrome155_ip_literal_has_no_server_name(self):
        hello = build_client_hello("127.0.0.1", profile=chrome155)
        self.assertNotIn(0, parse_client_hello(hello).extension_types())

    def test_verify_chain_accepts_ip_san(self):
        from cryptography.hazmat.primitives import serialization

        from pybrws.certs import verify_chain

        certificate, _key = hostile.leaf(self.ca, "127.0.0.1")
        der = certificate.public_bytes(serialization.Encoding.DER)
        self.assertEqual(verify_chain([der], "127.0.0.1", self.store), certificate)

    def test_ipv6_literal_connects_with_verification(self):
        from pybrws.handshake import connect

        def script(peer):
            peer.handshake()
            peer.send_app(b"pong:" + peer.read_app())

        server = hostile.Tls13Server(script, ca=self.ca, host="::1", bind="::1")
        server.start()
        with connect("::1", server.port, trust_store=self.store, timeout=5) as tls:
            tls.send(b"ping")
            self.assertEqual(tls.recv(), b"pong:ping")
        server.join(5)
        self.assertEqual(server.errors, [])


class TestPublicSuffixes(unittest.TestCase):
    """C1: RFC 6265 5.3 step 5. A Domain attribute that is a public suffix
    would reach every site under it, so the cookie is ignored -- unless the
    suffix is the request host itself, where it is merely host-only."""

    def test_public_suffix_domain_is_ignored(self):
        for host, domain in (("attacker.com", "com"), ("evil.co.uk", "co.uk"),
                             ("evil.github.io", "github.io")):
            with self.subTest(domain=domain):
                self.assertIsNone(parse_set_cookie("s=1; Domain=" + domain, host, "/"))

    def test_registrable_domain_still_widens(self):
        cookie = parse_set_cookie("s=1; Domain=example.com", "www.example.com", "/")
        self.assertEqual((cookie.domain, cookie.host_only), ("example.com", False))

    def test_public_suffix_equal_to_host_is_host_only(self):
        # Review Focus 3: kept, not dropped.
        cookie = parse_set_cookie("s=1; Domain=github.io", "github.io", "/")
        self.assertEqual((cookie.domain, cookie.host_only), ("github.io", True))

    def test_an_ip_host_never_widens(self):
        # RFC 6265 5.1.3: the suffix case of domain-match is for host names
        # only. Otherwise 127.0.0.1 could set a cookie that 10.0.0.1 receives.
        cookie = parse_set_cookie("s=1; Domain=0.0.1", "127.0.0.1", "/")
        self.assertEqual((cookie.domain, cookie.host_only), ("127.0.0.1", True))
        self.assertFalse(domain_matches("10.0.0.1", "0.0.1"))

    def test_the_last_domain_attribute_is_the_one_checked(self):
        # RFC 6265 5.3 step 4: an earlier, acceptable Domain does not launder
        # a later public suffix.
        self.assertIsNone(parse_set_cookie(
            "s=1; Domain=example.com; Domain=com", "www.example.com", "/"))


class TestControlCharacters(unittest.TestCase):
    """C2, C3: a byte that ends a header line must never reach a writer, and
    a byte that merely is not ASCII must travel unchanged."""

    @staticmethod
    def session_over(scripts_by_host):
        """A Session whose connections replay scripts, chosen by host."""
        from pybrws.http1 import Http1Connection
        from pybrws.session import Session

        opened = []

        def fake_open(host, port, timeout=None):
            tls = hostile.ScriptedTls(scripts_by_host[host].pop(0), alpn="http/1.1")
            opened.append((host, tls))
            return tls, Http1Connection(tls)

        session = Session(proxy=False)
        session._open = fake_open
        return session, opened

    def test_cookie_with_crlf_is_rejected(self):
        # RFC 6265bis 5.6 step 1: any CTL but HTAB, anywhere in the string.
        for header in ("s=a\r\nX: y", "s=a\nX: y", "s\r=a", "s=a\x00b",
                       "s=a\x7fb", "s=a; Path=/\nX: y"):
            with self.subTest(header=header):
                self.assertIsNone(parse_set_cookie(header, "example.com", "/"))
        self.assertEqual(parse_set_cookie("s=a\tb", "example.com", "/").value, "a\tb")

    def test_cookie_cannot_inject_into_http1(self):
        # The review's proof of concept: a sibling host plants a cookie whose
        # bare LF would start a line of its choosing in www.example.com's request.
        session, opened = self.session_over({
            "evil.example.com": [[b"HTTP/1.1 200 OK\r\nSet-Cookie: t=1\nX-Injected: "
                                  b"yes; Domain=example.com\r\nContent-Length: 0\r\n\r\n"]],
            "www.example.com": [[b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]],
        })
        with session:
            session.get("https://evil.example.com/")
            session.get("https://www.example.com/")
        victim = b"".join(bytes(tls.sent) for host, tls in opened
                          if host == "www.example.com")
        self.assertNotIn(b"X-Injected", victim)
        self.assertEqual(victim.count(b"\n"), victim.count(b"\r\n"))

    def test_caller_header_with_crlf_raises_before_sending(self):
        from pybrws.http1 import Http1Connection
        from pybrws.http2 import Http2Connection

        bad = ({"X-A": "a\r\nInjected: 1"}, {"X-A": "a\nInjected: 1"},
               {"X-A": "a\x00"}, {"X-A\r\nInjected": "1"})
        for headers in bad:
            for kind, alpn in ((Http1Connection, "http/1.1"), (Http2Connection, "h2")):
                with self.subTest(kind=kind.__name__, headers=headers):
                    tls = hostile.ScriptedTls([], alpn=alpn)
                    connection = kind(tls)
                    before = len(tls.sent)   # HTTP/2 has sent its preface
                    with self.assertRaises(ValueError):
                        connection.request("GET", "/", "example.com",
                                           headers=list(headers.items()))
                    self.assertEqual(len(tls.sent), before)

    def test_http1_request_line_is_checked_too(self):
        from pybrws.http1 import Http1Connection

        tls = hostile.ScriptedTls([], alpn="http/1.1")
        with self.assertRaises(ValueError):
            Http1Connection(tls).request("GET", "/a\r\nInjected: 1", "example.com")
        self.assertEqual(bytes(tls.sent), b"")

    def test_http2_refused_header_leaves_no_open_stream(self):
        from pybrws.http2 import Http2Connection

        connection = Http2Connection(hostile.ScriptedTls([]))
        first = connection.next_stream_id
        with self.assertRaises(ValueError):
            connection.send_request("GET", "/", "example.com",
                                    headers=[("x-a", "a\nb")])
        self.assertEqual((connection.next_stream_id, connection._open), (first, {}))

    def test_h3_fields_are_checked(self):
        from pybrws import h3

        with self.assertRaises(ValueError):
            h3.request_fields("GET", "/", "example.com", [("x-a", "a\r\nb")])
        self.assertIn((b"x-a", b"\xe2\x82\xac"),
                      h3.request_fields("GET", "/", "example.com",
                                        [("X-A", "\xe2\x82\xac")]))

    def test_sidecar_does_not_forward_a_header_line_break(self):
        # The sidecar writes upstream headers into the local client's HTTP/1.1
        # response; an upstream's bare LF must not start a line there.
        from unittest import mock

        from pybrws import proxy
        from pybrws.message import Response

        upstream = Response(status=200, headers=[("X-A", "a\nSet-Cookie: planted=1")],
                            body=b"ok")
        with self.assertRaises(ValueError):
            proxy.serialise(upstream)
        sidecar = proxy.Proxy(ca=None, verbose=False)   # fetch needs no CA
        with mock.patch.object(proxy, "get", return_value=upstream):
            written = sidecar.fetch("https://example.com/")
        self.assertTrue(written.startswith(b"HTTP/1.1 502"))
        self.assertNotIn(b"planted", written)

    def test_received_h2_value_with_lf_is_malformed(self):
        # RFC 9113 8.2.1: CR, LF and NUL make the response malformed.
        from hpack import Encoder

        from pybrws.http2 import (FLAG_END_HEADERS, FLAG_END_STREAM, HEADERS,
                                  Http2Connection, Http2Error, frame)

        for value in (b"t=1\nX-Injected: yes", b"t=1\rX", b"t=\x001"):
            with self.subTest(value=value):
                block = Encoder().encode([(b":status", b"200"), (b"set-cookie", value)])
                tls = hostile.ScriptedTls([frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM,
                                                 firefox157.H2_FIRST_STREAM_ID, block)])
                connection = Http2Connection(tls)
                with self.assertRaises(Http2Error) as caught:
                    connection.read_response(
                        connection.send_request("GET", "/", "example.com"))
                self.assertIn("PROTOCOL_ERROR", str(caught.exception))
                self.assertTrue(connection.broken)

    def test_non_ascii_cookie_round_trips_over_http1(self):
        # C3: the bytes of "\u20ac" in UTF-8 come back exactly as they were set.
        session, opened = self.session_over({"example.com": [[
            b"HTTP/1.1 200 OK\r\nSet-Cookie: s=\xe2\x82\xac\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ]]})
        with session:
            session.get("https://example.com/")
            session.get("https://example.com/next")
        sent = b"".join(bytes(tls.sent) for _host, tls in opened)
        self.assertIn(b"\r\nCookie: s=\xe2\x82\xac\r\n", sent)


class TestCookieAge(unittest.TestCase):
    """C4: a Max-Age of hundreds of digits overflowed a float after the
    response had arrived, and Session.get lost the response."""

    def test_huge_max_age_is_clamped(self):
        from pybrws.cookies import MAX_COOKIE_AGE

        before = time.time()
        cookie = parse_set_cookie("a=b; Max-Age=" + "9" * 400, "a.test", "/")
        self.assertLessEqual(cookie.expires, time.time() + MAX_COOKIE_AGE)
        self.assertGreaterEqual(cookie.expires, before + MAX_COOKIE_AGE)

    def test_far_expires_is_clamped_too(self):
        from pybrws.cookies import MAX_COOKIE_AGE

        cookie = parse_set_cookie("a=b; Expires=Fri, 31 Dec 9999 23:59:59 GMT",
                                  "a.test", "/")
        self.assertLessEqual(cookie.expires, time.time() + MAX_COOKIE_AGE)

    def test_session_survives_huge_max_age(self):
        session, _opened = TestControlCharacters.session_over({"a.test": [[
            b"HTTP/1.1 200 OK\r\nSet-Cookie: a=b; Max-Age=" + b"9" * 400
            + b"\r\nContent-Length: 2\r\n\r\nok"]]})
        with session:
            response = session.get("https://a.test/")
        self.assertEqual((response.status, response.body), (200, b"ok"))


CREDENTIALS = [("Authorization", "Bearer s3cret"), ("Cookie", "caller=1"),
               ("Proxy-Authorization", "Basic cHJveHk=")]


def recording(answer: bytes, seen: list):
    """An openssl_server handler: keep the request head, send `answer`."""
    def handler(tls):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = tls.recv(4096)
            if not chunk:
                return
            data += chunk
        seen.append(data)
        tls.sendall(answer)
    return handler


class TestRedirectCredentials(unittest.TestCase):
    """C5: credentials the caller gave for one origin do not follow a
    redirect to another, as curl and requests behave. Same origin means
    the same scheme, host and port, however they are spelled."""

    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def assert_carries_none(self, head: bytes):
        for name, value in CREDENTIALS:
            self.assertNotIn(value.encode(), head, name)

    def test_client_drops_authorization_across_hosts(self):
        from pybrws import client

        first, second = [], []
        target = hostile.openssl_server(
            recording(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", second),
            ca=self.ca, host="localhost")
        start = hostile.openssl_server(
            recording(b"HTTP/1.1 302 Found\r\nLocation: https://localhost:%d/next\r\n"
                      b"Content-Length: 0\r\n\r\n" % target, first),
            ca=self.ca, host="127.0.0.1")
        response = client.get("https://127.0.0.1:%d/" % start, headers=CREDENTIALS,
                               follow_redirects=1, proxy=False,
                               trust_store=self.store, timeout=5)
        self.assertEqual(response.status, 200)
        self.assertIn(b"Bearer s3cret", first[0])
        self.assert_carries_none(second[0])

    def test_session_drops_caller_cookie_across_hosts(self):
        session, opened = TestControlCharacters.session_over({
            "a.example": [[b"HTTP/1.1 302 Found\r\nLocation: https://b.example/\r\n"
                           b"Content-Length: 0\r\n\r\n"]],
            "b.example": [[b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]],
        })
        with session:
            session.get("https://a.example/", headers=CREDENTIALS, follow_redirects=1)
        heads = {host: bytes(tls.sent) for host, tls in opened}
        self.assertIn(b"caller=1", heads["a.example"])
        self.assert_carries_none(heads["b.example"])

    def test_cli_http3_path_drops_authorization(self):
        import argparse
        from unittest import mock

        from pybrws import cli, h3
        from pybrws.message import Response

        sent = []
        answers = iter([Response(status=302, headers=[("location", "https://b.example/")]),
                        Response(status=200)])

        def fake_get(url, **kwargs):
            sent.append(list(kwargs.get("headers") or []))
            return next(answers)

        args = argparse.Namespace(url="https://a.example/", timeout=5, location=True,
                                  max_redirs=5, insecure=False)
        with mock.patch.object(h3, "get", side_effect=fake_get):
            self.assertEqual(cli.fetch_http3(args, firefox157, list(CREDENTIALS)).status, 200)
        self.assertEqual(sent[0], CREDENTIALS)
        self.assertEqual(sent[1], [])

    def test_same_origin_spelled_differently_keeps_credentials(self):
        # Review Focus 2.
        from pybrws.client import redirect_headers, same_origin

        for a, b in (("https://localhost/", "https://LOCALHOST:443/x"),
                     ("https://fa\u00df.de/", "https://xn--fa-hia.de/"),
                     ("https://[::1]/", "https://[0:0::1]:443/")):
            with self.subTest(a=a, b=b):
                self.assertTrue(same_origin(a, b))
                self.assertEqual(redirect_headers(CREDENTIALS, a, b), CREDENTIALS)

    def test_other_port_drops_credentials(self):
        from pybrws.client import redirect_headers, same_origin

        kept = [("X-Keep", "1")]
        for b in ("https://localhost:8443/", "http://localhost/", "https://other.test/"):
            with self.subTest(to=b):
                self.assertFalse(same_origin("https://localhost/", b))
                self.assertEqual(redirect_headers(
                    CREDENTIALS[:1] + kept + [("cookie", "c"), ("PROXY-AUTHORIZATION", "p")],
                    "https://localhost/", b), kept)
        self.assertEqual(redirect_headers({"authorization": "a", "X-Keep": "1"},
                                          "https://a.test/", "https://b.test/"), kept)
        self.assertIsNone(redirect_headers(None, "https://a.test/", "https://b.test/"))


class TestHttp3Redirects(unittest.TestCase):
    """C6: the CLI's HTTP/3 loop answers the same question as the TCP one."""

    @staticmethod
    def args(location: bool):
        import argparse

        return argparse.Namespace(url="https://a.example/", timeout=5,
                                  location=location, max_redirs=5, insecure=False)

    def test_http3_no_location_prints_the_redirect(self):
        import contextlib
        import io
        from unittest import mock

        from pybrws import cli, h3
        from pybrws.message import Response

        redirect = Response(status=302, headers=[("location", "https://b.example/")],
                            http_version="h3")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(h3, "get", return_value=redirect) as get, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--http3", "--no-location", "-I", "https://a.example/"])
        self.assertEqual((code, get.call_count), (0, 1))
        self.assertIn("302", out.getvalue())

    def test_http3_follows_only_redirect_statuses(self):
        # Fetch's redirect statuses, as client.request and Session use.
        from unittest import mock

        from pybrws import cli, h3
        from pybrws.message import Response

        not_modified = Response(status=304, headers=[("location", "https://b.example/")])
        with mock.patch.object(h3, "get", return_value=not_modified) as get:
            response = cli.fetch_http3(self.args(location=True), firefox157, [])
        self.assertEqual((response.status, get.call_count), (304, 1))


if __name__ == "__main__":
    unittest.main()
