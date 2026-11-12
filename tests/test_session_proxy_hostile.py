"""Session, Fetcher, proxies and the sidecar, against hostile conditions.

S1-S3, F2, P1, P2 and X1 of the 2026-11-11 review. No network: scripted
transports behind a patched `connect`, and loopback servers from
`tests/hostile.py`.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from hpack import Encoder

from pybrws import session as session_module
from pybrws.http2 import (FLAG_END_HEADERS, FLAG_END_STREAM, GOAWAY, HEADERS,
                          StreamRefused, frame)
from pybrws.profiles import firefox157
from pybrws.session import Session

from tests import hostile

OK_H1 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
SID = firefox157.H2_FIRST_STREAM_ID


def h2_ok() -> bytes:
    return frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, SID,
                 Encoder().encode([(b":status", b"200")]))


def goaway(last_stream_id: int, code: int = 0) -> bytes:
    return frame(GOAWAY, 0, 0, last_stream_id.to_bytes(4, "big") + code.to_bytes(4, "big"))


class Transports:
    """Patches session.connect to hand out scripted transports in order."""

    def __init__(self, *scripts, alpn: str = "http/1.1") -> None:
        self.made = [hostile.ScriptedTls(script, alpn=alpn) for script in scripts]
        self._queue = list(self.made)
        self.patch = mock.patch.object(session_module, "connect", side_effect=self._next)

    def _next(self, *args, **kwargs):
        if not self._queue:
            raise AssertionError("the client opened one connection too many")
        return self._queue.pop(0)

    def sent(self) -> bytes:
        return b"".join(bytes(tls.sent) for tls in self.made)

    def __enter__(self):
        self.patch.start()
        return self

    def __exit__(self, *exc):
        self.patch.stop()


class TestRetryPolicy(unittest.TestCase):
    """S1, S2, D5: a request is sent again only when that cannot repeat
    an action the server already took."""

    def test_post_is_not_retried_after_timeout(self):
        # The review's proof of concept: the server was still processing
        # POST /pay when the client gave up, and the retry paid twice.
        with Transports([OK_H1, TimeoutError("timed out")], [OK_H1]) as transports:
            with Session(proxy=False) as session:
                session.get("https://example.com/")
                with self.assertRaises(TimeoutError):
                    session.post("https://example.com/pay", data=b"amount=100")
        self.assertEqual(transports.sent().count(b"POST /pay "), 1)

    def test_get_is_still_retried_on_stale_connection(self):
        # A pooled connection the server had closed: nothing came back, and
        # a GET is safe to send again.
        with Transports([OK_H1, EOFError()], [OK_H1]) as transports:
            with Session(proxy=False) as session:
                session.get("https://example.com/")
                self.assertEqual(session.get("https://example.com/again").status, 200)
        self.assertEqual(transports.sent().count(b"GET /again "), 2)

    def test_get_is_not_retried_once_the_answer_began(self):
        with Transports([OK_H1, b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\npart",
                         TimeoutError("timed out")], [OK_H1]) as transports:
            with Session(proxy=False) as session:
                session.get("https://example.com/")
                with self.assertRaises(Exception):
                    session.get("https://example.com/again")
        self.assertEqual(transports.sent().count(b"GET /again "), 1)

    def test_post_is_retried_after_refused_stream(self):
        # GOAWAY below the stream: RFC 9113 6.8 guarantees it was never
        # processed, so even a POST goes again, once, on a fresh connection.
        with Transports([goaway(0)], [h2_ok()], alpn="h2") as transports:
            with Session(proxy=False) as session:
                response = session.post("https://example.com/pay", data=b"amount=100")
        self.assertEqual(response.status, 200)
        self.assertEqual(len([tls for tls in transports.made if tls.sent]), 2)

    def test_may_retry(self):
        from pybrws.session import IDEMPOTENT, may_retry

        self.assertEqual(IDEMPOTENT, frozenset({"GET", "HEAD", "OPTIONS"}))
        refused = StreamRefused("refused")
        for error in (refused, ConnectionRefusedError(), __import__("socket").gaierror()):
            self.assertTrue(may_retry("POST", error, False))
        self.assertTrue(may_retry("get", TimeoutError(), False))
        self.assertFalse(may_retry("GET", TimeoutError(), True))
        self.assertFalse(may_retry("POST", TimeoutError(), False))
        self.assertFalse(may_retry("PUT", ConnectionResetError(), False))


H1_503 = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"


class TestFetcherRetry(unittest.TestCase):
    """S3: the opt-in Retry follows the same method rule as the Session."""

    @staticmethod
    def fetcher():
        from pybrws.pool import Fetcher, Retry

        return Fetcher(proxy=False, retry=Retry(attempts=3, backoff=0))

    def test_fetcher_does_not_retry_post_on_503(self):
        with Transports([H1_503, OK_H1]) as transports, self.fetcher() as fetcher:
            result = fetcher.fetch("https://example.com/pay", method="POST", data=b"x")
        self.assertEqual((result.status, result.attempts, result.method), (503, 1, "POST"))
        self.assertEqual(transports.sent().count(b"POST /pay "), 1)

    def test_fetcher_retries_get_on_503(self):
        with Transports([H1_503, OK_H1]), self.fetcher() as fetcher:
            result = fetcher.fetch("https://example.com/")
        self.assertEqual((result.status, result.attempts, result.method), (200, 2, "GET"))

    def test_fetcher_retries_post_on_stream_refused(self):
        # The Session's own retry on a fresh connection is refused too; the
        # Fetcher's next attempt goes through.
        with Transports([goaway(0)], [goaway(0)], [h2_ok()], alpn="h2") as transports, \
                self.fetcher() as fetcher:
            result = fetcher.fetch("https://example.com/pay", method="POST", data=b"x")
        self.assertEqual((result.status, result.attempts), (200, 2))
        self.assertEqual(len(transports.made), 3)

    def test_fetcher_retries_get_on_timeout(self):
        with Transports([TimeoutError("timed out")], [OK_H1]), self.fetcher() as fetcher:
            result = fetcher.fetch("https://example.com/")
        self.assertEqual((result.status, result.attempts), (200, 2))

    def test_fetcher_does_not_retry_post_on_timeout(self):
        with Transports([TimeoutError("timed out")], [OK_H1]) as transports, \
                self.fetcher() as fetcher:
            result = fetcher.fetch("https://example.com/pay", method="POST", data=b"x")
        self.assertIsInstance(result.error, TimeoutError)
        self.assertEqual(result.attempts, 1)
        self.assertEqual(transports.sent().count(b"POST /pay "), 1)


FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
POST_URL = "https://pybrws.127.0.0.1.nip.io:4443/submit"


class TestSessionHeaderSets(unittest.TestCase):
    """F2: a Session sends the measured set for the request it makes, as
    client.post does, instead of the GET navigation set with Content-Type
    and Content-Length tacked on at the end."""

    @staticmethod
    def first_request(call) -> bytes:
        with Transports([OK_H1]) as transports, Session(proxy=False) as session:
            call(session)
        return bytes(transports.made[0].sent)

    def test_session_post_matches_fetch_capture(self):
        sent = self.first_request(lambda s: s.post(POST_URL, json={"field": "value"}))
        self.assertEqual(sent, (FIXTURES / "reference-firefox-157-post-fetch.txt").read_bytes())

    def test_session_form_post_matches_click_capture(self):
        sent = self.first_request(
            lambda s: s.post(POST_URL, data={"field": "value"}, kind="form"))
        self.assertEqual(sent, (FIXTURES / "reference-firefox-157-post-click.txt").read_bytes())

    def test_session_get_unchanged(self):
        from pybrws.http1 import Http1Connection

        sent = self.first_request(lambda s: s.get("https://example.com/page?q=1"))
        expected = Http1Connection(hostile.ScriptedTls([], alpn="http/1.1")).build_request(
            "GET", "/page?q=1", "example.com", firefox157.H1_HEADERS)
        self.assertEqual(sent, expected)


def connect_proxy(seen: dict, context=None) -> int:
    """A loopback proxy, HTTPS if `context` is given: it records the first
    raw byte and the (decrypted) CONNECT head, then answers 200."""
    import socket
    import ssl
    import threading

    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(10)

    def serve():
        try:
            raw, _ = listener.accept()
            raw.settimeout(10)
            seen["first"] = raw.recv(1, socket.MSG_PEEK)
            try:
                conn = context.wrap_socket(raw, server_side=True) if context else raw
                with conn:
                    head = b""
                    while b"\r\n\r\n" not in head:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        head += chunk
                    seen["connect"] = head
                    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            except (ssl.SSLError, OSError) as exc:
                seen["error"] = exc
        finally:
            listener.close()

    threading.Thread(target=serve, daemon=True).start()
    return listener.getsockname()[1]


class TestProxyHop(unittest.TestCase):
    """P1, D7: an https:// proxy is spoken to over TLS, verified, so the
    Proxy-Authorization it is sent does not cross the network in clear."""

    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_https_proxy_speaks_tls_before_connect(self):
        from pybrws.proxies import open_socket

        seen = {}
        port = connect_proxy(seen, hostile.server_context(self.ca, "127.0.0.1"))
        sock = open_socket("example.com", 443, timeout=5,
                           proxy="https://user:secret@127.0.0.1:%d" % port,
                           proxy_ssl_context=hostile.client_context(self.ca))
        sock.close()
        self.assertEqual(seen["first"], b"\x16")   # a TLS handshake record
        self.assertIn(b"CONNECT example.com:443 HTTP/1.1\r\n", seen["connect"])
        self.assertIn(b"Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=", seen["connect"])

    def test_https_proxy_untrusted_certificate_fails(self):
        # Verified against the system store by default (D7): the test CA
        # is not in it, so the hop is refused before CONNECT is sent.
        from pybrws.proxies import ProxyError, open_socket

        seen = {}
        port = connect_proxy(seen, hostile.server_context(self.ca, "127.0.0.1"))
        with self.assertRaises(ProxyError) as caught:
            open_socket("example.com", 443, timeout=5,
                        proxy="https://user:secret@127.0.0.1:%d" % port)
        self.assertIn("certificate", str(caught.exception).lower())
        self.assertNotIn("connect", seen)

    def test_connect_brackets_an_ipv6_target(self):
        # C7 again, in the one authority the review did not list.
        from pybrws.proxies import open_socket

        seen = {}
        port = connect_proxy(seen)
        open_socket("::1", 8443, timeout=5, proxy="http://127.0.0.1:%d" % port).close()
        self.assertTrue(seen["connect"].startswith(
            b"CONNECT [::1]:8443 HTTP/1.1\r\nHost: [::1]:8443\r\n"))


class TestNoProxy(unittest.TestCase):
    """P2: NO_PROXY / no_proxy, the way requests reads it -- a comma list,
    an exact name or a domain suffix, or * for everything."""

    RULE = "example.com, .internal.test,10.0.0.1"

    def test_no_proxy_exact_and_suffix(self):
        from pybrws.proxies import bypass

        for host in ("example.com", "api.example.com", "API.Example.COM",
                     "internal.test", "a.internal.test", "10.0.0.1"):
            with self.subTest(host=host):
                self.assertTrue(bypass(host, self.RULE))
        for host in ("badexample.com", "example.org", "10.0.0.2"):
            with self.subTest(host=host):
                self.assertFalse(bypass(host, self.RULE))

    def test_no_proxy_star(self):
        from pybrws.proxies import bypass

        self.assertTrue(bypass("anything.test", "*"))
        self.assertFalse(bypass("anything.test", ""))

    def test_environment_proxy_skips_bypassed_hosts(self):
        import os

        from pybrws.proxies import resolve

        for variable in ("NO_PROXY", "no_proxy"):
            env = {"HTTPS_PROXY": "http://proxy.test:3128", variable: "example.com"}
            with self.subTest(variable=variable), mock.patch.dict(os.environ, env, clear=True):
                self.assertIsNone(resolve(None, "www.example.com"))
                self.assertEqual(resolve(None, "other.test").host, "proxy.test")

    def test_explicit_proxy_ignores_no_proxy(self):
        import os

        from pybrws.proxies import resolve

        with mock.patch.dict(os.environ, {"NO_PROXY": "*"}, clear=True):
            self.assertEqual(resolve("http://proxy.test:3128", "example.com").host,
                             "proxy.test")

    def test_bypassed_host_is_dialled_directly(self):
        # open_socket and the Session's pool key agree on it.
        import os

        from pybrws import proxies

        env = {"HTTPS_PROXY": "http://proxy.test:3128", "NO_PROXY": "example.com"}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(proxies.socket, "create_connection") as dial:
            dial.return_value.recv.return_value = b""   # a proxy would hang up
            proxies.open_socket("www.example.com", 443, timeout=5)
            self.assertEqual(dial.call_args.args[0], ("www.example.com", 443))
            self.assertIsNone(Session()._key("www.example.com", 443)[2])
            self.assertIsNotNone(Session()._key("other.test", 443)[2])


def mode_of(path) -> int:
    import stat

    return stat.S_IMODE(Path(path).stat().st_mode)


@unittest.skipUnless(__import__("os").name == "posix", "POSIX permissions")
class TestCaKeyPermissions(unittest.TestCase):
    """X1: the sidecar's CA key lets whoever reads it mint certificates the
    owner's browser trusts. It was written 0644 in a 0755 directory."""

    def setUp(self):
        import os
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self._tmp.name) / "ca"
        self._umask = os.umask(0o022)   # the common default, explicitly

    def tearDown(self):
        import os

        os.umask(self._umask)
        self._tmp.cleanup()

    def test_new_ca_key_is_0600_in_0700_directory(self):
        from pybrws.proxy import CertificateAuthority

        CertificateAuthority(self.directory)
        self.assertEqual(mode_of(self.directory), 0o700)
        self.assertEqual(mode_of(self.directory / "ca-key.pem"), 0o600)

    def test_existing_loose_key_is_tightened_with_a_warning(self):
        import contextlib
        import io
        import os

        from pybrws.proxy import CertificateAuthority

        first = CertificateAuthority(self.directory)
        os.chmod(self.directory, 0o755)
        os.chmod(self.directory / "ca-key.pem", 0o644)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            again = CertificateAuthority(self.directory)
        self.assertEqual(again.certificate, first.certificate)   # loaded, not replaced
        self.assertEqual(mode_of(self.directory / "ca-key.pem"), 0o600)
        # A directory the user named (--ca-dir . or ~) is theirs: warned
        # about, not chmod'ed. The key in it is what needed protecting.
        self.assertEqual(mode_of(self.directory), 0o755)
        self.assertIn("ca-key.pem", err.getvalue())
        self.assertIn("left %s as it is" % self.directory, err.getvalue())

    def test_the_default_directory_is_tightened(self):
        import contextlib
        import io
        import os
        from unittest import mock

        from pybrws import proxy

        proxy.CertificateAuthority(self.directory)
        os.chmod(self.directory, 0o755)
        with mock.patch.object(proxy, "DEFAULT_CA_DIR", self.directory), \
                contextlib.redirect_stderr(io.StringIO()):
            proxy.CertificateAuthority(self.directory)
        self.assertEqual(mode_of(self.directory), 0o700)

    def test_write_private_replaces_a_loose_file(self):
        import os

        from pybrws.proxy import _write_private

        self.directory.mkdir(mode=0o700)
        path = self.directory / "key.pem"
        path.write_bytes(b"old")
        os.chmod(path, 0o644)
        _write_private(path, b"new")
        self.assertEqual((path.read_bytes(), mode_of(path)), (b"new", 0o600))


if __name__ == "__main__":
    unittest.main()
