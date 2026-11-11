"""The end of a stream, and informational responses, against hostile peers.

E1 and E2 of the 2026-11-11 review. Over TLS, an authenticated close_notify
is the only clean end of a stream; a bare TCP FIN may be an attacker cutting
the connection, so a body that depends on the end of the connection for its
length is truncated unless close_notify arrived. Peers are in
`tests/hostile.py`. No network.
"""

from __future__ import annotations

import unittest

from pybrws.handshake import connect
from pybrws.http1 import Http1Connection, Http1Error
from pybrws.http2 import Http2Connection, Http2Error

from tests import hostile

HEAD_CLOSE = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"


def _head(length: int) -> bytes:
    return b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % length


class TestEndOfStream(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _connect(self, script):
        server = hostile.Tls13Server(script, ca=self.ca)
        server.start()
        self.addCleanup(server.join, 5)
        tls = connect("localhost", server.port, trust_store=self.store, timeout=5)
        self.addCleanup(tls.close)
        return tls

    def _get(self, script):
        tls = self._connect(script)
        return Http1Connection(tls).request("GET", "/", "localhost")

    def test_close_delimited_body_with_close_notify_is_complete(self):
        def script(peer):
            peer.handshake(alpn="http/1.1")
            peer.read_app()
            peer.send_app(HEAD_CLOSE + b"x" * 5000)
            peer.close_notify()

        self.assertEqual(self._get(script).body, b"x" * 5000)

    def test_close_delimited_body_cut_by_fin_raises(self):
        def script(peer):
            peer.handshake(alpn="http/1.1")
            peer.read_app()
            peer.send_app(HEAD_CLOSE + b"PART-ONE-")
            peer.fin()

        with self.assertRaises(Http1Error) as caught:
            self._get(script)
        self.assertIn("close_notify", str(caught.exception))

    def test_empty_record_inside_body_is_ignored(self):
        def script(peer):
            peer.handshake(alpn="http/1.1")
            peer.read_app()
            peer.send_app(_head(10) + b"12345")
            peer.send_app(b"")
            peer.send_app(b"67890")

        self.assertEqual(self._get(script).body, b"1234567890")

    def test_content_length_body_then_fin_is_complete(self):
        def script(peer):
            peer.handshake(alpn="http/1.1")
            peer.read_app()
            peer.send_app(_head(2) + b"ok")
            peer.fin()

        self.assertEqual(self._get(script).body, b"ok")

    def test_recv_returns_empty_only_at_close_notify(self):
        def script(peer):
            peer.handshake()
            peer.send_app(b"")
            peer.send_app(b"data")
            peer.close_notify()

        tls = self._connect(script)
        self.assertEqual(tls.recv(), b"data")
        self.assertEqual(tls.recv(), b"")

    def test_http2_clean_close_while_waiting_raises(self):
        # A clean close at a frame boundary is still the end of every stream
        # in flight; reading on must raise, not spin on empty reads.
        connection = Http2Connection(hostile.ScriptedTls([b""]))
        with self.assertRaises(Http2Error):
            connection._frame_from_wire()


class TestInformationalResponses(unittest.TestCase):
    """E2: every 1xx but 101 is informational and precedes the real answer.
    Taking a 103 Early Hints as final leaves the real response unread, and
    the next request on the pooled connection reads it instead."""

    HINTS = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"

    def test_early_hints_then_final_response(self):
        tls = hostile.ScriptedTls([self.HINTS + _head(2) + b"ok"], alpn="http/1.1")
        response = Http1Connection(tls).request("GET", "/", "example.test")
        self.assertEqual((response.status, response.body), (200, b"ok"))

    def test_pooled_connection_stays_in_step_after_103(self):
        tls = hostile.ScriptedTls(
            [self.HINTS + _head(5) + b"first", _head(6) + b"second"],
            alpn="http/1.1")
        connection = Http1Connection(tls)
        self.assertEqual(connection.request("GET", "/1", "example.test").body,
                         b"first")
        self.assertEqual(connection.request("GET", "/2", "example.test").body,
                         b"second")


if __name__ == "__main__":
    unittest.main()
