"""Follow-ups from the whole-branch review of fix/review-2026-11.

Each class answers one finding of that review (or of the re-run of the
original review's proofs of concept), with the case that showed it.
No network: scripted transports, and loopback servers from tests/hostile.py.
"""

from __future__ import annotations

import contextlib
import io
import os
import time
import unittest
from unittest import mock

from hpack import Encoder

from pybrws import message
from pybrws.http1 import Http1Connection, Http1Error
from pybrws.http2 import (DATA, FLAG_END_HEADERS, FLAG_END_STREAM, HEADERS, RST_STREAM,
                          WINDOW_UPDATE, Http2Connection, Http2Error, StreamRefused, frame)
from pybrws.message import BodyTooLarge, IncrementalDecoder
from pybrws.profiles import firefox157
from pybrws.session import Session

from tests import hostile
from tests.test_session_proxy_hostile import OK_H1, Transports, goaway, h2_ok

SID = firefox157.H2_FIRST_STREAM_ID
REFUSED_STREAM = (7).to_bytes(4, "big")

try:
    from aioquic.quic.connection import QuicConnection
except ImportError:  # pragma: no cover
    QuicConnection = None


class TestPooledConnectionsTheServerClosed(unittest.TestCase):
    """A pooled HTTP/1.1 connection the server has closed -- after
    Connection: close, or its idle timeout -- is not handed a request. Since
    S1 a POST written there failed, though the server never saw it."""

    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def serve(self, *, idle_close: bool):
        seen = []

        def script(peer):
            peer.handshake(alpn="http/1.1")
            seen.append(peer.read_app().split(b" ", 1)[0])
            if len(seen) == 1 and not idle_close:
                peer.send_app(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                              b"Connection: close\r\n\r\nok")
                peer.close_notify()
                return
            peer.send_app(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            if len(seen) == 1:
                time.sleep(0.1)   # the server's keep-alive timeout
                peer.close_notify()

        server = hostile.Tls13Server(script, ca=self.ca, connections=2)
        server.start()
        return server, seen

    def get_then_post(self, *, idle_close: bool, pause: float):
        server, seen = self.serve(idle_close=idle_close)
        url = "https://localhost:%d/" % server.port
        with Session(proxy=False, trust_store=self.store) as session:
            self.assertEqual(session.get(url).status, 200)
            time.sleep(pause)
            self.assertEqual(session.post(url, data=b"x=1").status, 200)
        server.join(5)
        self.assertEqual(seen, [b"GET", b"POST"])

    def test_post_after_connection_close_goes_on_a_fresh_connection(self):
        self.get_then_post(idle_close=False, pause=0.2)

    def test_post_after_idle_close_goes_on_a_fresh_connection(self):
        self.get_then_post(idle_close=True, pause=0.5)

    def test_a_response_that_ends_the_connection_marks_it_done(self):
        ok = b"Content-Length: 2\r\n"
        cases = [
            ([b"HTTP/1.1 200 OK\r\n" + ok + b"Connection: close\r\n\r\nok"], True),
            ([b"HTTP/1.1 200 OK\r\n" + ok + b"Connection: keep-alive, Close\r\n\r\nok"], True),
            ([b"HTTP/1.0 200 OK\r\n" + ok + b"\r\nok"], True),
            ([b"HTTP/1.0 200 OK\r\n" + ok + b"Connection: keep-alive\r\n\r\nok"], False),
            ([b"HTTP/1.1 200 OK\r\n\r\nclose-delimited", b""], True),
            ([b"HTTP/1.1 200 OK\r\n" + ok + b"\r\nok"], False),
        ]
        for script, done in cases:
            with self.subTest(response=script[0][:48]):
                connection = Http1Connection(hostile.ScriptedTls(script, alpn="http/1.1"))
                connection.request("GET", "/", "example.com")
                self.assertEqual(connection.broken, done)


class TestHttp1FailuresMidResponse(unittest.TestCase):
    """A failure inside a response leaves the connection in the middle of a
    message. It used to stay pooled, and the next request read the rest of
    the old one."""

    def test_bad_chunk_size_does_not_reach_the_next_request(self):
        poisoned = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"
                    b"HTTP/1.1 204 No Content\r\nX-From: the-first-body\r\n\r\n")
        fresh = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nfresh!"
        with Transports([OK_H1, poisoned], [fresh]), Session(proxy=False) as session:
            session.get("https://example.com/a")
            with self.assertRaises(Http1Error):
                session.get("https://example.com/b")
            response = session.get("https://example.com/c")
        self.assertEqual((response.status, response.body), (200, b"fresh!"))

    def test_garbled_lengths_are_malformed(self):
        cases = [b"Content-Length: -5\r\n\r\n12345",
                 b"Content-Length: 5x\r\n\r\n12345",
                 b"Content-Length: +5\r\n\r\n12345",
                 b"Transfer-Encoding: chunked\r\n\r\n-1\r\nx\r\n0\r\n\r\n",
                 b"Transfer-Encoding: chunked\r\n\r\n\r\nx\r\n0\r\n\r\n"]
        for rest in cases:
            with self.subTest(head=rest[:30]):
                connection = Http1Connection(hostile.ScriptedTls(
                    [b"HTTP/1.1 200 OK\r\n" + rest], alpn="http/1.1"))
                with self.assertRaises(Http1Error):
                    connection.request("GET", "/", "example.com")
                self.assertTrue(connection.broken)

    def test_an_interrupt_mid_response_breaks_the_connection(self):
        partial = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"
        with Transports([OK_H1, partial, KeyboardInterrupt()], [OK_H1]), \
                Session(proxy=False) as session:
            session.get("https://example.com/a")
            with self.assertRaises(KeyboardInterrupt):
                session.get("https://example.com/b")
            self.assertEqual(session.get("https://example.com/c").body, b"ok")


class TestTicketKeys(unittest.TestCase):
    """A ticket is bound to the trust store itself, not to id(), which Python
    hands to the next object once the store is gone: a ticket earned under
    one set of anchors then resumed a connection another set rejects."""

    @classmethod
    def setUpClass(cls):
        cls.ca, _store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_the_key_holds_the_store(self):
        from cryptography.x509.verification import Store

        from pybrws.tickets import ticket_key

        store = Store([self.ca.certificate])
        self.assertIs(ticket_key("a.test", 443, True, store)[3], store)

    def test_a_ticket_does_not_outlive_its_store(self):
        from cryptography.x509.verification import Store

        from pybrws.tickets import Ticket, TicketStore, ticket_key

        tickets = TicketStore()
        store = Store([self.ca.certificate])
        tickets.add(ticket_key("a.test", 443, True, store),
                    Ticket(identity=b"i", psk=b"p" * 32, age_add=0, lifetime=3600,
                           suite_id=0x1301))
        del store
        for _ in range(20):
            other = Store([self.ca.certificate])
            self.assertIsNone(tickets.take(ticket_key("a.test", 443, True, other)))


class TestOriginSerialisation(unittest.TestCase):
    """Origin and Referer are the origin a browser serialises -- the A-label
    host in lower case, a port only when it is not 443 -- not the URL's
    netloc with whatever it carries."""

    @staticmethod
    def session_post(url: str) -> bytes:
        with Transports([OK_H1]) as transports, Session(proxy=False) as session:
            session.post(url, data=b"x=1")
        return transports.sent()

    def test_userinfo_and_spelling_do_not_reach_origin(self):
        sent = self.session_post("https://alice:s3cret@EXAMPLE.com:443/form")
        self.assertIn(b"\r\nOrigin: https://example.com\r\n", sent)
        self.assertIn(b"\r\nReferer: https://example.com/\r\n", sent)
        self.assertNotIn(b"s3cret", sent)

    def test_an_international_host_is_its_a_label(self):
        from pybrws.hosts import ascii_host

        sent = self.session_post("https://例え.jp/form")
        label = ascii_host("例え.jp").encode()
        self.assertIn(b"\r\nOrigin: https://" + label + b"\r\n", sent)

    def test_client_post_serialises_the_same_way(self):
        from pybrws import client

        tls = hostile.ScriptedTls([OK_H1], alpn="http/1.1")
        with mock.patch.object(client, "connect", return_value=tls):
            client.post("https://alice:s3cret@EXAMPLE.com:8443/form", data=b"x=1",
                        proxy=False)
        self.assertIn(b"\r\nOrigin: https://example.com:8443\r\n", bytes(tls.sent))
        self.assertNotIn(b"s3cret", bytes(tls.sent))


class TestRefusalDuringUpload(unittest.TestCase):
    """GOAWAY and REFUSED_STREAM mean while a body is going up what they
    mean at any other time: a POST above GOAWAY's last stream was never
    processed and goes again; one at or below it is still being served."""

    BODY = bytes(100_000)

    @staticmethod
    def credit() -> list[bytes]:
        increment = (1 << 20).to_bytes(4, "big")
        return [frame(WINDOW_UPDATE, 0, 0, increment), frame(WINDOW_UPDATE, 0, SID, increment)]

    def test_goaway_below_the_stream_is_refused_and_retried(self):
        with Transports([goaway(0)], self.credit() + [h2_ok()], alpn="h2") as transports, \
                Session(proxy=False) as session:
            response = session.post("https://example.com/upload", data=self.BODY)
        self.assertEqual(response.status, 200)
        self.assertEqual(len(transports.made), 2)

    def test_goaway_at_the_stream_lets_the_upload_finish(self):
        connection = Http2Connection(hostile.ScriptedTls(
            [goaway(SID)] + self.credit() + [h2_ok()]))
        response = connection.request("POST", "/upload", "example.com", body=self.BODY)
        self.assertEqual(response.status, 200)
        self.assertTrue(connection.broken)

    def test_refused_stream_during_upload_is_stream_refused(self):
        connection = Http2Connection(hostile.ScriptedTls(
            [frame(RST_STREAM, 0, SID, REFUSED_STREAM)]))
        with self.assertRaises(StreamRefused):
            connection.request("POST", "/upload", "example.com", body=self.BODY)


class TestRequestManyRefusals(unittest.TestCase):
    """StreamRefused.requests holds what the server never processed. One
    stream refused says nothing about its neighbours: those answered in the
    meantime are on .settled, not offered for sending again."""

    def test_only_unprocessed_requests_are_carried(self):
        encoder = Encoder()

        def head(stream: int, end: bool = True) -> bytes:
            flags = FLAG_END_HEADERS | (FLAG_END_STREAM if end else 0)
            return frame(HEADERS, flags, stream, encoder.encode([(b":status", b"200")]))

        connection = Http2Connection(hostile.ScriptedTls([
            head(SID),
            frame(RST_STREAM, 0, SID + 2, REFUSED_STREAM),
            head(SID + 4, end=False), frame(DATA, FLAG_END_STREAM, SID + 4, b"three"),
        ]))
        batch = [("POST", "/a", "example.com"), ("POST", "/b", "example.com"),
                 ("POST", "/c", "example.com")]
        results = connection.request_many(batch)
        self.assertEqual(next(results).status, 200)
        with self.assertRaises(StreamRefused) as caught:
            next(results)
        self.assertEqual(caught.exception.requests, [batch[1]])
        (request, response), = caught.exception.settled
        self.assertEqual((request, response.body), (batch[2], b"three"))


class TestFramesForAbandonedStreams(unittest.TestCase):
    """A stream no longer tracked -- a streaming response the caller stopped
    reading -- still sends frames, since nothing tells the server to stop
    (D10). Its header blocks change the connection's HPACK table and its
    DATA uses the connection window, so both are still honoured."""

    def test_trailers_on_an_abandoned_stream_keep_hpack_in_step(self):
        encoder = Encoder()
        unwanted = b"more, unwanted"
        tls = hostile.ScriptedTls([
            frame(HEADERS, FLAG_END_HEADERS, SID, encoder.encode([(b":status", b"200")])),
            frame(DATA, 0, SID, b"first piece"),
            frame(DATA, 0, SID, unwanted),
            frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, SID,
                  encoder.encode([(b"x-trailer", b"t1")])),
            frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, SID + 2,
                  encoder.encode([(b":status", b"200"), (b"x-trailer", b"t1")])),
        ])
        connection = Http2Connection(tls)
        _response, chunks = connection.stream_response(
            connection.send_request("GET", "/a", "example.com"))
        self.assertEqual(next(chunks), b"first piece")
        chunks.close()   # the caller stops reading
        before = len(tls.sent)
        response = connection.request("GET", "/b", "example.com")
        self.assertEqual(response.header("x-trailer"), "t1")
        credits = [payload for kind, _flags, stream, payload
                   in hostile.frames_in(bytes(tls.sent)[before:])
                   if kind == WINDOW_UPDATE and stream == 0]
        self.assertIn(len(unwanted).to_bytes(4, "big"), credits)


@unittest.skipIf(QuicConnection is None, "aioquic is not installed")
class TestHttp3Completion(unittest.TestCase):
    """An error while completing an h3 response reaches the caller at once
    -- it escaped into the event loop, and the caller waited out its
    timeout -- and the body is capped while it arrives, as over TCP."""

    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives import serialization

        cls.ca, _store, cls._tmp = hostile.trusted_ca()
        cls.cadata = cls.ca.certificate.public_bytes(serialization.Encoding.PEM)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        from pybrws import quic_impersonate

        quic_impersonate.install()
        self.addCleanup(quic_impersonate.uninstall)

    def failing_get(self, **server_options):
        from pybrws import h3

        options = {}
        if "max_body_size" in server_options:   # only where a test sets one
            options["max_body_size"] = server_options.pop("max_body_size")
        server = hostile.QuicServer(ca=self.ca, **server_options)
        self.addCleanup(server.close)
        start = time.monotonic()
        try:
            h3.get("https://127.0.0.1:%d/" % server.port, cadata=self.cadata,
                   timeout=10, **options)
        except Exception as exc:
            return exc, time.monotonic() - start
        self.fail("the request succeeded")

    def test_a_body_that_does_not_decode_fails_fast(self):
        error, elapsed = self.failing_get(body=b"this is not gzip",
                                          headers=[(b"content-encoding", b"gzip")])
        self.assertNotIsInstance(error, TimeoutError)
        self.assertLess(elapsed, 2)

    def test_a_malformed_status_fails_fast(self):
        from pybrws.h3 import Http3Error

        error, elapsed = self.failing_get(status=b"2x0")
        self.assertIsInstance(error, Http3Error)
        self.assertLess(elapsed, 2)

    def test_the_body_is_capped_as_it_arrives(self):
        error, elapsed = self.failing_get(body=bytes(300_000), max_body_size=100_000)
        self.assertIsInstance(error, BodyTooLarge)
        self.assertLess(elapsed, 2)


@unittest.skipIf(QuicConnection is None, "aioquic is not installed")
class TestEmptyCompressedCertificate(unittest.TestCase):
    """Q1 covers every failure: an empty certificate list escaped as
    IndexError. RFC 8446 4.4.2.4 names decode_error for it."""

    def test_empty_certificate_list_is_decode_error(self):
        import aioquic.tls as tls
        from aioquic.buffer import Buffer

        from pybrws import quic_impersonate
        from pybrws.wire import vector
        from tests.test_quic_hostile import compressed_message

        quic_impersonate.install()
        self.addCleanup(quic_impersonate.uninstall)
        context = tls.Context(is_client=True)
        context.state = tls.State.CLIENT_EXPECT_CERTIFICATE
        context._pybrws_connection = object()
        empty = compressed_message(vector(b"", 1) + vector(b"", 3))
        with self.assertRaises(tls.AlertDecodeError):
            context._handle_reassembled_message(0x19, Buffer(data=empty), {})


class TestFeedIsCapped(unittest.TestCase):
    """D-1, from the re-run of the review's proofs: one feed() call returned
    the whole expansion of its input -- 256 MiB from 405 bytes of brotli.
    It holds its output at once, so it takes the buffered cap; pieces()
    still streams without one."""

    def test_one_feed_call_is_capped(self):
        import brotli

        bomb = brotli.compress(bytes(8 << 20), quality=5)
        with mock.patch.object(message, "DEFAULT_MAX_BODY", 1 << 20):
            with self.assertRaises(BodyTooLarge):
                IncrementalDecoder("br").feed(bomb)
            streamed = sum(len(piece) for piece in IncrementalDecoder("br").pieces(bomb))
        self.assertEqual(streamed, 8 << 20)


class TestCliCaps(unittest.TestCase):
    """The CLI can lift or set the body cap (curl's --max-filesize), and the
    library's own errors are one line, not a traceback."""

    def run_cli(self, argv, outcome, *, target="request"):
        from pybrws import cli, h3
        from pybrws.message import Response

        calls = []

        def fake(url, **kwargs):
            calls.append(kwargs)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome or Response(status=200, body=b"ok")

        owner = cli if target == "request" else h3
        with mock.patch.object(owner, "request", side_effect=fake), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                code = cli.main(argv + ["-s", "-o", os.devnull, "https://example.com/"])
            except SystemExit as exc:
                code = exc.code
        return calls, code

    def test_max_filesize_reaches_the_request(self):
        for argv, expected in (([], message.DEFAULT_MAX_BODY),
                               (["--max-filesize", "0"], None),
                               (["--max-filesize", "1000"], 1000)):
            with self.subTest(argv=argv):
                calls, code = self.run_cli(argv, None)
                self.assertEqual((code, calls[0]["max_body_size"]), (0, expected))
        calls, _code = self.run_cli(["--http3", "--max-filesize", "1000"], None, target="h3")
        self.assertEqual(calls[0]["max_body_size"], 1000)

    def test_library_errors_are_one_line(self):
        from pybrws.handshake import HandshakeError
        from pybrws.message import ContentEncodingError

        for error in (BodyTooLarge("too big"), ContentEncodingError("bad gzip"),
                      Http1Error("bad framing"), Http2Error("PROTOCOL_ERROR"),
                      HandshakeError("bad hello")):
            with self.subTest(error=type(error).__name__):
                _calls, code = self.run_cli([], error)
                self.assertIsInstance(code, str)
                self.assertIn(type(error).__name__, code)


if __name__ == "__main__":
    unittest.main()
