"""QUIC and HTTP/3 against hostile conditions and hostile neighbours.

Q1-Q9 of the 2026-11-11 review. Offline: QuicConnection.connect() and
datagrams_to_send(), read back with pybrws.quic.
"""

from __future__ import annotations

import threading
import types
import unittest

from pybrws import quic_impersonate as qi
from pybrws.parser import parse_client_hello
from pybrws.profiles import firefox157_quic as profile
from pybrws.quic import client_hello_from_datagrams
from pybrws.wire import vector

try:
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
except ImportError:  # pragma: no cover
    QuicConnection = None

CAPTURED_HOST = "blog-cloudflare-com-assets.storage.googleapis.com"
CAPTURED_LENGTH = 1931


def first_flight(configuration):
    """The ClientHello a fresh connection sends, parsed."""
    connection = QuicConnection(configuration=configuration)
    connection.connect(("192.0.2.1", 443), now=0.0)
    datagrams = [data for data, _ in connection.datagrams_to_send(now=0.0)]
    return parse_client_hello(client_hello_from_datagrams(datagrams))


def alpn_of(hello) -> list[bytes]:
    data, names = hello.extension(16).data[2:], []
    while data:
        names.append(data[1:1 + data[0]])
        data = data[1 + data[0]:]
    return names


@unittest.skipIf(QuicConnection is None, "aioquic is not installed")
class TestPerConnection(unittest.TestCase):
    """Q2: the patch acts on connections pybrws made and nothing else, with
    the profile each one names, from any thread."""

    def setUp(self):
        qi.install()
        self.addCleanup(qi.uninstall)

    def test_unrelated_aioquic_client_is_untouched(self):
        hello = first_flight(QuicConfiguration(
            is_client=True, alpn_protocols=["doq"], server_name="dns.example"))
        self.assertEqual(alpn_of(hello), [b"doq"])
        self.assertNotIn(65037, hello.extension_types())

    def test_marked_configuration_is_impersonated(self):
        hello = first_flight(qi.configuration(CAPTURED_HOST, verify=False))
        self.assertIn(65037, hello.extension_types())
        self.assertEqual(list(hello.cipher_suites), list(profile.CIPHER_SUITES))
        self.assertEqual(len(hello.raw), CAPTURED_LENGTH)

    def test_concurrent_hellos_in_threads(self):
        sizes, errors = [], []

        def worker():
            try:
                for _ in range(6):
                    hello = first_flight(qi.configuration(CAPTURED_HOST, verify=False))
                    sizes.append(len(hello.raw))
            except Exception as exc:   # collected, reported below
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(errors, [])
        self.assertEqual(sizes, [CAPTURED_LENGTH] * 48)

    def test_second_profile_in_one_process(self):
        other = types.ModuleType("other_quic_profile")
        other.__dict__.update(vars(profile))
        other.ALPN_PROTOCOLS = ("h3-29",)
        other.STATIC_PAYLOADS = dict(profile.STATIC_PAYLOADS)
        other.STATIC_PAYLOADS[16] = vector(vector(b"h3-29", 1), 2)

        theirs = first_flight(qi.configuration(CAPTURED_HOST, profile=other, verify=False))
        ours = first_flight(qi.configuration(CAPTURED_HOST, verify=False))
        self.assertEqual(alpn_of(theirs), [b"h3-29"])
        self.assertEqual(alpn_of(ours), [b"h3"])


def certificate_body(der: bytes = b"a fake certificate") -> bytes:
    """A TLS 1.3 Certificate body holding one entry."""
    from pybrws.wire import u16

    return vector(b"", 1) + vector(vector(der, 3) + u16(0), 3)


def compressed_message(body: bytes | None = None, *, announced: int | None = None,
                       squeezed: bytes | None = None, extra_claimed: int = 0) -> bytes:
    """A CompressedCertificate (RFC 8879) handshake message, zlib, with
    knobs for each way it can lie."""
    import zlib

    from pybrws.wire import u16, u24

    body = certificate_body() if body is None else body
    squeezed = zlib.compress(body) if squeezed is None else squeezed
    payload = (u16(1) + u24(len(body) if announced is None else announced)
               + u24(len(squeezed) + extra_claimed) + squeezed)
    return bytes([0x19]) + u24(len(payload)) + payload


@unittest.skipIf(QuicConnection is None, "aioquic is not installed")
class TestCompressedCertificateState(unittest.TestCase):
    """Q1: type 25 stands for a Certificate, so it is accepted where one is
    legal and nowhere else, and every failure is an alert, which aioquic
    turns into a connection close -- not an exception that escapes into
    asyncio and leaves the caller waiting."""

    def setUp(self):
        qi.install()
        self.addCleanup(qi.uninstall)

    @staticmethod
    def context(state):
        import aioquic.tls as tls

        context = tls.Context(is_client=True)
        context.state = state
        context._pybrws_connection = object()   # as quic_impersonate marks its own
        return context

    @staticmethod
    def deliver(context, message: bytes) -> None:
        from aioquic.buffer import Buffer

        context._handle_reassembled_message(0x19, Buffer(data=message), {})

    def test_before_server_hello_raises_unexpected_message(self):
        import aioquic.tls as tls

        with self.assertRaises(tls.AlertUnexpectedMessage):
            self.deliver(self.context(tls.State.CLIENT_EXPECT_SERVER_HELLO),
                         compressed_message())

    def test_after_handshake_raises_and_keeps_certificate(self):
        import aioquic.tls as tls

        context = self.context(tls.State.CLIENT_POST_HANDSHAKE)
        context._peer_certificate = kept = object()
        with self.assertRaises(tls.AlertUnexpectedMessage):
            self.deliver(context, compressed_message())
        self.assertIs(context._peer_certificate, kept)
        self.assertEqual(context.state, tls.State.CLIENT_POST_HANDSHAKE)

    def test_corrupt_payload_raises_bad_certificate(self):
        import aioquic.tls as tls

        with self.assertRaises(tls.AlertBadCertificate):
            self.deliver(self.context(tls.State.CLIENT_EXPECT_CERTIFICATE),
                         compressed_message(squeezed=b"this is not zlib"))

    def test_wrong_uncompressed_length_raises_bad_certificate(self):
        # RFC 8879 section 4 names bad_certificate for this too.
        import aioquic.tls as tls

        body = certificate_body()
        with self.assertRaises(tls.AlertBadCertificate):
            self.deliver(self.context(tls.State.CLIENT_EXPECT_CERTIFICATE),
                         compressed_message(body, announced=len(body) + 1))

    def test_length_mismatch_raises_decode_error(self):
        # The message's own framing: its vector claims more than it holds.
        import aioquic.tls as tls

        with self.assertRaises(tls.AlertDecodeError):
            self.deliver(self.context(tls.State.CLIENT_EXPECT_CERTIFICATE),
                         compressed_message(extra_claimed=10))

    def test_unparseable_certificate_raises_decode_error(self):
        import aioquic.tls as tls

        with self.assertRaises(tls.AlertDecodeError):
            self.deliver(self.context(tls.State.CLIENT_EXPECT_CERTIFICATE),
                         compressed_message(b"\x00\x00"))

    def test_garbage_der_raises_bad_certificate(self):
        import aioquic.tls as tls

        with self.assertRaises(tls.AlertBadCertificate):
            self.deliver(self.context(tls.State.CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE),
                         compressed_message(certificate_body(b"not a certificate")))


@unittest.skipIf(QuicConnection is None, "aioquic is not installed")
class TestIpLiteralsOverQuic(unittest.TestCase):
    """Q3: an IP literal gets no server_name, as Firefox sends none, and
    the certificate is still checked against the address."""

    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives import serialization

        from tests import hostile

        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()
        cls.cadata = cls.ca.certificate.public_bytes(serialization.Encoding.PEM)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        qi.install()
        self.addCleanup(qi.uninstall)

    def test_ip_literal_quic_hello_has_no_server_name(self):
        hello = first_flight(qi.configuration("127.0.0.1", verify=False))
        self.assertNotIn(0, hello.extension_types())
        # Nothing else moves: the captured hello less its server_name.
        self.assertEqual(len(hello.raw), CAPTURED_LENGTH - (9 + len(CAPTURED_HOST)))

    def test_h3_get_ip_literal_against_local_server(self):
        from pybrws import h3
        from tests import hostile

        server = hostile.QuicServer(ca=self.ca, host="127.0.0.1")
        self.addCleanup(server.close)
        response = h3.get("https://127.0.0.1:%d/" % server.port,
                          cadata=self.cadata, timeout=10)
        self.assertEqual((response.status, response.body), (200, b"ok"))

    def test_h3_ip_literal_rejects_certificate_for_another_ip(self):
        # The proof that leaving SNI out did not switch the name check off:
        # a certificate for 127.0.0.2, from a trusted CA, on 127.0.0.1.
        from pybrws import h3
        from tests import hostile

        server = hostile.QuicServer(ca=self.ca, host="127.0.0.1",
                                    certificate_host="127.0.0.2")
        self.addCleanup(server.close)
        with self.assertRaises(h3.Http3Error) as caught:
            h3.get("https://127.0.0.1:%d/" % server.port, cadata=self.cadata, timeout=10)
        self.assertIn("doesn't match", str(caught.exception))
        self.assertEqual(server.requests, [])


@unittest.skipIf(QuicConnection is None, "aioquic is not installed")
class TestHttp3Failures(unittest.TestCase):
    """Q4: an h3 request fails as soon as its stream or its connection does,
    and `timeout` bounds the whole operation, the handshake included. A
    2-second timeout to a silent port used to fail after 30."""

    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives import serialization

        from tests import hostile

        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()
        cls.cadata = cls.ca.certificate.public_bytes(serialization.Encoding.PEM)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        qi.install()
        self.addCleanup(qi.uninstall)

    def failing_get(self, port: int, timeout: float):
        """The exception h3.get raised, and how long it took to."""
        import time

        from pybrws import h3

        start = time.monotonic()
        try:
            h3.get("https://127.0.0.1:%d/" % port, cadata=self.cadata, timeout=timeout)
        except Exception as exc:
            return exc, time.monotonic() - start
        self.fail("the request succeeded")

    def server(self, on_request: str):
        from tests import hostile

        server = hostile.QuicServer(ca=self.ca, on_request=on_request)
        self.addCleanup(server.close)
        return server

    def test_stream_reset_fails_the_request_immediately(self):
        from pybrws.h3 import Http3Error

        error, elapsed = self.failing_get(self.server("reset").port, timeout=10)
        self.assertIsInstance(error, Http3Error)
        self.assertLess(elapsed, 2)

    def test_connection_close_fails_the_request_immediately(self):
        from pybrws.h3 import Http3Error

        error, elapsed = self.failing_get(self.server("close").port, timeout=10)
        self.assertIsInstance(error, Http3Error)
        self.assertLess(elapsed, 2)

    def test_timeout_bounds_the_handshake(self):
        import socket

        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind(("127.0.0.1", 0))
        self.addCleanup(silent.close)
        error, elapsed = self.failing_get(silent.getsockname()[1], timeout=2)
        self.assertIsInstance(error, TimeoutError)
        self.assertLess(elapsed, 3)


@unittest.skipIf(QuicConnection is None, "aioquic is not installed")
class TestHttp3Post(unittest.TestCase):
    """Q5, D8: no Firefox HTTP/3 POST has been captured, so h3 refuses one
    instead of sending the GET navigation headers with a body attached."""

    NOT_SENT = AssertionError("the request was sent")

    def test_h3_post_raises_unmeasured(self):
        from unittest import mock

        from pybrws import h3
        from pybrws.client import Unmeasured

        with mock.patch.object(h3, "open_connection", side_effect=self.NOT_SENT):
            with self.assertRaises(Unmeasured) as caught:
                h3.post("https://example.com/", data=b"amount=1")
        self.assertIn("HTTP/3 POST", str(caught.exception))
        self.assertIn("pybrws capture quic", str(caught.exception))

    def test_cli_http3_with_a_body_refuses(self):
        # It used to call h3.get whatever -X and -d said: a silent GET.
        from unittest import mock

        from pybrws import cli, h3

        with mock.patch.object(h3, "open_connection", side_effect=self.NOT_SENT):
            with self.assertRaises(SystemExit) as caught:
                cli.main(["--http3", "-d", "amount=1", "https://example.com/"])
        self.assertIn("Unmeasured", str(caught.exception.code))

    def test_h3_get_headers_unchanged(self):
        from cryptography.hazmat.primitives import serialization

        from pybrws import h3
        from tests import hostile

        ca, _store, tmp = hostile.trusted_ca()
        self.addCleanup(tmp.cleanup)
        qi.install()
        self.addCleanup(qi.uninstall)
        server = hostile.QuicServer(ca=ca)
        self.addCleanup(server.close)
        authority = "127.0.0.1:%d" % server.port
        h3.get("https://%s/" % authority, timeout=10,
               cadata=ca.certificate.public_bytes(serialization.Encoding.PEM))
        self.assertEqual(server.requests[0], h3.request_fields(
            "GET", "/", authority, profile.navigation_headers(authority)))


def session_ticket(server_name: str):
    """A ticket aioquic would consider valid for `server_name`."""
    import datetime

    import aioquic.tls as tls

    now = datetime.datetime.now(datetime.timezone.utc)
    return tls.SessionTicket(
        age_add=0, cipher_suite=tls.CipherSuite.AES_128_GCM_SHA256,
        not_valid_after=now + datetime.timedelta(hours=1),
        not_valid_before=now - datetime.timedelta(hours=1),
        resumption_secret=bytes(32), server_name=server_name, ticket=b"t" * 32)


@unittest.skipIf(QuicConnection is None, "aioquic is not installed")
class TestNoQuicTickets(unittest.TestCase):
    """Q6: Firefox's QUIC resumption is unmeasured, so no ticket is offered
    -- a configured one crashed the hello writer -- and tickets a server
    sends are let go."""

    def setUp(self):
        qi.install()
        self.addCleanup(qi.uninstall)

    def test_configuration_refuses_a_session_ticket(self):
        with self.assertRaises(ValueError) as caught:
            qi.configuration(CAPTURED_HOST, session_ticket=session_ticket(CAPTURED_HOST))
        self.assertIn("QUIC resumption", str(caught.exception))

    def test_a_ticket_set_later_is_not_offered(self):
        config = qi.configuration(CAPTURED_HOST, verify=False)
        config.session_ticket = session_ticket(CAPTURED_HOST)
        hello = first_flight(config)   # a BufferWriteError, before
        self.assertNotIn(41, hello.extension_types())
        self.assertEqual(len(hello.raw), CAPTURED_LENGTH)

    def test_received_tickets_are_ignored(self):
        from cryptography.hazmat.primitives import serialization

        from pybrws import h3
        from tests import hostile

        ca, _store, tmp = hostile.trusted_ca()
        self.addCleanup(tmp.cleanup)
        server = hostile.QuicServer(ca=ca, tickets=True)
        self.addCleanup(server.close)
        cadata = ca.certificate.public_bytes(serialization.Encoding.PEM)
        for _ in range(2):
            response = h3.get("https://127.0.0.1:%d/" % server.port,
                              cadata=cadata, timeout=10)
            self.assertEqual(response.status, 200)
        self.assertEqual(server.resumed, [False, False])


@unittest.skipIf(QuicConnection is None, "aioquic is not installed")
class TestRetry(unittest.TestCase):
    """Q7, RFC 9000 17.2.5.3: after a Retry 'a client MUST use the same
    cryptographic handshake message'. aioquic builds a new one -- a new
    random, a newly drawn order, new grease."""

    def setUp(self):
        qi.install()
        self.addCleanup(qi.uninstall)

    def test_hello_after_retry_is_identical(self):
        from aioquic.quic.packet import encode_quic_retry

        from pybrws.quic import parse_long_header

        connection = QuicConnection(configuration=qi.configuration(CAPTURED_HOST,
                                                                   verify=False))
        address = ("192.0.2.1", 443)
        connection.connect(address, now=0.0)
        first = [data for data, _ in connection.datagrams_to_send(now=0.0)]
        server_id = bytes(range(8))
        connection.receive_datagram(encode_quic_retry(
            version=connection._version, source_cid=server_id,
            destination_cid=connection.host_cid,
            original_destination_cid=connection._peer_cid.cid,
            retry_token=b"a retry token"), address, now=0.1)
        second = [data for data, _ in connection.datagrams_to_send(now=0.1)]

        # The Retry was taken, so this is a new Initial, not a resend.
        self.assertEqual(connection._retry_count, 1)
        header, _ = parse_long_header(second[0])
        self.assertEqual((header["destination_id"], header["token"]),
                         (server_id, b"a retry token"))
        self.assertEqual(client_hello_from_datagrams(second),
                         client_hello_from_datagrams(first))

    def test_h3_get_through_a_retry(self):
        # The resent hello goes into a new tls.Context: the transcript, the
        # random and the key exchange must all still agree for this to work.
        from cryptography.hazmat.primitives import serialization

        from pybrws import h3
        from tests import hostile

        ca, _store, tmp = hostile.trusted_ca()
        self.addCleanup(tmp.cleanup)
        server = hostile.QuicServer(ca=ca, retry=True)
        self.addCleanup(server.close)
        response = h3.get("https://127.0.0.1:%d/" % server.port, timeout=10,
                          cadata=ca.certificate.public_bytes(serialization.Encoding.PEM))
        self.assertEqual((response.status, response.body), (200, b"ok"))


class TestParsers(unittest.TestCase):
    """Q8, Q9: a short datagram raised IndexError out of the reader, and
    load_hex misread the module's own hexdump output."""

    # Long header, Initial, version 1, then a 20-byte destination id that
    # the 7-byte datagram does not hold.
    SHORT = bytes([0xC0, 0, 0, 0, 1, 20, 1])

    def test_short_datagram_raises_quic_error(self):
        from pybrws.quic import QuicError, decrypt_initial, parse_long_header

        cut_token = bytes([0xC0, 0, 0, 0, 1, 1, 0xAA, 0, 0x05, 0x01])
        for datagram in (self.SHORT, self.SHORT[:6], cut_token):
            with self.subTest(datagram=datagram.hex()):
                with self.assertRaises(QuicError):
                    parse_long_header(datagram)
                with self.assertRaises(QuicError):
                    decrypt_initial(datagram)

    @unittest.skipIf(QuicConnection is None, "aioquic is not installed")
    def test_datagram_iterators_skip_malformed(self):
        from pybrws.tools import read_quic

        qi.install()
        self.addCleanup(qi.uninstall)
        connection = QuicConnection(configuration=qi.configuration(CAPTURED_HOST,
                                                                   verify=False))
        connection.connect(("192.0.2.1", 443), now=0.0)
        flight = [data for data, _ in connection.datagrams_to_send(now=0.0)]
        hello = client_hello_from_datagrams([self.SHORT] + flight)
        self.assertEqual(len(hello), CAPTURED_LENGTH)
        groups = read_quic.by_connection([self.SHORT] + flight)
        self.assertEqual(list(groups.values()), [flight])

    def test_load_hex_reads_hexdump_output(self):
        import tempfile
        from pathlib import Path

        from pybrws.hexio import hexdump, load_hex

        # Printable bytes on purpose: the text column then holds digits,
        # A-F and a '#', each of which the reader took for data or comment.
        data = bytes(range(0x20, 0x48))
        self.assertEqual(len(data), 40)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dump.txt"
            path.write_text(hexdump(data) + "\n", encoding="utf-8")
            self.assertEqual(load_hex(path), data)
            path.write_text("# a plain dump, as save_hex writes\n" + data.hex() + "\n",
                            encoding="utf-8")
            self.assertEqual(load_hex(path), data)


if __name__ == "__main__":
    unittest.main()
