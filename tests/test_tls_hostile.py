"""The TLS layer against peers that misbehave on purpose.

Each class covers one finding of the 2026-11-11 review (the IDs in the class
docstrings are the review's). The peers are in `tests/hostile.py`. No network.
"""

from __future__ import annotations

import tracemalloc
import unittest
import zlib

import brotli

from pybrws.certs import CertificateError, decompress_certificate
from pybrws.emitter import build_client_hello, retry_hello, with_psk
from pybrws.handshake import connect
from pybrws.keyexchange import KeyExchange
from pybrws.keyschedule import CIPHER_SUITES, psk_binder
from pybrws.parser import parse_client_hello
from pybrws.profiles import chrome155, firefox157
from pybrws.tickets import Ticket, TicketStore
from pybrws.wire import u16, u24, vector

from tests import hostile


def _zstd_compress(data: bytes) -> bytes:
    try:
        from compression import zstd
    except ImportError:   # Python below 3.14
        import zstandard
        return zstandard.ZstdCompressor().compress(data)
    return zstd.compress(data)


def compress_cert(algorithm: int, body: bytes, *, declared: int | None = None) -> bytes:
    """A CompressedCertificate body (RFC 8879) for `body`."""
    compress = {1: zlib.compress, 2: brotli.compress, 3: _zstd_compress}[algorithm]
    return (u16(algorithm) + u24(len(body) if declared is None else declared)
            + vector(compress(body), 3))


class TestKit(unittest.TestCase):
    """The scripted server itself, against the real client.

    Without this a broken kit would make every "is rejected" test pass for
    the wrong reason.
    """

    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_correct_handshake_round_trips(self):
        def script(peer):
            peer.handshake()
            peer.send_app(b"pong:" + peer.read_app())

        server = hostile.Tls13Server(script, ca=self.ca)
        server.start()
        with connect("localhost", server.port, trust_store=self.store,
                     timeout=5) as tls:
            tls.send(b"ping")
            self.assertEqual(tls.recv(), b"pong:ping")
        server.join(5)
        self.assertEqual(server.errors, [])
        self.assertTrue(server.peer.client_finished_ok)

    def test_openssl_server_round_trips(self):
        port = hostile.openssl_server(hostile.echo, ca=self.ca)
        with connect("localhost", port, trust_store=self.store,
                     timeout=5) as tls:
            tls.send(b"ping")
            self.assertEqual(tls.recv(), b"pong:ping")


class TestCertificateDecompression(unittest.TestCase):
    """T1: the output is bounded by the declared length while decompressing,
    not compared with it afterwards. The message arrives before the server
    has proved anything, so this is reachable by anyone on the path."""

    @classmethod
    def setUpClass(cls):
        ca, _store, tmp = hostile.trusted_ca()
        der = hostile.leaf_der(ca, "localhost")
        tmp.cleanup()
        cls.body = vector(b"", 1) + vector(vector(der, 3) + vector(b"", 2), 3)

    def test_bomb_is_rejected_without_expanding(self):
        # 256 MiB of zeros, compressed incrementally so the test itself never
        # holds them, declared as an ordinary 1500-byte chain.
        compressor = brotli.Compressor(quality=5)
        chunk = bytes(1 << 20)
        payload = b"".join(compressor.process(chunk) for _ in range(256))
        payload += compressor.finish()
        message = u16(2) + u24(1500) + vector(payload, 3)

        tracemalloc.start()
        try:
            with self.assertRaises(CertificateError):
                decompress_certificate(message)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 16 << 20)

    def test_output_one_byte_past_declared_length_is_rejected(self):
        for algorithm in (1, 2, 3):
            with self.subTest(algorithm=algorithm):
                with self.assertRaises(CertificateError):
                    decompress_certificate(
                        compress_cert(algorithm, bytes(1501), declared=1500))

    def test_each_algorithm_round_trips(self):
        for algorithm in (1, 2, 3):
            with self.subTest(algorithm=algorithm):
                self.assertEqual(
                    decompress_certificate(compress_cert(algorithm, self.body)),
                    self.body)


class TestHelloRetryRequest(unittest.TestCase):
    """T2, T2a, T2b, T2c: the second ClientHello belongs in the transcript,
    a PSK in it is re-bound to the new transcript, the cookie goes before the
    PSK, and a cookie-only retry is legal."""

    SUITE = CIPHER_SUITES[0x1301]

    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _round_trip(self, port, profile, tickets=None):
        with connect("localhost", port, profile=profile, trust_store=self.store,
                     tickets=tickets, timeout=5) as tls:
            tls.send(b"ping")
            self.assertEqual(tls.recv(), b"pong:ping")
            return tls.resumed

    def test_secp384r1_only_server_completes_firefox157(self):
        # firefox157 sends shares for X25519MLKEM768, x25519 and P-256 only,
        # so a P-384-only server has to ask again.
        port = hostile.openssl_server(hostile.echo, ca=self.ca, curve="secp384r1")
        self._round_trip(port, firefox157)

    def test_p256_only_server_completes_chrome155(self):
        # chrome155 sends no P-256 share at all.
        port = hostile.openssl_server(hostile.echo, ca=self.ca, curve="prime256v1")
        self._round_trip(port, chrome155)

    def test_resumed_connection_through_hrr_completes(self):
        port = hostile.openssl_server(hostile.echo, ca=self.ca,
                                      curve="secp384r1", connections=2)
        store = TicketStore()
        self.assertFalse(self._round_trip(port, firefox157, store))
        self.assertTrue(self._round_trip(port, firefox157, store))

    def _psk_hello(self):
        ticket = Ticket(identity=b"ticket-identity", psk=bytes(32), age_add=7,
                        lifetime=3600, suite_id=0x1301)
        first = with_psk(build_client_hello("a.test"), [ticket], self.SUITE)
        share = KeyExchange([0x0018]).public_share(0x0018)
        return ticket, first, share

    def test_retry_hello_puts_pre_shared_key_last_after_cookie(self):
        ticket, first, share = self._psk_hello()
        second = retry_hello(first, 0x0018, share, b"\x00\x02c0",
                             binder_context=b"context", tickets=[ticket],
                             suite=self.SUITE)
        types = [e.type for e in parse_client_hello(second).extensions]
        self.assertEqual(types[-1], 41)
        self.assertIn(44, types[:-1])

    def test_retry_hello_binder_covers_hrr_transcript(self):
        ticket, first, share = self._psk_hello()
        context = b"message_hash(CH1) and the HRR stand here"
        second = retry_hello(first, 0x0018, share, None, binder_context=context,
                             tickets=[ticket], suite=self.SUITE)
        message = second[5:]
        binders = 2 + 1 + self.SUITE.hash_size   # one binder, with lengths
        self.assertEqual(message[-self.SUITE.hash_size:],
                         psk_binder(self.SUITE, ticket.psk,
                                    context + message[:-binders]))

    def test_cookie_only_hrr_is_answered(self):
        seen = {}

        def script(peer):
            first = peer.read_client_hello()
            peer.send_hrr(group=None, cookie=b"c0")
            second = peer.read_client_hello()
            seen["cookie"] = second.extension(44).data
            seen["same_shares"] = (second.extension(51).data
                                   == first.extension(51).data)
            peer.send_server_hello()
            peer.send_handshake(peer.encrypted_extensions())
            peer.send_handshake(peer.certificate())
            peer.send_handshake(peer.certificate_verify())
            peer.send_handshake(peer.finished())
            peer.read_client_finished()
            peer.send_app(b"pong:" + peer.read_app())

        server = hostile.Tls13Server(script, ca=self.ca)
        server.start()
        self._round_trip(server.port, firefox157)
        server.join(5)
        self.assertEqual(server.errors, [])
        self.assertEqual(seen["cookie"], vector(b"c0", 2))
        self.assertTrue(seen["same_shares"])
        self.assertTrue(server.peer.client_finished_ok)


def _issue_ticket(peer):
    """A correct server that hands out one ticket, then echoes."""
    peer.handshake()
    peer.send_handshake(peer.new_session_ticket(b"ticket-%d" % peer.index))
    peer.send_app(b"pong:" + peer.read_app())


class TestTicketBinding(unittest.TestCase):
    """T3: a ticket is bound to the server it came from and to how that
    server was checked. A resumed handshake shows no certificate, so a ticket
    earned without verification must never stand in for one."""

    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _ping(self, port, tickets, **kwargs):
        with connect("localhost", port, tickets=tickets, timeout=5, **kwargs) as tls:
            tls.send(b"ping")
            self.assertEqual(tls.recv(), b"pong:ping")

    def _recording(self, offers):
        def script(peer):
            hello = peer.read_client_hello()
            offers.append(hello.extension(41) is not None)
            peer.send_server_hello()
            peer.send_handshake(peer.encrypted_extensions())
            peer.send_handshake(peer.certificate())
            peer.send_handshake(peer.certificate_verify())
            peer.send_handshake(peer.finished())
            peer.read_client_finished()
            peer.send_app(b"pong:" + peer.read_app())
        return script

    def test_ticket_from_unverified_session_not_offered_to_verified(self):
        offers = []
        recording = self._recording(offers)

        def script(peer):
            if peer.index == 0:
                _issue_ticket(peer)
            else:
                recording(peer)

        server = hostile.Tls13Server(script, ca=self.ca, connections=2)
        server.start()
        tickets = TicketStore()
        self._ping(server.port, tickets, verify=False)
        self.assertEqual(len(tickets), 1)
        self._ping(server.port, tickets, verify=True, trust_store=self.store)
        server.join(5)
        self.assertEqual(offers, [False])

    def test_ticket_not_offered_to_another_port(self):
        issuing = hostile.Tls13Server(_issue_ticket, ca=self.ca)
        issuing.start()
        offers = []
        other = hostile.Tls13Server(self._recording(offers), ca=self.ca)
        other.start()
        tickets = TicketStore()
        self._ping(issuing.port, tickets, trust_store=self.store)
        self.assertEqual(len(tickets), 1)
        self._ping(other.port, tickets, trust_store=self.store)
        issuing.join(5)
        other.join(5)
        self.assertEqual(offers, [False])

    def test_sessions_sharing_a_store_with_same_settings_still_resume(self):
        # Review Focus 5: binding tickets must not end legitimate resumption.
        from pybrws.session import Session

        port = hostile.openssl_server(hostile.http_ok, ca=self.ca, connections=2)
        url = "https://localhost:%d/" % port
        with Session(trust_store=self.store) as first, \
                Session(trust_store=self.store) as second:
            second.tickets = first.tickets
            # Recorded as opened: http_ok answers Connection: close, so the
            # pool rightly lets the connection go once the response is read.
            opened = []
            dial = second._open
            second._open = lambda *a, **k: opened.append(dial(*a, **k)) or opened[-1]
            self.assertEqual(first.get(url).status, 200)
            self.assertEqual(second.get(url).status, 200)
            tls, _http = opened[0]
            self.assertTrue(tls.resumed)


class TestKeyUpdate(unittest.TestCase):
    """T4: RFC 8446 section 4.6.3. A KeyUpdate ratchets the sender's key, so
    the receiver must ratchet its read key to keep decrypting; and when the
    peer asks, the receiver must answer with one of its own."""

    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _serve(self, script):
        server = hostile.Tls13Server(script, ca=self.ca)
        server.start()
        tls = connect("localhost", server.port, trust_store=self.store, timeout=5)
        return server, tls

    def test_update_not_requested_is_followed(self):
        def script(peer):
            peer.handshake()
            peer.send_app(b"one")
            peer.key_update(request=False)
            peer.send_app(b"two")

        server, tls = self._serve(script)
        with tls:
            self.assertEqual(tls.recv(), b"one")
            self.assertEqual(tls.recv(), b"two")
        server.join(5)
        self.assertEqual(server.errors, [])

    def test_update_requested_is_answered(self):
        def script(peer):
            peer.handshake()
            peer.key_update(request=True)
            peer.send_app(b"go")
            peer.send_app(b"pong:" + peer.read_app())

        server, tls = self._serve(script)
        with tls:
            self.assertEqual(tls.recv(), b"go")
            tls.send(b"ping")
            self.assertEqual(tls.recv(), b"pong:ping")
        server.join(5)
        self.assertEqual(server.errors, [])
        self.assertEqual(server.peer.client_key_updates, 1)


class TestRecordDiscipline(unittest.TestCase):
    """T5, T6: once TLS 1.3 keys are in place every record but a handshake-
    time ChangeCipherSpec is encrypted, so a plaintext one is an injection; a
    handshake message must not span a key change; and a post-handshake
    message may legally span several records."""

    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _connect(self, script, tickets=None):
        server = hostile.Tls13Server(script, ca=self.ca)
        server.start()
        self.addCleanup(server.join, 5)
        return connect("localhost", server.port, trust_store=self.store,
                       tickets=tickets, timeout=5)

    def test_plaintext_ticket_after_keys_is_rejected(self):
        from pybrws.records import UnexpectedRecord

        def script(peer):
            peer.handshake()
            peer.send_record(hostile.HANDSHAKE, peer.new_session_ticket(b"planted"),
                             encrypted=False)
            peer.send_app(b"data")

        tickets = TicketStore()
        with self._connect(script, tickets) as tls:
            with self.assertRaises(UnexpectedRecord):
                tls.recv()
        self.assertEqual(len(tickets), 0)

    def test_plaintext_alert_after_keys_is_rejected(self):
        from pybrws.records import UnexpectedRecord

        def script(peer):
            peer.handshake()
            peer.send_record(hostile.ALERT, b"\x01\x00", encrypted=False)

        with self._connect(script) as tls:
            with self.assertRaises(UnexpectedRecord):
                tls.recv()

    def test_message_spanning_the_key_change_is_rejected(self):
        from pybrws.handshake import HandshakeError

        def script(peer):
            peer.read_client_hello()
            peer.send_server_hello(extra_plaintext=peer.encrypted_extensions())

        with self.assertRaises(HandshakeError) as caught:
            self._connect(script)
        self.assertIn("key change", str(caught.exception))

    def test_change_cipher_spec_after_handshake_is_rejected(self):
        from pybrws.records import UnexpectedRecord

        def script(peer):
            peer.handshake()
            peer.send_record(hostile.CHANGE_CIPHER_SPEC, b"\x01", encrypted=False)
            peer.send_app(b"data")

        with self._connect(script) as tls:
            with self.assertRaises(UnexpectedRecord):
                tls.recv()

    def test_fragmented_ticket_is_reassembled(self):
        def script(peer):
            peer.handshake()
            ticket = peer.new_session_ticket(b"split-ticket")
            peer.send_record(hostile.HANDSHAKE, ticket[:10], encrypted=True)
            peer.send_record(hostile.HANDSHAKE, ticket[10:], encrypted=True)
            peer.send_app(b"data")

        tickets = TicketStore()
        with self._connect(script, tickets) as tls:
            self.assertEqual(tls.recv(), b"data")
        self.assertEqual(len(tickets), 1)


class TestTls12FirstFlight(unittest.TestCase):
    """T7, T8, T9: a server that coalesces its first flight, one that staples
    OCSP, and one whose random carries the TLS 1.3 downgrade sentinel."""

    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _connect(self, **options):
        server = hostile.Tls12Server(ca=self.ca, **options)
        server.start()
        self.addCleanup(server.join, 5)
        tls = connect("localhost", server.port, trust_store=self.store, timeout=5)
        tls.close()
        server.join(5)
        return server

    def test_plain_tls12_server_completes(self):
        # The control: the scripted server works when it does nothing odd.
        self.assertTrue(self._connect().completed)

    def test_coalesced_first_flight_completes(self):
        self.assertTrue(self._connect(coalesce_first_flight=True).completed)

    def test_certificate_status_is_accepted(self):
        self.assertTrue(self._connect(certificate_status=True).completed)

    def test_downgrade_sentinel_is_rejected(self):
        from pybrws.handshake import HandshakeError

        for suffix in (b"DOWNGRD\x01", b"DOWNGRD\x00"):
            with self.subTest(suffix=suffix):
                with self.assertRaises(HandshakeError) as caught:
                    self._connect(random_suffix=suffix)
                self.assertIn("4.1.3", str(caught.exception))


class TestServerValidation(unittest.TestCase):
    """T10: what the client checks about the server's ServerHello and flight.
    Each case is otherwise a valid handshake, so a rejection is for this one
    defect and nothing else; each message names the RFC alert (D10: raised,
    not sent)."""

    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _rejects(self, script):
        from pybrws.handshake import HandshakeError

        server = hostile.Tls13Server(script, ca=self.ca)
        server.start()
        self.addCleanup(server.join, 5)
        with self.assertRaises(HandshakeError) as caught:
            connect("localhost", server.port, trust_store=self.store, timeout=5)
        return str(caught.exception)

    @staticmethod
    def _rest_of_handshake(peer, *, alpn=None):
        peer.send_handshake(peer.encrypted_extensions(alpn))
        peer.send_handshake(peer.certificate())
        peer.send_handshake(peer.certificate_verify())
        peer.send_handshake(peer.finished())
        peer.read_client_finished()

    def _server_hello_variant(self, **server_hello):
        def script(peer):
            peer.read_client_hello()
            peer.send_server_hello(**server_hello)
            self._rest_of_handshake(peer)
        return self._rejects(script)

    def test_wrong_session_id_echo(self):
        self.assertIn("illegal_parameter",
                      self._server_hello_variant(session_id_echo=b"\x01" * 32))

    def test_nonzero_compression_method(self):
        self.assertIn("illegal_parameter",
                      self._server_hello_variant(compression=1))

    def test_duplicate_extension(self):
        duplicate = u16(43) + vector(u16(0x0304), 2)
        self.assertIn("illegal_parameter",
                      self._server_hello_variant(extra_extensions=duplicate))

    def test_extension_not_allowed_in_server_hello(self):
        alpn = u16(16) + vector(vector(vector(b"h2", 1), 2), 2)
        self.assertIn("unsupported_extension",
                      self._server_hello_variant(extra_extensions=alpn))

    def test_unoffered_alpn(self):
        def script(peer):
            peer.read_client_hello()
            peer.send_server_hello()
            self._rest_of_handshake(peer, alpn="spdy/1")
        self.assertIn("spdy/1", self._rejects(script))

    def test_missing_encrypted_extensions(self):
        def script(peer):
            peer.read_client_hello()
            peer.send_server_hello()
            peer.send_handshake(peer.certificate())
            peer.send_handshake(peer.certificate_verify())
            peer.send_handshake(peer.finished())
        self.assertIn("unexpected_message", self._rejects(script))

    def test_encrypted_extensions_out_of_order(self):
        def script(peer):
            peer.read_client_hello()
            peer.send_server_hello()
            peer.send_handshake(peer.encrypted_extensions())
            peer.send_handshake(peer.certificate())
            peer.send_handshake(peer.encrypted_extensions())
            peer.send_handshake(peer.certificate_verify())
            peer.send_handshake(peer.finished())
        self.assertIn("unexpected_message", self._rejects(script))

    def test_tls12_nonempty_renegotiation_info(self):
        from pybrws.handshake import HandshakeError

        server = hostile.Tls12Server(ca=self.ca, renegotiation_info=b"\x01\x00")
        server.start()
        self.addCleanup(server.join, 5)
        with self.assertRaises(HandshakeError) as caught:
            connect("localhost", server.port, trust_store=self.store, timeout=5)
        self.assertIn("5746", str(caught.exception))


class TestKeyShareFormat(unittest.TestCase):
    """T11: RFC 8446 section 4.2.8.2 allows only the uncompressed point form
    for the NIST curves in a key share."""

    def _point(self, curve, form):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(curve())
        return key.public_key().public_bytes(serialization.Encoding.X962, form)

    def test_compressed_p256_point_is_rejected(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        point = self._point(ec.SECP256R1, serialization.PublicFormat.CompressedPoint)
        with self.assertRaises(ValueError):
            KeyExchange([0x0017]).shared_secret(0x0017, point)

    def test_uncompressed_point_still_works(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        for group, curve in ((0x0017, ec.SECP256R1), (0x0018, ec.SECP384R1)):
            with self.subTest(group=group):
                point = self._point(curve,
                                    serialization.PublicFormat.UncompressedPoint)
                self.assertTrue(KeyExchange([group]).shared_secret(group, point))


if __name__ == "__main__":
    unittest.main()
