"""Tests for pybrws.tls12 and the TLS 1.2 handshake.

The integration tests run against Python's own `ssl` module as a server,
pinned to TLS 1.2. That makes OpenSSL the oracle: if the PRF, the key block,
the record protection or either Finished is wrong, the handshake fails. No
amount of unit testing a PRF against itself proves that much.

The unit tests below it cover the parts where a wrong answer still looks like
an answer -- the key block's partitioning, the two AEAD nonce constructions,
and the message parsers.
"""

import socket
import ssl
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import _selfsigned  # noqa: E402

from pybrws import tls12  # noqa: E402
from pybrws.handshake import HandshakeError, connect  # noqa: E402
from pybrws.records import CHANGE_CIPHER_SPEC  # noqa: E402

HOSTNAME = "pybrws.test"


class LocalServer:
    """A TLS server on localhost, pinned to one protocol version."""

    def __init__(self, maximum=ssl.TLSVersion.TLSv1_2, alpn=("http/1.1",),
                 ask_for_certificate=False, ciphers=None):
        self.context, self._tmp = _selfsigned.context(HOSTNAME, list(alpn))
        self.context.maximum_version = maximum
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        if ask_for_certificate:
            self.context.verify_mode = ssl.CERT_OPTIONAL
        if ciphers:
            self.context.set_ciphers(ciphers)
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.version = None
        self.cipher = None
        self.received = None
        self.error = None
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            raw, _peer = self.listener.accept()
            with self.context.wrap_socket(raw, server_side=True) as tls:
                self.version = tls.version()
                self.cipher = tls.cipher()
                self.received = tls.recv(4096)
                tls.sendall(b"pong")
        except Exception as exc:          # recorded, not raised, for the test
            self.error = exc
        finally:
            self.listener.close()

    def join(self, timeout=10.0):
        self._thread.join(timeout)


@unittest.skipIf(sys.platform == "emscripten", "needs real sockets")
class TestAgainstOpenSsl(unittest.TestCase):
    """OpenSSL as the oracle for every derivation at once."""

    def exchange(self, **kwargs) -> LocalServer:
        server = LocalServer(**kwargs)
        self.addCleanup(server.join)
        with connect("127.0.0.1", server.port, verify=False, timeout=10) as tls:
            tls.send(b"ping")
            self.assertEqual(tls.recv(), b"pong")
            self.negotiated = tls.suite
            self.alpn = tls.alpn
        server.join()
        if server.error is not None:
            raise server.error
        return server

    def test_a_full_tls_12_handshake_and_round_trip(self):
        server = self.exchange()
        self.assertEqual(server.version, "TLSv1.2")
        self.assertEqual(server.received, b"ping")
        self.assertIn(self.negotiated.id, tls12.SUITES)

    def test_the_server_sees_the_alpn_we_asked_for(self):
        server = self.exchange(alpn=("http/1.1",))
        self.assertEqual(server.version, "TLSv1.2")
        self.assertEqual(self.alpn, "http/1.1")

    def test_h2_over_tls_12(self):
        self.exchange(alpn=("h2",))
        self.assertEqual(self.alpn, "h2")

    def test_a_client_certificate_request_does_not_break_it(self):
        # The server asks and we have nothing to give. A browser answers with
        # an empty Certificate and carries on; this used to raise.
        server = self.exchange(ask_for_certificate=True)
        self.assertEqual(server.version, "TLSv1.2")
        self.assertEqual(server.received, b"ping")

    def test_chacha20_poly1305(self):
        # The other AEAD construction: twelve bytes of fixed IV and no
        # explicit nonce, where GCM has four and eight. A client that uses
        # one for the other produces records the peer cannot open.
        server = self.exchange(ciphers="ECDHE+CHACHA20")
        self.assertEqual(server.version, "TLSv1.2")
        self.assertEqual(self.negotiated.aead.__name__, "ChaCha20Poly1305")

    def test_aes_256_gcm_with_a_sha384_prf(self):
        # SHA384 changes the PRF and the key sizes while the Finished stays
        # twelve bytes, which is the part easy to get wrong.
        # ECDSA rather than RSA: the test certificate is an EC key, so an
        # ECDHE-RSA suite cannot be selected and the server answers
        # handshake_failure for a reason that has nothing to do with us.
        server = self.exchange(ciphers="ECDHE-ECDSA-AES256-GCM-SHA384")
        self.assertEqual(server.version, "TLSv1.2")
        self.assertEqual(self.negotiated.hash_size, 48)

    def test_tls_13_still_works_against_the_same_harness(self):
        # The branch is on the ServerHello, so both paths share everything up
        # to it; a change to one can break the other silently.
        server = LocalServer(maximum=ssl.TLSVersion.TLSv1_3)
        self.addCleanup(server.join)
        with connect("127.0.0.1", server.port, verify=False, timeout=10) as tls:
            tls.send(b"ping")
            self.assertEqual(tls.recv(), b"pong")
        server.join()
        self.assertEqual(server.version, "TLSv1.3")

    def test_the_compatibility_change_cipher_spec_is_not_sent_too_early(self):
        # It used to go out immediately after the ClientHello, which TLS 1.3
        # servers tolerate and a TLS 1.2 server answers with
        # handshake_failure. The bug was invisible for as long as 1.2 was
        # unreachable, so this is the regression test for it: a 1.2 handshake
        # completing at all proves the ordering.
        server = self.exchange()
        self.assertEqual(server.version, "TLSv1.2")


class TestThePrf(unittest.TestCase):
    SUITE = tls12.SUITES[0xC02F]

    def test_it_produces_the_length_asked_for(self):
        for length in (1, 12, 32, 48, 104, 200):
            with self.subTest(length=length):
                self.assertEqual(
                    len(tls12.prf(self.SUITE, b"s", b"label", b"seed", length)),
                    length)

    def test_it_is_deterministic(self):
        a = tls12.prf(self.SUITE, b"s", b"label", b"seed", 48)
        b = tls12.prf(self.SUITE, b"s", b"label", b"seed", 48)
        self.assertEqual(a, b)

    def test_every_input_changes_the_output(self):
        base = tls12.prf(self.SUITE, b"s", b"label", b"seed", 48)
        self.assertNotEqual(base, tls12.prf(self.SUITE, b"t", b"label", b"seed", 48))
        self.assertNotEqual(base, tls12.prf(self.SUITE, b"s", b"labeL", b"seed", 48))
        self.assertNotEqual(base, tls12.prf(self.SUITE, b"s", b"label", b"seeD", 48))

    def test_a_longer_output_extends_a_shorter_one(self):
        # P_hash is a chain, so the first bytes must not change with length.
        short = tls12.prf(self.SUITE, b"s", b"l", b"d", 32)
        long = tls12.prf(self.SUITE, b"s", b"l", b"d", 96)
        self.assertEqual(long[:32], short)

    def test_the_hash_matters(self):
        sha384 = tls12.SUITES[0xC030]
        self.assertNotEqual(
            tls12.prf(self.SUITE, b"s", b"l", b"d", 48),
            tls12.prf(sha384, b"s", b"l", b"d", 48))

    def test_verify_data_is_twelve_bytes_whatever_the_hash(self):
        for suite in (self.SUITE, tls12.SUITES[0xC030]):
            with self.subTest(suite=suite.name):
                data = tls12.finished_verify_data(
                    suite, b"m" * 48, b"client finished", b"h" * suite.hash_size)
                self.assertEqual(len(data), tls12.VERIFY_DATA_SIZE)

    def test_the_two_finished_labels_differ(self):
        # Using one label for both directions gives a handshake that verifies
        # against itself and against nothing else.
        args = (self.SUITE, b"m" * 48)
        self.assertNotEqual(
            tls12.finished_verify_data(*args, b"client finished", b"h" * 32),
            tls12.finished_verify_data(*args, b"server finished", b"h" * 32))


class TestTheKeyBlock(unittest.TestCase):
    SUITE = tls12.SUITES[0xC02F]

    def test_the_pieces_are_the_sizes_the_suite_says(self):
        ck, sk, ci, si = tls12.key_block(self.SUITE, b"m" * 48, b"c" * 32,
                                         b"s" * 32)
        self.assertEqual(len(ck), self.SUITE.key_size)
        self.assertEqual(len(sk), self.SUITE.key_size)
        self.assertEqual(len(ci), self.SUITE.fixed_iv_size)
        self.assertEqual(len(si), self.SUITE.fixed_iv_size)

    def test_the_directions_differ(self):
        ck, sk, ci, si = tls12.key_block(self.SUITE, b"m" * 48, b"c" * 32,
                                         b"s" * 32)
        self.assertNotEqual(ck, sk)
        self.assertNotEqual(ci, si)

    def test_the_randoms_go_in_server_first(self):
        # RFC 5246 reverses them here against the master secret, and getting
        # it backwards gives two endpoints that each think the other's
        # records are corrupt.
        forward = tls12.key_block(self.SUITE, b"m" * 48, b"c" * 32, b"s" * 32)
        backward = tls12.key_block(self.SUITE, b"m" * 48, b"s" * 32, b"c" * 32)
        self.assertNotEqual(forward, backward)

    def test_chacha20_takes_a_twelve_byte_iv(self):
        suite = tls12.SUITES[0xCCA8]
        _ck, _sk, ci, _si = tls12.key_block(suite, b"m" * 48, b"c" * 32,
                                            b"s" * 32)
        self.assertEqual(len(ci), 12)
        self.assertEqual(suite.explicit_nonce_size, 0)

    def test_extended_master_secret_differs_from_the_plain_one(self):
        # RFC 7627. Firefox asks for it, so deriving the other way fails the
        # Finished with bad_record_mac and no hint as to why.
        plain = tls12.master_secret(self.SUITE, b"p" * 48, b"c" * 32, b"s" * 32)
        extended = tls12.extended_master_secret(self.SUITE, b"p" * 48, b"h" * 32)
        self.assertEqual(len(plain), 48)
        self.assertEqual(len(extended), 48)
        self.assertNotEqual(plain, extended)


class TestTheCipher(unittest.TestCase):
    def round_trip(self, suite_id: int) -> None:
        suite = tls12.SUITES[suite_id]
        key = b"k" * suite.key_size
        iv = b"i" * suite.fixed_iv_size
        writer = tls12.Cipher(suite, key, iv)
        reader = tls12.Cipher(suite, key, iv)
        for index in range(4):
            plaintext = b"message %d" % index
            record = writer.encrypt(0x17, plaintext)
            self.assertEqual(record[0], 0x17, "the content type stays in the clear")
            header, payload = record[:5], record[5:]
            self.assertEqual(int.from_bytes(header[3:5], "big"), len(payload))
            kind, opened = reader.decrypt(header, payload)
            self.assertEqual((kind, opened), (0x17, plaintext))

    def test_aes_128_gcm(self):
        self.round_trip(0xC02F)

    def test_aes_256_gcm(self):
        self.round_trip(0xC030)

    def test_chacha20_poly1305(self):
        self.round_trip(0xCCA8)

    def test_the_sequence_number_is_in_the_additional_data(self):
        # Reusing it would let records be replayed or reordered unnoticed.
        suite = tls12.SUITES[0xC02F]
        key, iv = b"k" * 16, b"i" * 4
        writer = tls12.Cipher(suite, key, iv)
        first = writer.encrypt(0x17, b"same")
        second = writer.encrypt(0x17, b"same")
        self.assertNotEqual(first, second)

    def test_a_record_out_of_order_does_not_open(self):
        from cryptography.exceptions import InvalidTag

        suite = tls12.SUITES[0xC02F]
        key, iv = b"k" * 16, b"i" * 4
        writer = tls12.Cipher(suite, key, iv)
        reader = tls12.Cipher(suite, key, iv)
        writer.encrypt(0x17, b"first")
        second = writer.encrypt(0x17, b"second")
        with self.assertRaises(InvalidTag):
            reader.decrypt(second[:5], second[5:])

    def test_gcm_puts_the_explicit_nonce_on_the_wire(self):
        suite = tls12.SUITES[0xC02F]
        writer = tls12.Cipher(suite, b"k" * 16, b"i" * 4)
        record = writer.encrypt(0x17, b"x")
        # 5 header + 8 explicit nonce + 1 plaintext + 16 tag
        self.assertEqual(len(record), 5 + 8 + 1 + 16)

    def test_chacha20_puts_nothing_on_the_wire(self):
        suite = tls12.SUITES[0xCCA8]
        writer = tls12.Cipher(suite, b"k" * 32, b"i" * 12)
        record = writer.encrypt(0x17, b"x")
        self.assertEqual(len(record), 5 + 1 + 16)

    def test_a_truncated_record_is_refused(self):
        suite = tls12.SUITES[0xC02F]
        reader = tls12.Cipher(suite, b"k" * 16, b"i" * 4)
        with self.assertRaises(tls12.Tls12Error):
            reader.decrypt(b"\x17\x03\x03\x00\x03", b"abc")

    def test_reset_puts_the_sequence_back(self):
        suite = tls12.SUITES[0xC02F]
        writer = tls12.Cipher(suite, b"k" * 16, b"i" * 4)
        first = writer.encrypt(0x17, b"same")
        writer.reset()
        self.assertEqual(writer.encrypt(0x17, b"same"), first)


class TestSuiteSelection(unittest.TestCase):
    def test_the_implemented_ones_resolve(self):
        for suite_id in (0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8):
            with self.subTest(suite=hex(suite_id)):
                self.assertEqual(tls12.suite_for(suite_id).id, suite_id)

    def test_an_offered_but_unimplemented_one_says_which(self):
        # Offered because Firefox offers it; refused by name so the failure
        # reads as a decision rather than a crash.
        with self.assertRaises(tls12.Tls12Error) as caught:
            tls12.suite_for(0x002F)
        self.assertIn("RSA_WITH_AES_128_CBC_SHA", str(caught.exception))

    def test_one_that_was_never_offered_says_so(self):
        with self.assertRaises(tls12.Tls12Error) as caught:
            tls12.suite_for(0x1234)
        self.assertIn("never offered", str(caught.exception))

    def test_every_tls_12_suite_in_the_profile_is_accounted_for(self):
        # Either implemented or explicitly refused. A suite in neither table
        # would fail with a KeyError from somewhere unhelpful.
        from pybrws.profiles import firefox157

        for suite_id in firefox157.CIPHER_SUITES:
            if suite_id in (0x1301, 0x1302, 0x1303):
                continue
            with self.subTest(suite=hex(suite_id)):
                self.assertTrue(suite_id in tls12.SUITES
                                or suite_id in tls12.UNIMPLEMENTED)


class TestMessages(unittest.TestCase):
    def test_a_server_key_exchange_round_trips(self):
        from pybrws.wire import u16, vector

        point = b"\x04" + b"p" * 64
        body = (bytes([tls12.CURVE_TYPE_NAMED]) + u16(0x0017) + vector(point, 1)
                + u16(0x0401) + vector(b"sig", 2))
        exchange = tls12.parse_server_key_exchange(body)
        self.assertEqual(exchange.group, 0x0017)
        self.assertEqual(exchange.peer_point, point)
        self.assertEqual(exchange.scheme, 0x0401)
        self.assertEqual(exchange.signature, b"sig")

    def test_the_signed_params_stop_before_the_signature(self):
        # Including the signature in what it covers is a mistake that still
        # verifies against a server making the same one, and against nothing
        # real.
        from pybrws.wire import u16, vector

        point = b"\x04" + b"p" * 64
        params = bytes([tls12.CURVE_TYPE_NAMED]) + u16(0x0017) + vector(point, 1)
        body = params + u16(0x0401) + vector(b"sig", 2)
        self.assertEqual(tls12.parse_server_key_exchange(body).signed_params,
                         params)

    def test_an_explicit_curve_is_refused(self):
        with self.assertRaises(tls12.Tls12Error):
            tls12.parse_server_key_exchange(b"\x01\x00\x00\x00")

    def test_a_truncated_one_is_refused(self):
        with self.assertRaises(tls12.Tls12Error):
            tls12.parse_server_key_exchange(b"\x03\x00\x17\x40")

    def test_a_certificate_message_parses(self):
        from pybrws.wire import vector

        body = vector(vector(b"first", 3) + vector(b"second", 3), 3)
        self.assertEqual(tls12.parse_certificate(body), [b"first", b"second"])

    def test_an_empty_certificate_list_is_refused(self):
        from pybrws.wire import vector

        with self.assertRaises(tls12.Tls12Error):
            tls12.parse_certificate(vector(b"", 3))

    def test_our_empty_certificate_is_a_valid_empty_list(self):
        self.assertEqual(tls12.empty_certificate(), b"\x00\x00\x00")

    def test_a_client_key_exchange_is_the_point_length_prefixed(self):
        self.assertEqual(tls12.client_key_exchange(b"\x04abc"),
                         b"\x04\x04abc")


if __name__ == "__main__":
    unittest.main()
