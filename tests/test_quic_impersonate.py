"""Tests for pybrws.quic_impersonate, offline.

Two kinds. One asserts the hello this produces against the Firefox capture,
which is the measurement. The other asserts that the seams in aioquic are
still where this module reaches into them -- because every one of them is a
private name in a dependency, and the failure mode of a moved seam is a
handshake that dies somewhere far from the cause. An upgrade should break a
test, not a connection.
"""

import unittest
from pathlib import Path

from pybrws import quic_impersonate as qi
from pybrws.hexio import load_hex
from pybrws.parser import parse_client_hello
from pybrws.profiles import firefox157_quic as profile
from pybrws.quic import client_hello_from_datagrams, parse_transport_parameters

try:
    import aioquic.tls as aioquic_tls
    from aioquic.quic.connection import QuicConnection
except ImportError:  # pragma: no cover
    QuicConnection = None

FIXTURE = (Path(__file__).resolve().parent.parent / "fixtures"
           / "reference-firefox-157-quic.hex")
CAPTURED_HOST = "blog-cloudflare-com-assets.storage.googleapis.com"
PER_CONNECTION = (0, 51, 65037)   # host, keys, greased payload


def build(host=CAPTURED_HOST):
    """One client's first flight, as bytes, with the patch installed."""
    connection = QuicConnection(configuration=qi.configuration(host, verify=False))
    connection.connect(("192.0.2.1", 443), now=0.0)
    datagrams = [data for data, _ in connection.datagrams_to_send(now=0.0)]
    return parse_client_hello(client_hello_from_datagrams(datagrams)), connection


@unittest.skipIf(QuicConnection is None, "aioquic is not installed")
class ImpersonationCase(unittest.TestCase):
    def setUp(self):
        qi.install()
        self.addCleanup(qi.uninstall)


class TestTheHello(ImpersonationCase):
    @classmethod
    def setUpClass(cls):
        cls.golden = parse_client_hello(load_hex(FIXTURE))

    def test_every_static_payload_matches_the_capture(self):
        ours, _ = build()
        for kind, payload in profile.STATIC_PAYLOADS.items():
            with self.subTest(extension=kind):
                self.assertEqual(ours.extension(kind).data, payload)
                self.assertEqual(ours.extension(kind).data,
                                 self.golden.extension(kind).data)

    def test_the_per_connection_extensions_match_in_length(self):
        ours, _ = build()
        for kind in PER_CONNECTION:
            with self.subTest(extension=kind):
                self.assertEqual(len(ours.extension(kind).data),
                                 len(self.golden.extension(kind).data))

    def test_the_whole_hello_is_the_captured_length(self):
        ours, _ = build()
        self.assertEqual(len(ours.raw), len(self.golden.raw))

    def test_the_extension_set_and_tail_match(self):
        ours, _ = build()
        self.assertEqual(frozenset(ours.extension_types()),
                         frozenset(self.golden.extension_types()))
        self.assertEqual(tuple(ours.extension_types()[-2:]),
                         profile.PINNED_TAIL)

    def test_the_cipher_suites_and_session_id_match(self):
        ours, _ = build()
        self.assertEqual(list(ours.cipher_suites), list(self.golden.cipher_suites))
        self.assertEqual(ours.session_id, self.golden.session_id)

    def test_the_transport_parameters_match_but_for_the_connection_id(self):
        ours, _ = build()
        mine = parse_transport_parameters(ours.extension(57).data)
        theirs = parse_transport_parameters(self.golden.extension(57).data)
        self.assertEqual([i for i, _ in mine], [i for i, _ in theirs])
        for (identifier, value), (_, expected) in zip(mine, theirs):
            if identifier == profile.PARAMETER_SOURCE_CONNECTION_ID:
                self.assertEqual(len(value), profile.CONNECTION_ID_SIZE)
                continue
            with self.subTest(parameter=hex(identifier)):
                self.assertEqual(value, expected)

    def test_the_order_differs_between_connections(self):
        orders = {tuple(build()[0].extension_types()) for _ in range(12)}
        self.assertGreater(len(orders), 1,
                           "the order must be drawn, not stored")

    def test_the_flight_takes_two_datagrams(self):
        # 1931 bytes cannot fit in the 1200 QUIC starts with, which is why
        # the reader needed reassembly in the first place.
        connection = QuicConnection(
            configuration=qi.configuration(CAPTURED_HOST, verify=False))
        connection.connect(("192.0.2.1", 443), now=0.0)
        datagrams = [data for data, _ in connection.datagrams_to_send(now=0.0)]
        self.assertEqual(len(datagrams), 2)

    def test_a_different_host_changes_only_the_server_name(self):
        short, _ = build("a.test")
        long, _ = build("a.test" + "x" * 10)
        self.assertEqual(len(long.raw) - len(short.raw), 10)


class TestTheConnectionIds(ImpersonationCase):
    def test_the_source_id_is_the_profile_length(self):
        _, connection = build()
        self.assertEqual(len(connection.host_cid), profile.CONNECTION_ID_SIZE)

    def test_the_initial_destination_id_is_longer(self):
        # RFC 9000 section 7.2 requires at least 8 bytes. aioquic has one
        # setting for both lengths, so matching Firefox's three-byte source id
        # made this three too -- which Cloudflare tolerated and Google
        # answered by dropping every Initial packet without a word.
        _, connection = build()
        self.assertEqual(len(connection._original_destination_connection_id),
                         profile.INITIAL_DESTINATION_ID_SIZE)
        self.assertGreaterEqual(
            len(connection._original_destination_connection_id), 8)

    def test_the_sent_destination_id_is_the_one_the_keys_came_from(self):
        # They are derived from it, so a mismatch makes every Initial packet
        # undecryptable by the peer and says nothing about why.
        from pybrws.quic import parse_long_header

        connection = QuicConnection(
            configuration=qi.configuration(CAPTURED_HOST, verify=False))
        connection.connect(("192.0.2.1", 443), now=0.0)
        datagram = next(data for data, _ in connection.datagrams_to_send(now=0.0))
        header, _ = parse_long_header(datagram)
        self.assertEqual(header["destination_id"],
                         connection._original_destination_connection_id)

    def test_the_two_ids_are_not_the_same_bytes(self):
        _, connection = build()
        self.assertNotEqual(connection.host_cid,
                            connection._original_destination_connection_id)


class TestTheSeams(ImpersonationCase):
    """Every private name this module reaches for, asserted to still exist."""

    def test_the_module_functions_are_there(self):
        for name in ("push_client_hello", "decode_public_key",
                     "pull_certificate"):
            with self.subTest(name=name):
                self.assertTrue(hasattr(aioquic_tls, name))

    def test_the_context_methods_are_there(self):
        for name in ("_client_send_hello", "_client_handle_hello",
                     "_handle_reassembled_message", "_set_peer_certificate",
                     "_set_state"):
            with self.subTest(name=name):
                self.assertTrue(hasattr(aioquic_tls.Context, name))

    def test_the_key_exchange_hole_is_still_the_right_shape(self):
        # The stub works only because aioquic computes the shared secret as
        # self._x25519_private_key.exchange(peer_public_key). If that changes
        # the stub silently stops being reached and the group it stands in for
        # stops working.
        # The original, not the wrapper installed over it -- inspecting the
        # wrapper would only prove this module calls its own stub.
        original = qi._originals["_client_handle_hello"]
        source = original.__code__.co_names
        self.assertIn("_x25519_private_key", source)
        self.assertIn("decode_public_key", source)
        self.assertIn("exchange", source)

    def test_aioquic_still_lacks_the_post_quantum_group(self):
        # The whole reason for the stub. If aioquic gains 0x11ec, most of this
        # module can go away, and this test is where that gets noticed.
        self.assertNotIn(0x11EC, [group.value for group in aioquic_tls.Group])

    def test_aioquic_names_compressed_certificates_but_does_not_handle_them(self):
        # It has the enum member, which is what made the failure confusing:
        # the type is known and the handling is absent, so the dispatcher
        # falls through to unexpected_message. If handling appears, that seam
        # can go, and this is where it gets noticed.
        self.assertEqual(aioquic_tls.HandshakeType.COMPRESSED_CERTIFICATE, 25)
        dispatcher = qi._originals["_handle_reassembled_message"]
        self.assertNotIn("COMPRESSED_CERTIFICATE",
                         dispatcher.__code__.co_names)

    def test_installing_twice_is_harmless(self):
        first = aioquic_tls.push_client_hello
        qi.install()
        self.assertIs(aioquic_tls.push_client_hello, first)

    def test_uninstall_puts_everything_back(self):
        patched = {
            "push_client_hello": aioquic_tls.push_client_hello,
            "decode_public_key": aioquic_tls.decode_public_key,
        }
        qi.uninstall()
        self.assertFalse(qi.installed())
        for name, was in patched.items():
            with self.subTest(name=name):
                self.assertIsNot(getattr(aioquic_tls, name), was)
        qi.install()   # the cleanup expects it installed

    def test_an_unpatched_hello_is_left_alone(self):
        # A connection this module did not set up must get aioquic's own
        # behaviour rather than a guess.
        qi.uninstall()
        connection = QuicConnection(
            configuration=qi.configuration(CAPTURED_HOST, verify=False))
        connection.connect(("192.0.2.1", 443), now=0.0)
        datagrams = [data for data, _ in connection.datagrams_to_send(now=0.0)]
        hello = parse_client_hello(client_hello_from_datagrams(datagrams))
        self.assertNotEqual(len(hello.extensions), 15)
        qi.install()


class _FakeSchedule:
    def __init__(self):
        self.hashed = []

    def update_hash(self, data):
        self.hashed.append(bytes(data))


class _FakeContext:
    """Enough of a Context for the compressed-certificate seam."""

    def __init__(self):
        self.key_schedule = _FakeSchedule()
        self.certificates = []
        self.states = []

    def _set_peer_certificate(self, certificate):
        self.certificates.append(certificate)

    def _set_state(self, state):
        self.states.append(state)


@unittest.skipIf(QuicConnection is None, "aioquic is not installed")
class TestCompressedCertificates(unittest.TestCase):
    """RFC 8879, which the impersonation itself provoked.

    Advertising compress_certificate because Firefox does means servers send
    handshake type 25, which aioquic answers with unexpected_message. The
    subtle part is the transcript: section 5 hashes the compressed message,
    so decompressing and handing the result to aioquic's own handler would
    hash the wrong bytes and fail Finished with no clue as to why.
    """

    def setUp(self):
        qi.install()
        self.addCleanup(qi.uninstall)

    @staticmethod
    def certificate_body(cert: bytes = b"a fake certificate") -> bytes:
        from pybrws.wire import u16, u24, u8, vector

        entry = vector(cert, 3) + u16(0)
        return vector(b"", 1) + vector(entry, 3)

    def compressed_message(self, body: bytes) -> bytes:
        import zlib

        from pybrws.wire import u16, u24, vector

        squeezed = zlib.compress(body)
        payload = u16(1) + u24(len(body)) + vector(squeezed, 3)
        return bytes([0x19]) + u24(len(payload)) + payload

    def dispatch(self, message: bytes):
        from aioquic.buffer import Buffer

        context = _FakeContext()
        aioquic_tls.Context._handle_reassembled_message(
            context, 0x19, Buffer(data=message), {})
        return context

    def test_the_certificate_comes_through(self):
        body = self.certificate_body()
        context = self.dispatch(self.compressed_message(body))
        self.assertEqual(len(context.certificates), 1)

    def test_the_transcript_gets_the_compressed_message(self):
        body = self.certificate_body()
        message = self.compressed_message(body)
        context = self.dispatch(message)
        self.assertEqual(context.key_schedule.hashed, [message])

    def test_the_transcript_does_not_get_the_decompressed_one(self):
        # The failure this prevents: a Finished check that fails for a reason
        # nothing in the error mentions.
        body = self.certificate_body()
        message = self.compressed_message(body)
        context = self.dispatch(message)
        plain = bytes([0x0B]) + len(body).to_bytes(3, "big") + body
        self.assertNotIn(plain, context.key_schedule.hashed)

    def test_the_state_advances_to_certificate_verify(self):
        context = self.dispatch(self.compressed_message(self.certificate_body()))
        self.assertEqual(context.states, [aioquic_tls.State.CLIENT_EXPECT_CERTIFICATE_VERIFY])

    def test_other_message_types_are_passed_straight_through(self):
        from aioquic.buffer import Buffer

        context = _FakeContext()
        with self.assertRaises(Exception):
            # Not a type 25, so aioquic's own dispatcher runs and rejects it
            # for having no state, rather than this module swallowing it.
            aioquic_tls.Context._handle_reassembled_message(
                context, 0x08, Buffer(data=b"\x08\x00\x00\x00"), {})


if __name__ == "__main__":
    unittest.main()
