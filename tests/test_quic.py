"""Tests for pybrws.quic: reading a ClientHello out of QUIC Initial packets.

No network and no browser. aioquic is the oracle: it builds a client's first
flight into raw datagrams, and it is asked separately what ClientHello it
serialised, so the bytes this module recovers can be compared against the
bytes that went in. A decryptor that is wrong produces either an InvalidTag or
garbage, and a round trip through two independent implementations is the only
check that is not just this code agreeing with itself.
"""

import unittest

from pybrws.quic import (
    FRAME_CRYPTO,
    FRAME_PADDING,
    TRANSPORT_PARAMETERS,
    is_grease_parameter,
    parameter_name,
    parse_transport_parameters,
    INITIAL_SALT_V1,
    CryptoStream,
    InitialKeys,
    QuicError,
    client_hello_from_datagrams,
    crypto_frames,
    decrypt_initial,
    parse_long_header,
    varint,
)

try:
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    import aioquic.tls as aioquic_tls
except ImportError:  # pragma: no cover
    QuicConnection = None


def client_first_flight(server_name="pybrws.test", alpn=("h3",), *,
                       padded=False):
    """Raw datagrams for a client's first flight, and the hello inside them.

    The hello is taken from aioquic's own serialiser rather than from this
    module, so the comparison is between two implementations.

    `padded` turns on aioquic's quantum readiness test, which inflates the
    hello until the flight needs two datagrams. A plain aioquic hello is only
    484 bytes and fits in one, so without this the reassembly path is never
    reached -- while a browser's is around 1900 and always needs it.
    """
    serialised = []
    original = aioquic_tls.push_client_hello

    def recording(buf, hello):
        start = buf.tell()
        original(buf, hello)
        serialised.append(bytes(buf.data_slice(start, buf.tell())))

    aioquic_tls.push_client_hello = recording
    try:
        configuration = QuicConfiguration(
            is_client=True, alpn_protocols=list(alpn), server_name=server_name,
            verify_mode=0, quantum_readiness_test=padded,
        )
        connection = QuicConnection(configuration=configuration)
        connection.connect(("127.0.0.1", 4433), now=0.0)
        datagrams = [data for data, _address in connection.datagrams_to_send(now=0.0)]
    finally:
        aioquic_tls.push_client_hello = original
    # The first serialisation is the one that goes on the wire; a resumption
    # run serialises once more to place the binder.
    return datagrams, serialised[-1]


@unittest.skipIf(QuicConnection is None, "aioquic is not installed")
class TestAgainstAioquic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.datagrams, cls.expected = client_first_flight()

    def test_the_flight_fits_in_one_datagram(self):
        # Stated so the class below is understood to be the one that covers
        # reassembly: a plain aioquic hello is small enough to arrive whole.
        self.assertEqual(len(self.datagrams), 1)

    def test_the_recovered_hello_is_the_one_that_went_in(self):
        self.assertEqual(client_hello_from_datagrams(self.datagrams),
                         self.expected)

    def test_the_hello_is_a_client_hello(self):
        self.assertEqual(client_hello_from_datagrams(self.datagrams)[0], 0x01)

    def test_unrelated_datagrams_are_skipped(self):
        noise = [b"\x00" * 64, b"not quic at all", bytes(range(256))]
        self.assertEqual(client_hello_from_datagrams(noise + self.datagrams),
                         self.expected)

    def test_the_header_is_readable_without_any_key(self):
        header, offset = parse_long_header(self.datagrams[0])
        self.assertEqual(header["version"], 1)
        self.assertEqual(header["token"], b"")
        self.assertGreater(len(header["destination_id"]), 0)
        self.assertGreater(offset, 7)

    def test_decryption_is_keyed_by_the_connection_id_in_the_clear(self):
        # The point of the module: no secret is needed, only the header.
        header, _ = parse_long_header(self.datagrams[0])
        keys = InitialKeys.derive(header["destination_id"])
        packet = decrypt_initial(self.datagrams[0], keys)
        self.assertTrue(crypto_frames(packet.payload))

    def test_the_wrong_connection_id_does_not_decrypt(self):
        header, _ = parse_long_header(self.datagrams[0])
        wrong = bytes(len(header["destination_id"]))
        with self.assertRaises(Exception):
            decrypt_initial(self.datagrams[0], InitialKeys.derive(wrong))

    def test_packet_numbers_start_at_zero_and_advance(self):
        numbers = [decrypt_initial(d).packet_number for d in self.datagrams]
        self.assertEqual(numbers, sorted(numbers))
        self.assertEqual(numbers[0], 0)


@unittest.skipIf(QuicConnection is None, "aioquic is not installed")
class TestAcrossDatagrams(unittest.TestCase):
    """A hello too large for one datagram, which is every browser's."""

    @classmethod
    def setUpClass(cls):
        cls.datagrams, cls.expected = client_first_flight(padded=True)

    def test_the_flight_really_spans_two(self):
        # Without this the rest of the class tests less than it looks.
        self.assertGreater(len(self.datagrams), 1)

    def test_the_pieces_reassemble_into_the_hello_that_went_in(self):
        self.assertEqual(client_hello_from_datagrams(self.datagrams),
                         self.expected)

    def test_reassembly_survives_reordering(self):
        # UDP does not promise order, and a capture holds whatever arrived.
        self.assertEqual(
            client_hello_from_datagrams(list(reversed(self.datagrams))),
            self.expected,
        )

    def test_a_missing_datagram_is_refused_rather_than_truncated(self):
        # The dangerous outcome is a short hello that still parses, which
        # would read as a browser sending fewer extensions than it does.
        for dropped in range(len(self.datagrams)):
            partial = [d for index, d in enumerate(self.datagrams)
                       if index != dropped]
            with self.subTest(dropped=dropped):
                with self.assertRaises(QuicError):
                    client_hello_from_datagrams(partial)

    def test_each_datagram_alone_is_not_enough(self):
        for index, datagram in enumerate(self.datagrams):
            with self.subTest(datagram=index):
                with self.assertRaises(QuicError):
                    client_hello_from_datagrams([datagram])


class TestVarint(unittest.TestCase):
    """RFC 9000 appendix A gives these exact encodings."""

    def test_the_four_worked_examples(self):
        self.assertEqual(varint(bytes.fromhex("c2197c5eff14e88c"), 0),
                         (151288809941952652, 8))
        self.assertEqual(varint(bytes.fromhex("9d7f3e7d"), 0), (494878333, 4))
        self.assertEqual(varint(bytes.fromhex("7bbd"), 0), (15293, 2))
        self.assertEqual(varint(bytes.fromhex("25"), 0), (37, 1))

    def test_the_two_byte_encoding_of_a_small_value_is_accepted(self):
        # Appendix A notes 37 may also be sent as 0x4025; a decoder that only
        # handled the shortest form would reject a legal packet.
        self.assertEqual(varint(bytes.fromhex("4025"), 0), (37, 2))

    def test_the_offset_is_returned_past_the_value(self):
        data = bytes.fromhex("25") + b"rest"
        value, offset = varint(data, 0)
        self.assertEqual((value, data[offset:]), (37, b"rest"))

    def test_a_truncated_varint_raises(self):
        with self.assertRaises(QuicError):
            varint(bytes.fromhex("9d7f"), 0)
        with self.assertRaises(QuicError):
            varint(b"", 0)


class TestInitialKeys(unittest.TestCase):
    def test_the_salt_is_the_published_one(self):
        # RFC 9001 section 5.2. Wrong by a byte and nothing decrypts, with no
        # clue as to why, so it is worth asserting rather than trusting.
        self.assertEqual(INITIAL_SALT_V1.hex(),
                         "38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

    def test_the_two_directions_differ(self):
        client = InitialKeys.derive(b"\x83\x94\xc8\xf0\x3e\x51\x57\x08")
        server = InitialKeys.derive(b"\x83\x94\xc8\xf0\x3e\x51\x57\x08",
                                    client=False)
        self.assertNotEqual(client.key, server.key)
        self.assertNotEqual(client.iv, server.iv)
        self.assertNotEqual(client.header_protection, server.header_protection)

    def test_the_key_sizes_are_what_aes_128_gcm_wants(self):
        keys = InitialKeys.derive(b"\x00" * 8)
        self.assertEqual((len(keys.key), len(keys.iv),
                          len(keys.header_protection)), (16, 12, 16))

    def test_the_nonce_xors_the_packet_number_into_the_tail(self):
        keys = InitialKeys.derive(b"\x00" * 8)
        self.assertEqual(keys.nonce(0), keys.iv)
        self.assertNotEqual(keys.nonce(1), keys.iv)
        self.assertEqual(keys.nonce(1)[:11], keys.iv[:11])

    def test_the_mask_wants_exactly_one_block(self):
        keys = InitialKeys.derive(b"\x00" * 8)
        self.assertEqual(len(keys.mask(b"s" * 16)), 16)
        with self.assertRaises(QuicError):
            keys.mask(b"too short")


class TestCryptoStream(unittest.TestCase):
    def test_pieces_in_order(self):
        stream = CryptoStream()
        stream.add(0, b"\x01\x00\x00\x04")
        stream.add(4, b"abcd")
        self.assertTrue(stream.complete)
        self.assertEqual(stream.message(), b"\x01\x00\x00\x04abcd")

    def test_pieces_out_of_order(self):
        stream = CryptoStream()
        stream.add(4, b"abcd")
        stream.add(0, b"\x01\x00\x00\x04")
        self.assertEqual(stream.message(), b"\x01\x00\x00\x04abcd")

    def test_a_gap_is_not_reported_as_complete(self):
        # The failure this prevents: a hole in the middle, the tail present,
        # and a length prefix that happens to be satisfied by the byte count.
        stream = CryptoStream()
        stream.add(0, b"\x01\x00\x00\x08")
        stream.add(8, b"efgh")
        self.assertFalse(stream.complete)
        self.assertEqual(stream.contiguous, b"\x01\x00\x00\x08")
        with self.assertRaises(QuicError):
            stream.message()

    def test_overlapping_pieces_are_not_duplicated(self):
        # A retransmission may resend a range that partly arrived already.
        stream = CryptoStream()
        stream.add(0, b"\x01\x00\x00\x06abc")
        stream.add(4, b"abcdef")
        self.assertEqual(stream.message(), b"\x01\x00\x00\x06abcdef")

    def test_an_empty_stream_is_not_complete(self):
        self.assertFalse(CryptoStream().complete)
        with self.assertRaises(QuicError):
            CryptoStream().message()


class TestFrames(unittest.TestCase):
    def test_padding_is_skipped(self):
        payload = bytes([FRAME_PADDING]) * 20
        self.assertEqual(crypto_frames(payload), [])

    def test_a_crypto_frame_is_read(self):
        payload = bytes([FRAME_CRYPTO, 0x00, 0x04]) + b"abcd"
        self.assertEqual(crypto_frames(payload), [(0, b"abcd")])

    def test_crypto_after_padding(self):
        payload = (bytes([FRAME_PADDING]) * 3
                   + bytes([FRAME_CRYPTO, 0x00, 0x02]) + b"hi")
        self.assertEqual(crypto_frames(payload), [(0, b"hi")])

    def test_an_unexpected_frame_type_raises(self):
        # RFC 9000 section 17.2.2 lists what an Initial may carry. Silently
        # skipping anything else would mean mis-parsing a frame and carrying
        # on through whatever followed.
        with self.assertRaises(QuicError):
            crypto_frames(bytes([0x08, 0x00]))




class TestTransportParameters(unittest.TestCase):
    """The fingerprint QUIC adds that TCP has no equivalent of."""

    def test_wire_order_is_preserved(self):
        # A dict would throw away the thing being measured. Descending on
        # purpose: a decoder that sorted would still pass an ascending case.
        data = (bytes([0x0B, 0x01, 0x19])
                + bytes([0x0A, 0x01, 0x03])
                + bytes([0x01, 0x01, 0x05]))
        self.assertEqual([i for i, _ in parse_transport_parameters(data)],
                         [0x0B, 0x0A, 0x01])

    def test_an_empty_value_is_kept(self):
        # disable_active_migration is present-or-absent and carries nothing,
        # so a parser that dropped empties would lose it entirely.
        parsed = parse_transport_parameters(bytes([0x0C, 0x00]))
        self.assertEqual(parsed, [(0x0C, b"")])

    def test_nothing_at_all_is_fine(self):
        self.assertEqual(parse_transport_parameters(b""), [])

    def test_a_multi_byte_identifier_is_read(self):
        # grease_quic_bit is 0x2ab2, which needs a two-byte varint.
        data = bytes([0x6A, 0xB2, 0x00])
        self.assertEqual(parse_transport_parameters(data), [(0x2AB2, b"")])

    def test_a_value_running_past_the_end_raises(self):
        with self.assertRaises(QuicError):
            parse_transport_parameters(bytes([0x04, 0x08, 0x00]))

    def test_the_grease_formula(self):
        # RFC 9000 section 18.1: 31 * N + 27.
        self.assertTrue(all(is_grease_parameter(31 * n + 27) for n in range(8)))
        self.assertFalse(any(is_grease_parameter(i) for i in (0x00, 0x01, 0x0F)))

    def test_a_registered_name_wins_over_the_grease_formula(self):
        # A third of the id space satisfies the formula, so a registered
        # parameter can match it by coincidence; renaming it to GREASE would
        # quietly drop it from the comparison.
        collisions = [i for i in TRANSPORT_PARAMETERS if is_grease_parameter(i)]
        for identifier in collisions:
            with self.subTest(identifier=hex(identifier)):
                self.assertEqual(parameter_name(identifier),
                                 TRANSPORT_PARAMETERS[identifier])

    def test_an_unknown_identifier_says_so(self):
        self.assertEqual(parameter_name(0x4444), "unknown(17476)")


if __name__ == "__main__":
    unittest.main()
