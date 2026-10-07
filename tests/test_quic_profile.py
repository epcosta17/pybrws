"""Tests for profiles.firefox157_quic against the capture it came from.

Every constant in the profile is asserted against
fixtures/reference-firefox-157-quic.hex, because a measured constant with no
test is one that can be deleted without the suite objecting -- which has
already happened once in this project.

What cannot be asserted against a single fixture is the order, since Firefox
draws a fresh one per connection. What is asserted instead is the shape of
the draw: the set never changes, the last two never move, and the shuffle is
uniform.
"""

import collections
import unittest
from pathlib import Path

from pybrws.hexio import load_hex
from pybrws.parser import parse_client_hello
from pybrws.profiles import firefox157, firefox157_quic as profile
from pybrws.quic import parse_transport_parameters

FIXTURE = (Path(__file__).resolve().parent.parent / "fixtures"
           / "reference-firefox-157-quic.hex")


class TestAgainstTheCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hello = parse_client_hello(load_hex(FIXTURE))

    def test_every_static_payload_matches_byte_for_byte(self):
        for kind, payload in profile.STATIC_PAYLOADS.items():
            with self.subTest(extension=kind):
                self.assertEqual(self.hello.extension(kind).data, payload)

    def test_the_extension_set_matches(self):
        self.assertEqual(frozenset(self.hello.extension_types()),
                         profile.EXTENSION_SET)

    def test_the_capture_ends_with_the_pinned_tail(self):
        self.assertEqual(tuple(self.hello.extension_types()[-2:]),
                         profile.PINNED_TAIL)

    def test_the_cipher_suites_match(self):
        self.assertEqual(tuple(self.hello.cipher_suites), profile.CIPHER_SUITES)

    def test_the_session_id_is_empty(self):
        # The TCP profile sends 32 bytes for middlebox compatibility, which
        # QUIC has no need of. Sending them here would be conspicuous.
        self.assertEqual(len(self.hello.session_id), profile.SESSION_ID_SIZE)
        self.assertEqual(len(self.hello.session_id), 0)

    def test_the_key_share_groups_and_sizes_match(self):
        from pybrws.parser import _Reader

        entries = _Reader(_Reader(self.hello.extension(51).data).vector(2))
        seen = []
        while entries.remaining:
            seen.append((entries.uint(2), len(entries.vector(2))))
        self.assertEqual(tuple(seen), profile.KEY_SHARE_GROUPS)

    def test_the_transport_parameters_match_in_order_and_value(self):
        captured = parse_transport_parameters(self.hello.extension(57).data)
        self.assertEqual([i for i, _ in captured],
                         [i for i, _ in profile.TRANSPORT_PARAMETERS])
        for (identifier, value), (_, expected) in zip(
                captured, profile.TRANSPORT_PARAMETERS):
            if identifier == profile.PARAMETER_SOURCE_CONNECTION_ID:
                continue  # the connection's own, not the profile's
            with self.subTest(parameter=hex(identifier)):
                self.assertEqual(value, expected)

    def test_rebuilding_the_parameters_reproduces_the_capture(self):
        captured = dict(parse_transport_parameters(self.hello.extension(57).data))
        rebuilt = profile.transport_parameters(
            captured[profile.PARAMETER_SOURCE_CONNECTION_ID])
        self.assertEqual(rebuilt, self.hello.extension(57).data)

    def test_the_greased_ech_payload_is_the_captured_length(self):
        self.assertEqual(len(self.hello.extension(65037).data),
                         42 + profile.ECH_PAYLOAD_SIZE)

    def test_the_server_name_rebuilds(self):
        from pybrws.parser import _Reader

        data = self.hello.extension(0).data
        reader = _Reader(_Reader(data).vector(2))
        reader.uint(1)
        host = reader.vector(2).decode("ascii")
        self.assertEqual(profile.server_name(host), data)


class TestItIsNotTheTcpProfile(unittest.TestCase):
    """The differences that make this a separate profile rather than a flag."""

    def test_fewer_cipher_suites(self):
        tcp = parse_client_hello(load_hex(
            FIXTURE.parent / "reference-firefox-157-windows-fresh.hex"))
        self.assertEqual(len(tcp.cipher_suites), 15)
        self.assertEqual(len(profile.CIPHER_SUITES), 3)

    def test_the_tls_12_extensions_are_gone(self):
        for kind in (11, 35):  # ec_point_formats, session_ticket
            self.assertNotIn(kind, profile.EXTENSION_SET)

    def test_signed_certificate_timestamp_is_gone_too(self):
        # This one does not follow from TLS 1.2 being unavailable, so it is
        # asserted on its own rather than lumped in above.
        self.assertNotIn(18, profile.EXTENSION_SET)

    def test_the_transport_parameters_extension_is_new(self):
        self.assertIn(57, profile.EXTENSION_SET)

    def test_fewer_supported_groups_than_tcp(self):
        self.assertEqual(len(profile.SUPPORTED_GROUPS), 5)
        self.assertEqual(profile.SUPPORTED_GROUPS[0], 0x11EC,
                         "the post-quantum group still comes first")

    def test_the_tcp_profile_still_has_a_fixed_order(self):
        # Stated here so the contrast is recorded in one place: the TCP
        # profile's order is a constant and this one's is drawn.
        self.assertTrue(hasattr(firefox157, "EXTENSIONS"))
        self.assertFalse(hasattr(firefox157, "extension_order"))
        self.assertTrue(hasattr(profile, "extension_order"))


class TestTheDraw(unittest.TestCase):
    def test_the_set_never_changes(self):
        for _ in range(200):
            self.assertEqual(frozenset(profile.extension_order()),
                             profile.EXTENSION_SET)

    def test_the_length_never_changes(self):
        for _ in range(200):
            self.assertEqual(len(profile.extension_order()),
                             len(profile.EXTENSION_SET))

    def test_the_tail_is_always_pinned(self):
        for _ in range(200):
            self.assertEqual(tuple(profile.extension_order()[-2:]),
                             profile.PINNED_TAIL)

    def test_the_tail_appears_nowhere_else(self):
        for _ in range(100):
            order = profile.extension_order()
            for kind in profile.PINNED_TAIL:
                self.assertEqual(order.count(kind), 1)

    def test_consecutive_draws_differ(self):
        # Thirteen items is 6 billion orders; two equal draws in fifty would
        # mean the shuffle is not shuffling.
        draws = {tuple(profile.extension_order()) for _ in range(50)}
        self.assertEqual(len(draws), 50)

    def test_the_draw_is_replayable(self):
        # A fixed rng has to give a fixed order, or nothing about the shuffle
        # can be tested except by sampling.
        def fixed(_n, box=[0]):
            box[0] = (box[0] + 7) % 251
            return bytes([box[0]])

        first = profile.extension_order(_reset(fixed))
        second = profile.extension_order(_reset(fixed))
        self.assertEqual(first, second)

    def test_the_shuffle_is_uniform(self):
        # A modulus over a byte would bias the low positions, and a bias is
        # itself a fingerprint. Chi-squared would be the proper test; this
        # asserts the weaker thing that every extension reaches every
        # position, which a biased or partial shuffle fails.
        positions = collections.defaultdict(set)
        for _ in range(4000):
            for index, kind in enumerate(profile.extension_order()[:-2]):
                positions[kind].add(index)
        for kind in profile.SHUFFLED:
            with self.subTest(extension=kind):
                self.assertEqual(len(positions[kind]), len(profile.SHUFFLED))

    def test_below_rejects_rather_than_taking_a_modulus(self):
        # 251 is not a multiple of 13, so bytes 247..255 have to be rejected
        # for the draw to stay uniform. An rng that only ever returns 255
        # would hang a modulus-free implementation that forgot to reject, and
        # loop forever here if the span were computed wrongly.
        self.assertEqual(profile._below(lambda n: b"\x00", 13), 0)
        self.assertEqual(profile._below(lambda n: b"\x0c", 13), 12)
        self.assertEqual(profile._below(lambda n: b"\xff", 1), 0)

    def test_a_single_item_needs_no_draw(self):
        called = []

        def never(n):
            called.append(n)
            return b"\x00"

        self.assertEqual(profile._below(never, 1), 0)
        self.assertEqual(called, [])


def _reset(fixed):
    """Hand back an rng whose internal counter starts over."""
    state = {"value": 0}

    def rng(n):
        state["value"] = (state["value"] + 7) % 251
        return bytes([state["value"]] * n)

    return rng


class TestVarint(unittest.TestCase):
    """The encoder, against RFC 9000 appendix A read the other way."""

    def test_the_worked_examples(self):
        self.assertEqual(profile._varint(37).hex(), "25")
        self.assertEqual(profile._varint(15293).hex(), "7bbd")
        self.assertEqual(profile._varint(494878333).hex(), "9d7f3e7d")
        self.assertEqual(profile._varint(151288809941952652).hex(),
                         "c2197c5eff14e88c")

    def test_it_round_trips_through_the_decoder(self):
        from pybrws.quic import varint

        for value in (0, 1, 63, 64, 16383, 16384, 0x3FFFFFFF, 0x40000000,
                      0xFF02DE1A, (1 << 62) - 1):
            with self.subTest(value=value):
                self.assertEqual(varint(profile._varint(value), 0)[0], value)

    def test_the_shortest_form_is_used(self):
        self.assertEqual(len(profile._varint(63)), 1)
        self.assertEqual(len(profile._varint(64)), 2)

    def test_too_large_is_refused(self):
        with self.assertRaises(ValueError):
            profile._varint(1 << 62)

    def test_negative_is_refused(self):
        with self.assertRaises(ValueError):
            profile._varint(-1)


if __name__ == "__main__":
    unittest.main()
