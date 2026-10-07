"""Tests for the HelloRetryRequest path."""

import unittest

from pybrws import handshake
from pybrws.emitter import build_client_hello, retry_hello, serialise
from pybrws.keyexchange import KeyExchange, supported
from pybrws.keyschedule import CIPHER_SUITES, transcript_hash
from pybrws.parser import parse_client_hello

SUITE = CIPHER_SUITES[0x1301]
EXT_KEY_SHARE = 51
EXT_COOKIE = 44


class FakeRetry:
    """Stands in for a parsed HelloRetryRequest."""

    def __init__(self, group, cookie=None, cipher_suite=0x1301):
        self.selected_group = group
        self.cookie = cookie
        self.cipher_suite = cipher_suite


class TestSerialise(unittest.TestCase):
    def test_round_trips(self):
        raw = build_client_hello("a.test")
        self.assertEqual(serialise(parse_client_hello(raw)), raw)

    def test_keeps_the_record_version(self):
        raw = build_client_hello("a.test")
        self.assertEqual(serialise(parse_client_hello(raw))[1:3], raw[1:3])


class TestRetryHello(unittest.TestCase):
    def setUp(self):
        self.first = build_client_hello("a.test")
        self.second = retry_hello(self.first, 0x001D, b"k" * 32)
        self.before = parse_client_hello(self.first)
        self.after = parse_client_hello(self.second)

    def test_identical_except_the_key_share(self):
        # RFC 8446 requires "identical except", which is why this is rebuilt
        # from the original bytes rather than re-emitted from the profile.
        self.assertEqual(self.before.random, self.after.random)
        self.assertEqual(self.before.session_id, self.after.session_id)
        self.assertEqual(self.before.cipher_suites, self.after.cipher_suites)
        self.assertEqual(self.before.extension_types(), self.after.extension_types())
        for old, new in zip(self.before.extensions, self.after.extensions):
            if old.type != EXT_KEY_SHARE:
                self.assertEqual(old.data, new.data, old.name)

    def test_the_key_share_carries_one_entry(self):
        data = self.after.extension(EXT_KEY_SHARE).data
        self.assertEqual(int.from_bytes(data[:2], "big"), len(data) - 2)
        self.assertEqual(int.from_bytes(data[2:4], "big"), 0x001D)
        self.assertEqual(data[6:], b"k" * 32)

    def test_a_cookie_is_echoed(self):
        with_cookie = parse_client_hello(
            retry_hello(self.first, 0x001D, b"k" * 32, b"\x00\x04abcd")
        )
        self.assertEqual(with_cookie.extension(EXT_COOKIE).data, b"\x00\x04abcd")

    def test_no_cookie_means_no_extension(self):
        self.assertIsNone(self.after.extension(EXT_COOKIE))


class TestRetryHandling(unittest.TestCase):
    def setUp(self):
        self.first = build_client_hello("a.test")
        self.exchange = KeyExchange([0x001D, 0x0017])
        self.raw_message = b"\x02\x00\x00\x04test"

    def retry(self, group, cookie=None):
        return handshake._retry(self.first, FakeRetry(group, cookie),
                                self.raw_message, self.exchange, SUITE)

    def test_produces_a_second_hello_for_the_named_group(self):
        second, exchange, _ = self.retry(0x11EC)
        self.assertEqual(exchange.groups, [0x11EC])
        data = parse_client_hello(second).extension(EXT_KEY_SHARE).data
        self.assertEqual(int.from_bytes(data[2:4], "big"), 0x11EC)

    def test_the_transcript_replaces_the_first_hello_with_its_hash(self):
        # RFC 8446 section 4.4.1. Appending the first hello as usual makes
        # every later verification fail, silently and much later.
        _, _, transcript = self.retry(0x11EC)
        digest = transcript_hash(SUITE, self.first[5:])
        self.assertEqual(transcript[0], handshake.MESSAGE_HASH)
        self.assertEqual(int.from_bytes(transcript[1:4], "big"), len(digest))
        self.assertEqual(bytes(transcript[4:4 + len(digest)]), digest)

    def test_the_retry_message_follows_the_synthetic_one(self):
        _, _, transcript = self.retry(0x11EC)
        self.assertTrue(bytes(transcript).endswith(self.raw_message))

    def test_the_transcript_is_shorter_than_the_hello_it_replaces(self):
        _, _, transcript = self.retry(0x11EC)
        self.assertLess(len(transcript), len(self.first))

    def test_a_group_already_offered_is_refused(self):
        # Answering would send the same thing again and invite a loop.
        with self.assertRaises(handshake.HandshakeError) as caught:
            self.retry(0x001D)
        self.assertIn("already offered", str(caught.exception))

    def test_a_group_this_client_cannot_produce_is_refused(self):
        with self.assertRaises(handshake.HandshakeError):
            self.retry(0x0100)

    def test_no_group_at_all_is_refused(self):
        with self.assertRaises(handshake.HandshakeError):
            self.retry(None)

    def test_a_cookie_reaches_the_second_hello(self):
        second, _, _ = self.retry(0x11EC, b"\x00\x03xyz")
        self.assertEqual(parse_client_hello(second).extension(EXT_COOKIE).data,
                         b"\x00\x03xyz")


class TestGroupSupport(unittest.TestCase):
    def test_the_curves_a_retry_may_name(self):
        for group in (0x0017, 0x0018, 0x0019, 0x001D, 0x11EC):
            self.assertTrue(supported(group), hex(group))

    def test_finite_field_groups_are_not_supported(self):
        self.assertFalse(supported(0x0100))


if __name__ == "__main__":
    unittest.main()
