"""Tests for session tickets and the pre_shared_key offer."""

import time
import unittest

from pybrws.emitter import build_client_hello, with_psk
from pybrws.keyschedule import (
    CIPHER_SUITES,
    KeySchedule,
    binder_key,
    psk_binder,
    resumption_psk,
)
from pybrws.parser import parse_client_hello
from pybrws.tickets import AGE_MODULUS, Ticket, TicketStore, parse_new_session_ticket

SUITE = CIPHER_SUITES[0x1301]
EXT_PRE_SHARED_KEY = 41


def vector(data: bytes, length_bytes: int) -> bytes:
    return len(data).to_bytes(length_bytes, "big") + data


def ticket_body(lifetime=7200, age_add=0x11223344, nonce=b"\x00", identity=b"t" * 16):
    return (lifetime.to_bytes(4, "big") + age_add.to_bytes(4, "big")
            + vector(nonce, 1) + vector(identity, 2) + vector(b"", 2))


def a_ticket(**kwargs):
    defaults = dict(identity=b"t" * 16, psk=b"p" * 32, age_add=1000,
                    lifetime=7200, suite_id=0x1301)
    defaults.update(kwargs)
    return Ticket(**defaults)


class TestParsing(unittest.TestCase):
    def test_fields(self):
        ticket = parse_new_session_ticket(ticket_body(), SUITE, b"r" * 32)
        self.assertEqual(ticket.identity, b"t" * 16)
        self.assertEqual(ticket.lifetime, 7200)
        self.assertEqual(ticket.age_add, 0x11223344)
        self.assertEqual(len(ticket.psk), SUITE.hash_size)

    def test_the_nonce_distinguishes_two_tickets_from_one_connection(self):
        first = parse_new_session_ticket(ticket_body(nonce=b"\x00"), SUITE, b"r" * 32)
        second = parse_new_session_ticket(ticket_body(nonce=b"\x01"), SUITE, b"r" * 32)
        self.assertNotEqual(first.psk, second.psk)

    def test_the_psk_matches_the_derivation(self):
        ticket = parse_new_session_ticket(ticket_body(nonce=b"\x07"), SUITE, b"r" * 32)
        self.assertEqual(ticket.psk, resumption_psk(SUITE, b"r" * 32, b"\x07"))


class TestAge(unittest.TestCase):
    def test_the_age_is_masked_by_the_server_value(self):
        ticket = a_ticket(age_add=5000)
        now = ticket.received + 2.0
        self.assertEqual(ticket.obfuscated_age(now), 2000 + 5000)

    def test_it_wraps_rather_than_overflowing(self):
        ticket = a_ticket(age_add=AGE_MODULUS - 1)
        self.assertLess(ticket.obfuscated_age(ticket.received + 1.0), AGE_MODULUS)

    def test_expiry_follows_the_lifetime(self):
        ticket = a_ticket(lifetime=10)
        self.assertFalse(ticket.expired(ticket.received + 5))
        self.assertTrue(ticket.expired(ticket.received + 11))

    def test_a_week_is_the_cap_whatever_the_server_claims(self):
        # RFC 8446 section 4.6.1.
        ticket = a_ticket(lifetime=10 ** 9)
        self.assertTrue(ticket.expired(ticket.received + 8 * 24 * 3600))


class TestStore(unittest.TestCase):
    def setUp(self):
        self.store = TicketStore()

    def test_round_trip(self):
        self.store.add("a.test", a_ticket())
        self.assertEqual(len(self.store), 1)
        self.assertIsNotNone(self.store.take("a.test"))

    def test_a_ticket_is_used_once(self):
        # Reusing one lets an observer link the two connections, which is
        # the opposite of what resumption is for here.
        self.store.add("a.test", a_ticket())
        self.store.take("a.test")
        self.assertIsNone(self.store.take("a.test"))

    def test_tickets_are_per_host(self):
        self.store.add("a.test", a_ticket())
        self.assertIsNone(self.store.take("b.test"))

    def test_expired_tickets_are_skipped(self):
        self.store.add("a.test", a_ticket(lifetime=0))
        self.store.add("a.test", a_ticket(identity=b"fresh" * 4))
        taken = self.store.take("a.test")
        self.assertEqual(taken.identity, b"fresh" * 4)

    def test_a_mismatched_suite_is_skipped(self):
        # The binder is keyed by the suite's hash, so one from another suite
        # cannot be offered.
        self.store.add("a.test", a_ticket(suite_id=0x1302))
        self.assertIsNone(self.store.take("a.test", suite_id=0x1301))

    def test_nothing_held(self):
        self.assertIsNone(self.store.take("a.test"))


class TestKeySchedule(unittest.TestCase):
    def test_a_psk_changes_the_early_secret(self):
        self.assertNotEqual(KeySchedule(SUITE).early_secret,
                            KeySchedule(SUITE, psk=b"p" * 32).early_secret)

    def test_the_binder_key_depends_on_the_psk(self):
        self.assertNotEqual(binder_key(SUITE, b"a" * 32), binder_key(SUITE, b"b" * 32))

    def test_resumption_needs_the_application_stage_first(self):
        with self.assertRaises(ValueError):
            KeySchedule(SUITE).resumption(b"transcript")


class TestPreSharedKeyOffer(unittest.TestCase):
    def setUp(self):
        self.ticket = a_ticket()
        self.plain = build_client_hello("a.test")
        self.offered = with_psk(self.plain, [self.ticket], SUITE)
        self.parsed = parse_client_hello(self.offered)

    def test_the_extension_is_last(self):
        # RFC 8446 requires it, because the binder covers everything before.
        self.assertEqual(self.parsed.extension_types()[-1], EXT_PRE_SHARED_KEY)

    def test_nothing_else_changed(self):
        before = parse_client_hello(self.plain)
        self.assertEqual(before.random, self.parsed.random)
        self.assertEqual(before.extension_types(),
                         self.parsed.extension_types()[:-1])

    def test_the_binder_signs_the_hello_that_contains_it(self):
        tail = 2 + 1 + SUITE.hash_size
        expected = psk_binder(SUITE, self.ticket.psk, self.offered[5:-tail])
        self.assertEqual(self.offered[-SUITE.hash_size:], expected)

    def test_the_identity_is_the_ticket(self):
        data = self.parsed.extension(EXT_PRE_SHARED_KEY).data
        identities_length = int.from_bytes(data[:2], "big")
        identity_length = int.from_bytes(data[2:4], "big")
        self.assertEqual(data[4:4 + identity_length], self.ticket.identity)
        self.assertEqual(identities_length, 2 + identity_length + 4)

    def test_offering_twice_is_refused(self):
        with self.assertRaises(ValueError):
            with_psk(self.offered, [self.ticket], SUITE)

    def test_a_different_ticket_gives_a_different_binder(self):
        other = with_psk(self.plain, [a_ticket(psk=b"q" * 32)], SUITE)
        self.assertNotEqual(other[-SUITE.hash_size:],
                            self.offered[-SUITE.hash_size:])


if __name__ == "__main__":
    unittest.main()
