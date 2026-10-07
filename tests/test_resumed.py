"""Tests for the resumed ClientHello against the reference captures.

A Session resumes by default, so this is the hello most requests actually
send. It is a different fingerprint from the fresh one -- JA4 counts
extensions, and resuming swaps one for another -- so it needs its own
capture and its own test. Without one, the measured constants behind it can
be deleted and the suite will not object.

Both fixtures came from one run of tools/catch_resumed.py: the same browser,
the same server, the same ticket, minutes apart.
"""

import unittest
from pathlib import Path

from pybrws.differ import diff
from pybrws.emitter import (EXT_ENCRYPTED_CLIENT_HELLO, EXT_PRE_SHARED_KEY,
                            EXT_SESSION_TICKET, build_client_hello, with_psk)
from pybrws.hexio import load_hex
from pybrws.keyschedule import CIPHER_SUITES
from pybrws.parser import _Reader, parse_client_hello
from pybrws.profiles import firefox157
from pybrws.tickets import Ticket

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
FRESH = FIXTURES / "reference-firefox-157-windows-fresh.hex"
RESUMED = FIXTURES / "reference-firefox-157-windows-resumed.hex"
HOSTNAME = "pybrws.127.0.0.1.nip.io"
ECH_FIXED_FIELDS = 42  # everything in the extension ahead of the payload

# The binder's length is the suite's hash length, so the capture says which
# suite the browser resumed under rather than this file guessing. It was
# SHA384 here, which is worth not hardcoding: the whole pre_shared_key
# extension is sixteen bytes longer than the SHA256 version, and reading that
# difference as something else cost a confused half hour once already.
SUITE_BY_HASH_SIZE = {32: 0x1301, 48: 0x1302}


def psk_identity(hello) -> bytes:
    """The ticket identity a capture's pre_shared_key extension offers."""
    reader = _Reader(_Reader(hello.extension(EXT_PRE_SHARED_KEY).data).vector(2))
    return reader.vector(2)


def psk_binder_size(hello) -> int:
    """The length of the first binder a capture offers."""
    reader = _Reader(hello.extension(EXT_PRE_SHARED_KEY).data)
    reader.vector(2)                      # the identities
    return len(_Reader(reader.vector(2)).vector(1))


def suite_of(hello):
    """The cipher suite a capture resumed under, read from its binder."""
    return CIPHER_SUITES[SUITE_BY_HASH_SIZE[psk_binder_size(hello)]]


def ech_payload(hello) -> bytes:
    reader = _Reader(hello.extension(EXT_ENCRYPTED_CLIENT_HELLO).data)
    reader.uint(1)
    reader.uint(2)
    reader.uint(2)
    reader.uint(1)
    reader.vector(2)
    return reader.vector(2)


class TestCaptures(unittest.TestCase):
    """What the two captures say, asserted so a reread cannot drift."""

    @classmethod
    def setUpClass(cls):
        cls.fresh = parse_client_hello(load_hex(FRESH))
        cls.resumed = parse_client_hello(load_hex(RESUMED))

    def test_the_browser_swaps_session_ticket_for_the_pre_shared_key(self):
        before = self.fresh.extension_types()
        after = self.resumed.extension_types()
        self.assertIn(EXT_SESSION_TICKET, before)
        self.assertNotIn(EXT_SESSION_TICKET, after)
        self.assertIn(EXT_PRE_SHARED_KEY, after)
        self.assertNotIn(EXT_PRE_SHARED_KEY, before)

    def test_the_extension_count_does_not_change(self):
        # This is the whole reason the swap matters: JA4 encodes the count, so
        # appending instead of swapping would read as t13d1518h2 against the
        # browser's t13d1517h2 -- a difference a server finds by counting.
        self.assertEqual(len(self.fresh.extension_types()),
                         len(self.resumed.extension_types()))

    def test_the_pre_shared_key_is_last(self):
        self.assertEqual(self.resumed.extension_types()[-1], EXT_PRE_SHARED_KEY)

    def test_everything_else_keeps_its_order(self):
        before = [t for t in self.fresh.extension_types()
                  if t != EXT_SESSION_TICKET]
        after = [t for t in self.resumed.extension_types()
                 if t != EXT_PRE_SHARED_KEY]
        self.assertEqual(before, after)

    def test_the_greased_ech_payload_grew_by_the_fitted_amount(self):
        # 240 -> 528 bytes, against a pre_shared_key of 287 on the wire. The
        # one byte left over is unexplained; see ech_growth_for_psk. If a
        # later capture contradicts it, this is the test that will say so.
        grew = len(ech_payload(self.resumed)) - len(ech_payload(self.fresh))
        wire = len(self.resumed.extension(EXT_PRE_SHARED_KEY).data) + 4
        self.assertEqual(grew, firefox157.ech_growth_for_psk(wire))
        self.assertEqual(len(ech_payload(self.fresh)),
                         firefox157.ECH_PAYLOAD_SIZE)


class TestAgainstTheCapture(unittest.TestCase):
    """Our resumed hello against the browser's."""

    @classmethod
    def setUpClass(cls):
        cls.golden = parse_client_hello(load_hex(RESUMED))
        cls.raw = load_hex(RESUMED)
        # The identity comes from the capture, so the pre_shared_key extension
        # is the length the browser's was rather than a number copied here.
        cls.suite = suite_of(cls.golden)
        cls.ticket = Ticket(identity=psk_identity(cls.golden), psk=b"p" * 32,
                            age_add=1000, lifetime=7200,
                            suite_id=SUITE_BY_HASH_SIZE[psk_binder_size(cls.golden)])

    def build(self) -> bytes:
        return with_psk(build_client_hello(HOSTNAME), [self.ticket], self.suite)

    def test_the_capture_resumed_under_a_sha384_suite(self):
        # Not a property of the browser, a property of this server. Stated so
        # that a reader does not take the extension's length as inherent.
        self.assertEqual(psk_binder_size(self.golden), 48)

    def test_no_structural_differences(self):
        self.assertEqual(diff(self.golden, parse_client_hello(self.build())), [])

    def test_matches_the_capture_length(self):
        self.assertEqual(len(self.build()), len(self.raw))

    def test_extension_order_matches_the_capture(self):
        mine = parse_client_hello(self.build())
        self.assertEqual(mine.extension_types(), self.golden.extension_types())

    def test_session_ticket_is_gone(self):
        mine = parse_client_hello(self.build())
        self.assertNotIn(EXT_SESSION_TICKET, mine.extension_types())

    def test_the_ech_payload_is_the_length_the_capture_carries(self):
        mine = parse_client_hello(self.build())
        self.assertEqual(len(ech_payload(mine)), len(ech_payload(self.golden)))

    def test_the_ech_payload_is_not_a_constant(self):
        # It is greased, so two connections must not carry the same bytes.
        first = ech_payload(parse_client_hello(self.build()))
        second = ech_payload(parse_client_hello(self.build()))
        self.assertNotEqual(first, second)
        self.assertEqual(len(first), len(second))

    def test_the_grown_payload_declares_its_own_length(self):
        data = parse_client_hello(self.build()).extension(
            EXT_ENCRYPTED_CLIENT_HELLO).data
        self.assertEqual(len(data), ECH_FIXED_FIELDS + len(ech_payload(
            parse_client_hello(self.build()))))


if __name__ == "__main__":
    unittest.main()
