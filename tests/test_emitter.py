"""Tests for pybrws.emitter against the reference capture."""

import os
import unittest
from pathlib import Path

from pybrws.differ import diff
from pybrws.emitter import build_client_hello
from pybrws.hexio import load_hex
from pybrws.parser import _Reader, parse_client_hello
from pybrws.profiles import firefox157

REFERENCE = Path(__file__).resolve().parent.parent / "fixtures" / "reference-firefox-157-windows.hex"
REFERENCE_HOSTNAME = "pybrws.127.0.0.1.nip.io"


class ReplayKeyExchange:
    """Returns a capture's own key_share entries instead of fresh keys."""

    def __init__(self, hello):
        entries = _Reader(_Reader(hello.extension(51).data).vector(2))
        self.shares = []
        while entries.remaining:
            group = entries.uint(2)
            self.shares.append((group, entries.vector(2)))

    def client_shares(self):
        return self.shares


def replay_script(hello) -> list[bytes]:
    """Per-connection material from a capture, in the order the emitter reads it."""
    ech = _Reader(hello.extension(65037).data)
    ech.uint(1)
    ech.uint(2)
    aead_id = ech.uint(2)
    config_id = ech.uint(1)
    enc = ech.vector(2)
    payload = ech.vector(2)

    return [
        hello.random,
        hello.session_id,
        bytes([firefox157.ECH_AEAD_IDS.index(aead_id)]),
        bytes([config_id]),
        enc,
        payload,
    ]


class TestEmitter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = load_hex(REFERENCE)
        cls.golden = parse_client_hello(cls.raw)

    def test_matches_reference_length(self):
        self.assertEqual(len(build_client_hello(REFERENCE_HOSTNAME)), len(self.raw))

    def test_no_structural_differences(self):
        mine = parse_client_hello(build_client_hello(REFERENCE_HOSTNAME))
        self.assertEqual(diff(self.golden, mine), [])

    def test_byte_identical_under_replayed_randomness(self):
        queue = replay_script(self.golden)

        def replay(n: int) -> bytes:
            chunk = queue.pop(0)
            if len(chunk) != n:
                raise AssertionError(f"emitter asked for {n} bytes, script holds {len(chunk)}")
            return chunk

        built = build_client_hello(
            REFERENCE_HOSTNAME, rng=replay, key_exchange=ReplayKeyExchange(self.golden)
        )
        self.assertEqual(built, self.raw)
        self.assertFalse(queue, "emitter consumed less randomness than the capture holds")

    def test_consecutive_builds_vary_only_where_firefox_does(self):
        a = parse_client_hello(build_client_hello(REFERENCE_HOSTNAME))
        b = parse_client_hello(build_client_hello(REFERENCE_HOSTNAME))
        self.assertNotEqual(a.random, b.random)
        self.assertNotEqual(a.session_id, b.session_id)
        self.assertNotEqual(a.extension(51).data, b.extension(51).data)
        self.assertNotEqual(a.extension(65037).data, b.extension(65037).data)
        self.assertEqual(diff(a, b), [])

    def test_aead_id_is_drawn_from_both_options(self):
        seen = set()
        for _ in range(64):
            hello = parse_client_hello(build_client_hello(REFERENCE_HOSTNAME))
            seen.add(int.from_bytes(hello.extension(65037).data[3:5], "big"))
        self.assertEqual(seen, set(firefox157.ECH_AEAD_IDS))

    def test_hostname_changes_only_the_sni_length(self):
        # Measured, not assumed: a capture with a 66-character name against
        # the reference 23 grew by exactly the 43 bytes the name added, and
        # its greased ECH payload stayed at 240. The payload stands in for an
        # inner ClientHello carrying the real name, so it could have tracked
        # it -- and ECH_PAYLOAD_SIZE was measured at one name while every host
        # fetched has a different one. A name-dependent payload would have put
        # our fresh hello wrong on every request.
        short = build_client_hello("a.test")
        long = build_client_hello("a.test" + "x" * 10)
        self.assertEqual(len(long) - len(short), 10)
        for hello in (short, long):
            ech = parse_client_hello(hello).extension(65037).data
            self.assertEqual(len(ech), 42 + firefox157.ECH_PAYLOAD_SIZE)

    def test_output_round_trips_through_the_parser(self):
        raw = build_client_hello(REFERENCE_HOSTNAME)
        self.assertEqual(parse_client_hello(raw).raw, raw)

class TestGreaseDraws(unittest.TestCase):
    """Per-connection GREASE, and which draws are shared.

    Measured from six Chrome 155 captures: five independent values -- the
    first cipher suite, the first and last extension, the first signature
    algorithm, the first supported version -- and one shared between
    supported_groups and key_share, identical in all six, which the protocol
    requires since the key_share entry has to name a group that was offered.
    """

    def context(self, rng=None):
        from pybrws.emitter import Context

        return Context("a.test", rng or os.urandom)

    def test_a_slot_asked_twice_gives_the_same_value(self):
        ctx = self.context()
        self.assertEqual(ctx.grease("groups"), ctx.grease("groups"))

    def test_different_slots_are_independent_draws(self):
        # Not a guarantee they differ -- sixteen values, so a collision is
        # expected once in sixteen. Over enough contexts they must disagree
        # at least once, which a shared value never would.
        disagreed = False
        for _ in range(200):
            ctx = self.context()
            if ctx.grease("cipher") != ctx.grease("versions"):
                disagreed = True
                break
        self.assertTrue(disagreed, "the slots are not drawing independently")

    def test_every_value_is_a_real_grease_value(self):
        from pybrws.model import GREASE_VALUES

        for index in range(100):
            ctx = self.context()
            self.assertIn(ctx.grease("slot%d" % index), GREASE_VALUES)

    def test_two_connections_draw_differently(self):
        values = {self.context().grease("cipher") for _ in range(200)}
        self.assertGreater(len(values), 1, "the value is not per-connection")

    def test_the_draw_covers_the_whole_space(self):
        from pybrws.model import GREASE_VALUES

        seen = {self.context().grease("cipher") for _ in range(4000)}
        self.assertEqual(seen, set(GREASE_VALUES))

    def test_a_fixed_rng_makes_it_replayable(self):
        first = self.context(lambda n: b"\x07" * n).grease("cipher")
        second = self.context(lambda n: b"\x07" * n).grease("cipher")
        self.assertEqual(first, second)

    def test_the_grease_table_is_indexable(self):
        # GREASE_VALUES is a frozenset for membership tests and cannot be
        # indexed, which only shows up when something tries to draw from it.
        from pybrws.model import GREASE_DRAW, GREASE_VALUES

        self.assertEqual(set(GREASE_DRAW), set(GREASE_VALUES))
        self.assertEqual(len(GREASE_DRAW), 16)
        self.assertEqual(GREASE_DRAW[0], 0x0A0A)


class TestTheTwoKindsOfProfile(unittest.TestCase):
    """A profile either stores an extension order or draws one."""

    def test_a_stored_order_is_used_verbatim(self):
        built = parse_client_hello(build_client_hello("a.test"))
        self.assertEqual(built.extension_types(),
                         [kind for kind, _ in firefox157.EXTENSIONS])

    def test_a_drawing_profile_is_asked_per_extension(self):
        from pybrws.emitter import Context, build_extensions

        asked = []

        class Drawer:
            @staticmethod
            def extension_order(ctx):
                return [23, 18, 35]

            @staticmethod
            def payload_for(kind, ctx):
                asked.append(kind)
                return b""

        out = build_extensions(Drawer, Context("a.test", os.urandom))
        self.assertEqual(asked, [23, 18, 35])
        # Three empty extensions: four bytes of header each.
        self.assertEqual(len(out), 12)

    def test_the_stored_path_is_still_taken_when_there_is_no_draw(self):
        # The distinction is the measurement: a stored order is a stronger
        # claim than a drawn one, and collapsing both into a draw would throw
        # it away.
        self.assertFalse(hasattr(firefox157, "extension_order"))
        self.assertTrue(hasattr(firefox157, "EXTENSIONS"))

    def test_a_callable_cipher_list_is_called(self):
        calls = []

        class Greased:
            LEGACY_VERSION = firefox157.LEGACY_VERSION
            RECORD_VERSION = firefox157.RECORD_VERSION
            SESSION_ID_SIZE = firefox157.SESSION_ID_SIZE
            COMPRESSION_METHODS = firefox157.COMPRESSION_METHODS
            EXTENSIONS = []

            @staticmethod
            def CIPHER_SUITES(ctx):
                calls.append(ctx)
                return (0x0A0A, 0x1301)

        built = parse_client_hello(build_client_hello("a.test", profile=Greased))
        self.assertEqual(len(calls), 1)
        self.assertEqual(list(built.cipher_suites), [0x0A0A, 0x1301])


if __name__ == "__main__":
    unittest.main()
