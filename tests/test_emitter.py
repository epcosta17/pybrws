"""Tests for pybrws.emitter against the reference capture."""

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


if __name__ == "__main__":
    unittest.main()
