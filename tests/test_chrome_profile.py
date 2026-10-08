"""Tests for profiles.chrome155 against the captures it came from.

Chrome is the second profile and the first test of whether `profiles/` is an
abstraction. These tests therefore do two jobs: hold the measurements, and
hold the *differences* from Firefox, since a profile system that quietly
makes the second browser look like the first would pass every test about
Chrome and still be wrong.

Every constant is compared against a capture rather than against what was
typed. Writing this file found two defects in the profile: a missing
extension, and two greased extension types that could collide.
"""

import glob
import os
import unittest
from pathlib import Path

from pybrws.emitter import Context, build_client_hello
from pybrws.hexio import load_hex
from pybrws.model import GREASE_DRAW, GREASE_VALUES
from pybrws.parser import _Reader, parse_client_hello
from pybrws.profiles import chrome155 as profile
from pybrws.profiles import firefox157

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
HOSTNAME = "pybrws.127.0.0.1.nip.io"
VOLATILE = {0, 51, 65037}          # host, keys, greased payload


def captures() -> list:
    paths = sorted(glob.glob(str(FIXTURES / "chrome-*.hex")))
    return [parse_client_hello(load_hex(p)) for p in paths]


def collapse(types) -> frozenset:
    return frozenset("G" if t in GREASE_VALUES else t for t in types)


def build(n: int = 1) -> list:
    return [parse_client_hello(build_client_hello(HOSTNAME, profile=profile))
            for _ in range(n)]


class TestTheCaptures(unittest.TestCase):
    """What the six captures say, asserted so a reread cannot drift."""

    @classmethod
    def setUpClass(cls):
        cls.hellos = captures()

    def test_there_are_six(self):
        self.assertEqual(len(self.hellos), 6)

    def test_one_set_and_six_orders(self):
        sets = {collapse(h.extension_types()) for h in self.hellos}
        orders = {tuple(collapse([t]) and ("G" if t in GREASE_VALUES else t)
                        for t in h.extension_types()) for h in self.hellos}
        self.assertEqual(len(sets), 1, "six captures of one browser")
        self.assertEqual(len(orders), 6, "a different order every time")

    def test_a_greased_extension_at_each_end(self):
        for hello in self.hellos:
            types = hello.extension_types()
            self.assertIn(types[0], GREASE_VALUES)
            self.assertIn(types[-1], GREASE_VALUES)

    def test_the_two_greased_types_never_collide(self):
        # RFC 8446 section 4.2 forbids a duplicate extension type, so they
        # cannot. The profile had to be fixed to respect that.
        for hello in self.hellos:
            types = hello.extension_types()
            self.assertNotEqual(types[0], types[-1])

    def test_six_greased_lists(self):
        for hello in self.hellos:
            with self.subTest(size=len(hello.raw)):
                self.assertIn(hello.cipher_suites[0], GREASE_VALUES)
                for kind, prefix in ((10, 2), (13, 2), (43, 1)):
                    body = hello.extension(kind).data[prefix:]
                    first = int.from_bytes(body[:2], "big")
                    self.assertIn(first, GREASE_VALUES)

    def test_supported_groups_and_key_share_share_one_value(self):
        # The protocol requires it: a key_share entry naming a group that was
        # never offered is an error.
        for hello in self.hellos:
            groups = hello.extension(10).data[2:]
            group_grease = int.from_bytes(groups[:2], "big")
            entries = _Reader(_Reader(hello.extension(51).data).vector(2))
            share_grease = entries.uint(2)
            self.assertEqual(group_grease, share_grease)

    def test_the_rest_of_the_hello_is_a_constant_size(self):
        # Every capture measures 1751 bytes plus its ECH extension, so the
        # greased ECH is the only thing moving the total.
        for hello in self.hellos:
            rest = len(hello.raw) - len(hello.extension(65037).data)
            self.assertEqual(rest, 1751)

    def test_the_ech_payload_sizes_are_the_ones_recorded(self):
        seen = set()
        for hello in self.hellos:
            reader = _Reader(hello.extension(65037).data)
            reader.uint(1), reader.uint(2), reader.uint(2), reader.uint(1)
            reader.vector(2)
            seen.add(len(reader.vector(2)))
        self.assertTrue(seen <= set(profile.ECH_PAYLOAD_SIZES))
        self.assertEqual(seen, {144, 208, 240})

    def test_the_aead_does_not_vary_the_way_firefox_does(self):
        aeads = set()
        for hello in self.hellos:
            reader = _Reader(hello.extension(65037).data)
            reader.uint(1), reader.uint(2)
            aeads.add(reader.uint(2))
        self.assertEqual(aeads, {profile.ECH_AEAD_ID})
        self.assertEqual(len(firefox157.ECH_AEAD_IDS), 2,
                         "Firefox draws between two")


class TestTheProfileMatches(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.golden = captures()[0]
        cls.ours = build(1)[0]

    def test_every_static_payload_is_the_captured_one(self):
        for kind, payload in profile.STATIC_PAYLOADS.items():
            with self.subTest(extension=kind):
                self.assertEqual(payload, self.golden.extension(kind).data)

    def test_the_extension_set_matches(self):
        self.assertEqual(collapse(self.ours.extension_types()),
                         collapse(self.golden.extension_types()))

    def test_there_are_twenty_extensions(self):
        self.assertEqual(len(self.ours.extensions), 20)
        self.assertEqual(len(self.golden.extensions), 20)

    def test_the_cipher_suites_match_with_grease_collapsed(self):
        def ours(hello):
            return ["G" if c in GREASE_VALUES else c for c in hello.cipher_suites]

        self.assertEqual(ours(self.ours), ours(self.golden))

    def test_the_session_id_is_thirty_two_bytes(self):
        self.assertEqual(len(self.ours.session_id), 32)
        self.assertEqual(len(self.golden.session_id), 32)

    def test_the_key_share_groups_and_sizes_match(self):
        def shares(hello):
            entries = _Reader(_Reader(hello.extension(51).data).vector(2))
            out = []
            while entries.remaining:
                group = entries.uint(2)
                out.append(("G" if group in GREASE_VALUES else group,
                            len(entries.vector(2))))
            return out

        self.assertEqual(shares(self.ours), shares(self.golden))

    def test_the_greased_lists_have_the_same_real_members(self):
        for kind, prefix in ((10, 2), (13, 2), (43, 1)):
            with self.subTest(extension=kind):
                def real(hello):
                    body = hello.extension(kind).data[prefix:]
                    items = [int.from_bytes(body[i:i + 2], "big")
                             for i in range(0, len(body), 2)]
                    return [x for x in items if x not in GREASE_VALUES]

                self.assertEqual(real(self.ours), real(self.golden))

    def test_the_volatile_extensions_match_in_length(self):
        for kind in VOLATILE - {65037}:
            with self.subTest(extension=kind):
                self.assertEqual(len(self.ours.extension(kind).data),
                                 len(self.golden.extension(kind).data))


class TestTheDraw(unittest.TestCase):
    def test_every_length_is_one_the_browser_produces(self):
        # The bug this catches: two greased extension types colliding made
        # both take the first one's payload, giving a hello one byte shorter
        # than any capture. A length no browser produces is the cheapest
        # possible tell.
        allowed = {len(h.raw) for h in captures()}
        produced = {len(h.raw) for h in build(300)}
        self.assertTrue(produced <= allowed,
                        "produced %s, browser produces %s"
                        % (sorted(produced), sorted(allowed)))

    def test_no_extension_type_is_ever_duplicated(self):
        for hello in build(300):
            types = hello.extension_types()
            self.assertEqual(len(set(types)), len(types))

    def test_the_order_is_different_every_time(self):
        orders = {tuple(h.extension_types()) for h in build(100)}
        self.assertEqual(len(orders), 100)

    def test_the_set_never_changes(self):
        sets = {collapse(h.extension_types()) for h in build(100)}
        self.assertEqual(len(sets), 1)

    def test_the_pinned_pair_is_deterministic_for_a_context(self):
        ctx = Context(HOSTNAME, os.urandom)
        self.assertEqual(profile.pinned_pair(ctx), profile.pinned_pair(ctx))

    def test_the_pinned_pair_always_differs(self):
        for _ in range(500):
            first, last = profile.pinned_pair(Context(HOSTNAME, os.urandom))
            self.assertNotEqual(first, last)
            self.assertIn(first, GREASE_DRAW)
            self.assertIn(last, GREASE_DRAW)

    def test_a_colliding_rng_still_yields_a_distinct_pair(self):
        # An rng that always returns the same byte would draw the same value
        # for both, which is the case the redraw exists for.
        first, last = profile.pinned_pair(Context(HOSTNAME, lambda n: b"\x00" * n))
        self.assertNotEqual(first, last)

    def test_every_position_is_reached_by_every_extension(self):
        # A partial or biased shuffle fails this; the draw uses rejection
        # rather than a modulus for that reason.
        positions = {kind: set() for kind in profile.SHUFFLED}
        for hello in build(1200):
            for index, kind in enumerate(hello.extension_types()[1:-1]):
                positions[kind].add(index)
        for kind, seen in positions.items():
            with self.subTest(extension=kind):
                self.assertEqual(len(seen), len(profile.SHUFFLED))


class TestItIsNotFirefox(unittest.TestCase):
    """The differences, asserted so the abstraction cannot flatten them."""

    def test_firefox_stores_an_order_and_chrome_draws_one(self):
        self.assertTrue(hasattr(firefox157, "EXTENSIONS"))
        self.assertFalse(hasattr(firefox157, "extension_order"))
        self.assertTrue(hasattr(profile, "extension_order"))
        self.assertTrue(hasattr(profile, "payload_for"))

    def test_chrome_greases_and_firefox_does_not(self):
        chrome = build(1)[0]
        fox = parse_client_hello(build_client_hello(HOSTNAME))
        self.assertTrue(any(c in GREASE_VALUES for c in chrome.cipher_suites))
        self.assertFalse(any(c in GREASE_VALUES for c in fox.cipher_suites))

    def test_the_cipher_list_is_a_callable_for_chrome_only(self):
        self.assertTrue(callable(profile.CIPHER_SUITES))
        self.assertFalse(callable(firefox157.CIPHER_SUITES))

    def test_not_one_http2_value_matches(self):
        pairs = (
            ("H2_SETTINGS", profile.H2_SETTINGS, firefox157.H2_SETTINGS),
            ("H2_CONNECTION_WINDOW_UPDATE", profile.H2_CONNECTION_WINDOW_UPDATE,
             firefox157.H2_CONNECTION_WINDOW_UPDATE),
            ("H2_FIRST_STREAM_ID", profile.H2_FIRST_STREAM_ID,
             firefox157.H2_FIRST_STREAM_ID),
            ("H2_HEADERS_PRIORITY", profile.H2_HEADERS_PRIORITY,
             firefox157.H2_HEADERS_PRIORITY),
            ("H2_PSEUDO_ORDER", profile.H2_PSEUDO_ORDER,
             firefox157.H2_PSEUDO_ORDER),
        )
        for name, chrome, fox in pairs:
            with self.subTest(field=name):
                self.assertNotEqual(tuple(chrome) if isinstance(chrome, (list, tuple))
                                    else chrome,
                                    tuple(fox) if isinstance(fox, (list, tuple))
                                    else fox)

    def test_chrome_sends_a_setting_firefox_does_not_and_the_reverse(self):
        chrome = {key for key, _ in profile.H2_SETTINGS}
        fox = {key for key, _ in firefox157.H2_SETTINGS}
        self.assertIn(6, chrome)      # max header list size
        self.assertNotIn(6, fox)
        self.assertIn(5, fox)         # max frame size
        self.assertNotIn(5, chrome)

    def test_the_pseudo_orders_are_both_measured_and_differ(self):
        self.assertEqual(profile.H2_PSEUDO_ORDER,
                         (":method", ":authority", ":scheme", ":path"))
        self.assertEqual(firefox157.H2_PSEUDO_ORDER,
                         (":method", ":path", ":authority", ":scheme"))


class TestTheHeaderCaptures(unittest.TestCase):
    """The HTTP header constants, against the files they came from."""

    @staticmethod
    def parse(name: str, skip_first: bool) -> list[tuple[str, str]]:
        raw = (FIXTURES / name).read_bytes().decode("latin-1")
        lines = raw.split("\r\n\r\n")[0].split("\r\n")
        if skip_first:
            lines = lines[1:]
        out = []
        for line in lines:
            if not line:
                continue
            key, _, value = line.partition(": ")
            out.append((key, value))
        return out

    def test_the_http2_order_matches(self):
        captured = self.parse("reference-chrome-155-h2.txt", False)
        pseudo = [n for n, _ in captured if n.startswith(":")]
        real = [n for n, _ in captured if not n.startswith(":")]
        self.assertEqual(tuple(pseudo), profile.H2_PSEUDO_ORDER)
        self.assertEqual([n for n, _ in profile.H2_NAVIGATION_HEADERS], real)

    def test_every_http2_value_matches(self):
        captured = dict(self.parse("reference-chrome-155-h2.txt", False))
        for name, value in profile.H2_NAVIGATION_HEADERS:
            with self.subTest(header=name):
                self.assertEqual(value, captured[name])

    def test_the_http1_order_and_casing_match(self):
        # The casing is measured: the client hints are lower case and
        # everything else capitalised. A client that normalises either way
        # gets it wrong.
        captured = self.parse("reference-chrome-155-h1.txt", True)
        self.assertEqual([n for n, _ in profile.H1_HEADERS],
                         [n for n, _ in captured])

    def test_the_http1_values_match_where_they_are_not_per_request(self):
        captured = dict(self.parse("reference-chrome-155-h1.txt", True))
        for name, value in profile.H1_HEADERS:
            if value.startswith("{"):     # filled per request
                continue
            with self.subTest(header=name):
                self.assertEqual(value, captured[name])

    def test_the_post_order_matches_including_the_interleaving(self):
        # The client hints are not grouped: platform, User-Agent, sec-ch-ua,
        # Content-Type, mobile. Only a capture gives that.
        captured = self.parse("reference-chrome-155-post.txt", True)
        self.assertEqual([n for n, _ in profile.H1_POST_XHR_HEADERS],
                         [n for n, _ in captured])

    def test_the_frame_fingerprint_matches_its_sidecar(self):
        import json

        recorded = json.loads(
            (FIXTURES / "reference-chrome-155-h2.frames.json").read_text(
                encoding="utf-8"))
        self.assertEqual([list(pair) for pair in profile.H2_SETTINGS],
                         recorded["settings"])
        self.assertEqual(profile.H2_CONNECTION_WINDOW_UPDATE,
                         recorded["connection_window_update"])
        self.assertEqual(profile.H2_FIRST_STREAM_ID,
                         recorded["first_stream_id"])
        self.assertEqual(profile.H2_HEADERS_PRIORITY["weight"],
                         recorded["headers_priority"]["weight"])
        self.assertEqual(profile.H2_HEADERS_PRIORITY["exclusive"],
                         recorded["headers_priority"]["exclusive"])

    def test_the_accept_language_is_flagged_as_machine_specific(self):
        # It carries the locale of the machine it was captured on, which is a
        # fingerprint of a person rather than of a browser. Kept so the
        # comparison above is like for like, and named so nobody ships it by
        # accident.
        self.assertEqual(profile.ACCEPT_LANGUAGE,
                         "en-MX,en-GB;q=0.9,en-US;q=0.8,en;q=0.7")
        self.assertNotEqual(profile.ACCEPT_LANGUAGE,
                            dict(firefox157.H2_NAVIGATION_HEADERS)
                            .get("accept-language"))

class TestWhatIsNotMeasured(unittest.TestCase):
    """A profile holds what was captured, and says so about the rest."""

    def test_the_unmeasured_sets_are_absent_rather_than_invented(self):
        for name in profile.UNMEASURED:
            with self.subTest(name=name):
                self.assertFalse(hasattr(profile, name))
                self.assertTrue(hasattr(firefox157, name),
                                "Firefox has it because it was captured")

    def test_asking_for_one_names_it_and_says_how_to_take_it(self):
        from pybrws.client import Unmeasured, header_set

        with self.assertRaises(Unmeasured) as caught:
            header_set(profile, "POST", "form", True)
        message = str(caught.exception)
        self.assertIn("H2_POST_FORM_HEADERS", message)
        self.assertIn("catch_request.py", message)

    def test_the_measured_kinds_still_resolve(self):
        from pybrws.client import header_set

        for method, kind, http2 in (("GET", "xhr", True), ("GET", "xhr", False),
                                    ("POST", "xhr", True), ("POST", "xhr", False)):
            with self.subTest(method=method, http2=http2):
                self.assertTrue(header_set(profile, method, kind, http2))

    def test_the_derived_http2_post_drops_host_and_connection(self):
        names = [n for n, _ in profile.H2_POST_XHR_HEADERS]
        self.assertNotIn("host", names)
        self.assertNotIn("connection", names)
        self.assertEqual(names, [n.lower() for n, _ in
                                 profile.H1_POST_XHR_HEADERS
                                 if n.lower() not in ("host", "connection")])

    def test_the_derived_set_appends_no_te(self):
        # Firefox's derivation appends `te: trailers`; Chrome's measured
        # HTTP/2 navigation carries none, so the derivation must not add one.
        self.assertNotIn("te", [n for n, _ in profile.H2_POST_XHR_HEADERS])
        self.assertIn("te", [n for n, _ in firefox157.H2_POST_XHR_HEADERS])

    def test_the_derived_set_does_not_invent_a_priority(self):
        # Chrome's HTTP/2 navigation adds `priority` that its HTTP/1.1 one
        # has no equivalent of, so an HTTP/2 POST probably carries one too --
        # with a value nothing here can supply. Omitted rather than guessed.
        self.assertNotIn("priority", [n for n, _ in profile.H2_POST_XHR_HEADERS])

    def test_the_per_request_values_are_placeholders(self):
        # Empty strings would be sent as empty headers, which is how a POST
        # with this profile first came back 400.
        filled = {"{authority}", "{content_length}", "{content_type}",
                  "{origin}", "{referer}"}
        for headers in (profile.H1_HEADERS, profile.H1_POST_XHR_HEADERS):
            for name, value in headers:
                with self.subTest(header=name):
                    self.assertNotEqual(value, "",
                                        "%s would go out empty" % name)
        values = {v for _, v in profile.H1_POST_XHR_HEADERS}
        self.assertTrue(filled <= values)


if __name__ == "__main__":
    unittest.main()
