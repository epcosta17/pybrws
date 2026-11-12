"""`pybrws verify --local --capture FILE`: any profile against your own hello."""

from __future__ import annotations

import contextlib
import functools
import io
import random
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pybrws import cli, emitter, handshake, profiles
from pybrws.hexio import load_hex
from pybrws.model import Extension
from pybrws.parser import parse_client_hello
# isolate and probe_fingerprint are imported here, before any test patches
# sys.modules, so that restoring sys.modules cannot unload them.
from pybrws.tools import ab_test, isolate, probe_fingerprint, verify  # noqa: F401
from tests.profile_files import write_profile

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
FIREFOX = str(FIXTURES / "reference-firefox-157-windows-fresh.hex")
CHROME = str(FIXTURES / "chrome-1.hex")
CHROMES = [str(FIXTURES / ("chrome-%d.hex" % n)) for n in range(1, 7)]
HOSTNAME = "pybrws.127.0.0.1.nip.io"

# A copy of firefox157 whose greased ECH payload is 208 bytes, not 240.
WRONG_ECH = '''\
from pybrws.profiles import firefox157
from pybrws.profiles.firefox157 import *
from pybrws.wire import u8, u16, vector

NAME = "wrong_ech"


def greased_ech(ctx):
    return (u8(0) + u16(1) + u16(1) + u8(ctx.random(1)[0])
            + vector(ctx.random(32), 2) + vector(ctx.random(208), 2))


EXTENSIONS = [(kind, greased_ech if kind == 65037 else payload)
              for kind, payload in firefox157.EXTENSIONS]
'''
# Copies that change one constant and nothing else.
TWO_SHARES = ("from pybrws.profiles.firefox157 import *\n"
              "NAME = 'two_shares'\n"
              "KEY_SHARE_GROUPS = [(0x11EC, 1216), (0x001D, 32)]\n")
NO_SESSION_ID = ("from pybrws.profiles.firefox157 import *\n"
                 "NAME = 'no_session_id'\n"
                 "SESSION_ID_SIZE = 0\n")
# The one line a copy with X25519_FIRST ends in: the error, then the file
# and line where it was raised, in firefox157's key_share.
FAILED_IN_FIREFOX157 = (r"^cannot build a hello from profile 'x25519_first': "
                        r"ValueError: key_share for 0x11ec: expected 1216 "
                        r"bytes from 0x001d, got 32 \(firefox157\.py:\d+\)$")
# firefox157's key_share lays the shares out against firefox157's own list,
# so this order cannot be built with it.
X25519_FIRST = ("from pybrws.profiles.firefox157 import *\n"
                "NAME = 'x25519_first'\n"
                "KEY_SHARE_GROUPS = [(0x001D, 32), (0x11EC, 1216)]\n")

# Copies of chrome155 that keep every size and change one list, which
# GREASE values drawn per connection must not hide.
CHROME_HEAD = ("from pybrws.profiles import chrome155\n"
               "from pybrws.profiles.chrome155 import *\n"
               "from pybrws.wire import u16, vector\n\n")
OTHER_GROUPS = CHROME_HEAD + '''\
NAME = "other_groups"


def payload_for(kind, ctx):
    if kind == 10:
        groups = (ctx.grease("groups"), 0x11EC, 0x001D, 0x0017, 0x0019)
        return vector(b"".join(u16(group) for group in groups), 2)
    return chrome155.payload_for(kind, ctx)
'''
OTHER_GROUPS_DRAWN = OTHER_GROUPS + (
    'DRAWN = dict(chrome155.DRAWN, supported_groups="greased value at the head")\n')
OTHER_SET = CHROME_HEAD + '''\
NAME = "other_set"


def extension_order(ctx):
    return [21 if kind == 4832 else kind for kind in chrome155.extension_order(ctx)]


def payload_for(kind, ctx):
    if kind == 21:
        return bytes(2)
    return chrome155.payload_for(kind, ctx)
'''
OTHER_CIPHER_ORDER = CHROME_HEAD + '''\
NAME = "other_cipher_order"


def CIPHER_SUITES(ctx):
    suites = list(chrome155.CIPHER_SUITES(ctx))
    suites[1], suites[2] = suites[2], suites[1]
    return tuple(suites)
'''
EMPTY_GREASE_EXTENSIONS = CHROME_HEAD + '''\
from pybrws.model import GREASE_VALUES

NAME = "empty_grease_extensions"


def payload_for(kind, ctx):
    if kind in GREASE_VALUES:
        return b""
    return chrome155.payload_for(kind, ctx)
'''
# Copies of firefox157 that change a fixed field and nothing else.
OTHER_RECORD_VERSION = ("from pybrws.profiles.firefox157 import *\n"
                        "NAME = 'other_record_version'\n"
                        "RECORD_VERSION = 0x0303\n")
OTHER_COMPRESSION = ("from pybrws.profiles.firefox157 import *\n"
                     "NAME = 'other_compression'\n"
                     "COMPRESSION_METHODS = [1]\n")

# The review's two runs: a changed field, and a DRAWN that names it.
ONE_MORE_GROUP = CHROME_HEAD + '''\
NAME = "one_more_group"


def payload_for(kind, ctx):
    if kind == 10:
        groups = (ctx.grease("groups"), 0x11EC, 0x001D, 0x0017, 0x0018, 0x0019)
        return vector(b"".join(u16(group) for group in groups), 2)
    return chrome155.payload_for(kind, ctx)
'''
ONE_MORE_GROUP_DRAWN = ONE_MORE_GROUP + (
    'DRAWN = dict(chrome155.DRAWN, supported_groups="greased value at the head")\n')
ALPN_H2_DRAWN = '''\
from pybrws.profiles import firefox157
from pybrws.profiles.firefox157 import *

NAME = "alpn_h2"
EXTENSIONS = [(kind, bytes.fromhex("0003026832") if kind == 16 else payload)
              for kind, payload in firefox157.EXTENSIONS]
DRAWN = {"alpn": "drawn per connection", "length": "drawn per connection"}
'''
# chrome155 copies with an ECH payload of a size Chrome never sends, and
# with the GREASE extensions moved one place in from each end.
ECH_100 = CHROME_HEAD + '''\
from pybrws.wire import u8

NAME = "ech_100"


def payload_for(kind, ctx):
    if kind == 65037:
        return (u8(0) + u16(1) + u16(1) + u8(ctx.random(1)[0])
                + vector(ctx.random(32), 2) + vector(ctx.random(100), 2))
    return chrome155.payload_for(kind, ctx)
'''
GREASE_MOVED_IN = CHROME_HEAD + '''\
NAME = "grease_moved_in"


def extension_order(ctx):
    order = chrome155.extension_order(ctx)
    return order[1:2] + order[:1] + order[2:-2] + order[-1:] + order[-2:-1]
'''


def firefox_ech(name: str, outer: int = 0, kdf: int = 1, aead: str = "1",
                enc: int = 32, payload: int = 240) -> str:
    """A copy of firefox157 whose greased ECH has these header values."""
    return f'''\
from pybrws.profiles import firefox157
from pybrws.profiles.firefox157 import *
from pybrws.wire import u8, u16, vector

NAME = "{name}"


def greased_ech(ctx):
    return (u8({outer}) + u16({kdf}) + u16({aead}) + u8(ctx.random(1)[0])
            + vector(ctx.random({enc}), 2) + vector(ctx.random({payload}), 2))


EXTENSIONS = [(kind, greased_ech if kind == 65037 else payload)
              for kind, payload in firefox157.EXTENSIONS]
'''


# A chrome155 copy whose greased key share draws a GREASE value of its own,
# and one that sends the same GREASE extension type at both ends.
OWN_SLOT = CHROME_HEAD + '''\
NAME = "own_slot"


def key_share(ctx):
    entries = u16(ctx.grease("key_share")) + vector(b"\\x00", 2)
    for (group, size), (offered, share) in zip(KEY_SHARE_GROUPS,
                                               ctx.key_exchange.client_shares()):
        entries += u16(group) + vector(share, 2)
    return vector(entries, 2)


def payload_for(kind, ctx):
    if kind == 51:
        return key_share(ctx)
    return chrome155.payload_for(kind, ctx)
'''
REPEATED_GREASE = CHROME_HEAD + '''\
NAME = "repeated_grease"


def extension_order(ctx):
    order = chrome155.extension_order(ctx)
    return order[:-1] + order[:1]
'''
# A profile whose own key_share fails, on line 8 of its file.
NAME_ERROR = '''\
from pybrws.profiles import firefox157
from pybrws.profiles.firefox157 import *

NAME = "name_error"


def key_share(ctx):
    return undefined_name


EXTENSIONS = [(kind, key_share if kind == 51 else payload)
              for kind, payload in firefox157.EXTENSIONS]
'''


def write_capture(directory: Path, name: str, raw: bytes) -> str:
    path = Path(directory) / name
    path.write_text(raw.hex() + "\n", encoding="utf-8")
    return str(path)


def with_ech_payload(raw: bytes, size: int) -> bytes:
    """`raw`, a ClientHello record, with its greased ECH payload `size` bytes."""
    hello = parse_client_hello(raw)
    rebuilt = []
    for extension in hello.extensions:
        if extension.type == 0xFE0D:
            data = extension.data
            cut = 8 + int.from_bytes(data[6:8], "big")
            extension = Extension(extension.type,
                                  data[:cut] + size.to_bytes(2, "big")
                                  + bytes(size))
        rebuilt.append(extension)
    hello.extensions = rebuilt
    return emitter.serialise(hello, int.from_bytes(raw[1:3], "big"))


def run(main, argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(argv)
    return code, out.getvalue()


class VerifyCaptureTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.profile = str(write_profile(Path(tmp.name)))

    def test_custom_profile_against_its_own_capture(self):
        code, out = run(verify.main, ["--local", "--profile", self.profile,
                                      "--capture", FIREFOX])
        self.assertEqual(code, 0, out)
        self.assertIn("same string as the capture", out)

    def test_copy_of_chrome155_against_a_chrome_capture(self):
        path = write_profile(Path(self.profile).parent,
                             "from pybrws.profiles.chrome155 import *\n"
                             "NAME = 'my-chrome'\n", "my_chrome.py")
        code, out = run(verify.main, ["--local", "--profile", str(path),
                                      "--capture", CHROME])
        self.assertEqual(code, 0, out)
        self.assertNotIn("UNEXPECTED", out)

    def test_profile_without_drawn_is_compared_strictly(self):
        code, out = run(verify.main, ["--local", "--profile", "firefox157",
                                      "--capture", CHROME])
        self.assertEqual(code, 1)

    def test_echoed_command_names_the_capture(self):
        _, out = run(verify.main, ["--local", "--profile", self.profile,
                                   "--capture", FIREFOX])
        self.assertEqual(out.splitlines()[0],
                         "$ pybrws verify --local --profile %s --capture %s"
                         % (self.profile, FIREFOX))
        _, out = run(verify.main, ["--local"])
        self.assertEqual(out.splitlines()[0],
                         "$ pybrws verify --local --profile firefox157")

    def test_sni_line_says_where_the_name_came_from(self):
        _, out = run(verify.main, ["--local"])
        self.assertIn("sni      pybrws.127.0.0.1.nip.io   (taken from the capture)",
                      out.splitlines())
        _, out = run(verify.main, ["--local", "--hostname", "example.com"])
        lines = out.splitlines()
        self.assertEqual(lines[0], "$ pybrws verify --local --profile firefox157"
                                   " --hostname example.com")
        self.assertIn("sni      example.com   (given with --hostname)", lines)

    def test_same_through_the_cli(self):
        code, out = run(cli.main, ["verify", "--local", "--profile",
                                   self.profile, "--capture", FIREFOX])
        self.assertEqual(code, 0, out)

    def test_mismatched_capture_fails(self):
        code, out = run(verify.main, ["--local", "--profile", "firefox157",
                                      "--capture", CHROME])
        self.assertEqual(code, 1)
        self.assertIn("differs", out)
        self.assertIn("cipher suites", out)

    def test_file_profile_without_capture_is_refused(self):
        with self.assertRaises(SystemExit) as caught:
            verify.main(["--local", "--profile", self.profile])
        self.assertIn("--capture", str(caught.exception))

    def test_builtin_name_with_capture_uses_that_file(self):
        code, out = run(verify.main, ["--local", "--profile", "firefox157",
                                      "--capture", FIREFOX])
        self.assertEqual(code, 0, out)

    def test_capture_without_local_is_refused(self):
        with self.assertRaises(SystemExit) as caught:
            verify.main(["--capture", FIREFOX])
        self.assertIn("--local", str(caught.exception))


def line_for(out: str, field: str) -> str:
    """The report's line for `field`."""
    for line in out.splitlines():
        if line.startswith(field + " "):
            return line
    raise AssertionError("no line for %s in:\n%s" % (field, out))


class VerifyComparesLengthsTests(unittest.TestCase):
    """A field drawn per connection differs in its bytes, never in its size,
    unless the profile's DRAWN says why."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def verify(self, text: str, name: str, capture: str = FIREFOX):
        path = write_profile(self.dir, text, name)
        return run(verify.main, ["--local", "--profile", str(path),
                                 "--capture", capture])

    def test_a_wrong_ech_length_fails_and_names_the_field(self):
        code, out = self.verify(WRONG_ECH, "wrong_ech.py")
        self.assertEqual(code, 1, out)
        self.assertIn("UNEXPECTED", line_for(out, "encrypted_client_hello"))
        self.assertIn("payload length 208, 240 in the capture",
                      line_for(out, "encrypted_client_hello"))
        self.assertIn("UNEXPECTED", line_for(out, "ours"))
        self.assertIn("Not a pass.", out)

    def test_a_wrong_session_id_length_fails(self):
        code, out = self.verify(NO_SESSION_ID, "no_session_id.py")
        self.assertEqual(code, 1, out)
        self.assertIn("UNEXPECTED", line_for(out, "session_id"))

    def test_a_key_share_of_other_groups_fails(self):
        code, out = self.verify(TWO_SHARES, "two_shares.py")
        self.assertEqual(code, 1, out)
        self.assertIn("UNEXPECTED", line_for(out, "key_share"))
        self.assertIn("1258 bytes, 1327 in the capture",
                      line_for(out, "key_share"))

    def test_the_builtin_profiles_still_pass(self):
        for name in ("firefox157", "chrome155"):
            with self.subTest(profile=name):
                code, out = run(verify.main, ["--local", "--profile", name])
                self.assertEqual(code, 0, out)
                self.assertIn("same string as the capture", out)
                self.assertNotIn("UNEXPECTED", out)

    def test_every_ech_size_chrome155_draws_passes_every_capture(self):
        # chrome155 draws a 144-, 208- or 240-byte payload, and its DRAWN
        # says so; each draw against each of the six captures is a pass,
        # whether the two sizes agree or not.
        drawn = set()
        for seed in range(100):
            rng = random.Random(seed).randbytes
            hello = parse_client_hello(emitter.build_client_hello(
                HOSTNAME, profile=profiles.chrome155, rng=rng))
            size = len(hello.extension(0xFE0D).data)
            if size in drawn:
                continue
            drawn.add(size)
            build = functools.partial(emitter.build_client_hello,
                                      rng=random.Random(seed).randbytes)
            for capture in CHROMES:
                with self.subTest(ech=size, capture=Path(capture).name), \
                        mock.patch.object(verify, "build_client_hello", build):
                    code, out = run(verify.main, ["--local", "--profile",
                                                  "chrome155", "--capture",
                                                  capture])
                    self.assertEqual(code, 0, out)
                    self.assertNotIn("UNEXPECTED", out)
            if len(drawn) == 3:
                break
        self.assertEqual(drawn, {186, 250, 282})


class VerifyNormalisesGreaseTests(unittest.TestCase):
    """GREASE values drawn per connection compare equal to any other, and
    nothing else in a list that carries them is excused. DRAWN excuses the
    order of the extensions and the sizes it names, nothing more."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def verify(self, text: str, name: str, capture: str = CHROME):
        path = write_profile(self.dir, text, name)
        return run(verify.main, ["--local", "--profile", str(path),
                                 "--capture", capture])

    def test_other_groups_of_the_same_length_fail(self):
        code, out = self.verify(OTHER_GROUPS, "other_groups.py")
        self.assertEqual(code, 1, out)
        self.assertIn("UNEXPECTED", line_for(out, "supported_groups"))

    def test_drawn_cannot_name_a_list(self):
        with self.assertRaises(SystemExit) as caught:
            self.verify(OTHER_GROUPS_DRAWN, "other_groups_drawn.py")
        self.assertIn("'supported_groups'", str(caught.exception))

    def test_another_extension_set_fails_on_the_set_not_the_order(self):
        code, out = self.verify(OTHER_SET, "other_set.py")
        self.assertEqual(code, 1, out)
        line = line_for(out, "extensions")
        self.assertIn("UNEXPECTED", line)
        self.assertNotIn("drawn", line)

    def test_another_cipher_order_fails(self):
        code, out = self.verify(OTHER_CIPHER_ORDER, "other_cipher_order.py")
        self.assertEqual(code, 1, out)
        self.assertIn("UNEXPECTED", line_for(out, "cipher suites"))

    def test_other_grease_extension_payloads_fail(self):
        code, out = self.verify(EMPTY_GREASE_EXTENSIONS,
                                "empty_grease_extensions.py")
        self.assertEqual(code, 1, out)
        self.assertIn("UNEXPECTED", line_for(out, "GREASE extensions"))

    def test_another_record_version_fails(self):
        code, out = self.verify(OTHER_RECORD_VERSION,
                                "other_record_version.py", FIREFOX)
        self.assertEqual(code, 1, out)
        self.assertIn("UNEXPECTED", line_for(out, "version"))

    def test_other_compression_methods_fail(self):
        code, out = self.verify(OTHER_COMPRESSION, "other_compression.py",
                                FIREFOX)
        self.assertEqual(code, 1, out)
        self.assertIn("UNEXPECTED", line_for(out, "compression"))

    def test_grease_values_that_differ_from_the_capture_still_match(self):
        captured = parse_client_hello(load_hex(CHROME))
        for seed in range(100):
            hello = parse_client_hello(emitter.build_client_hello(
                HOSTNAME, profile=profiles.chrome155,
                rng=random.Random(seed).randbytes))
            if all(hello.extension(t).data[:4] != captured.extension(t).data[:4]
                   for t in (10, 13)) and \
                    hello.cipher_suites[0] != captured.cipher_suites[0]:
                break
        else:
            self.fail("no seed draws GREASE values unlike the capture's")
        build = functools.partial(emitter.build_client_hello,
                                  rng=random.Random(seed).randbytes)
        with mock.patch.object(verify, "build_client_hello", build):
            code, out = run(verify.main, ["--local", "--profile", "chrome155"])
        self.assertEqual(code, 0, out)
        self.assertNotIn("UNEXPECTED", out)
        self.assertIn("match", line_for(out, "cipher suites"))
        for field in ("supported_groups", "signature_algorithms",
                      "supported_versions"):
            with self.subTest(field=field):
                self.assertFalse([line for line in out.splitlines()
                                  if line.startswith(field + " ")])
        self.assertIn("16 of 18", line_for(out, "payloads"))

    def test_chrome155_draws_only_the_order_and_the_ech_size(self):
        self.assertEqual(profiles.chrome155.DRAWN,
                         {"extensions": "order drawn per connection",
                          "encrypted_client_hello": (144, 208, 240)})


class VerifyDrawnRulesTests(unittest.TestCase):
    """DRAWN holds the extension order, with a note, and the lengths a field
    drawn per connection is drawn from. A field's content is compared first,
    whatever DRAWN says, and anything else in DRAWN stops verify."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def verify(self, text: str, name: str, capture: str = CHROME):
        path = write_profile(self.dir, text, name)
        return run(verify.main, ["--local", "--profile", str(path),
                                 "--capture", capture])

    def stops(self, text: str, name: str, capture: str = CHROME) -> str:
        with self.assertRaises(SystemExit) as caught:
            self.verify(text, name, capture)
        message = str(caught.exception)
        self.assertNotIn("\n", message)
        self.assertIn("DRAWN can hold", message)
        return message

    def test_drawn_naming_a_list_stops_verify(self):
        self.assertIn("'supported_groups'",
                      self.stops(ONE_MORE_GROUP_DRAWN, "one_more_group_drawn.py"))

    def test_drawn_naming_alpn_and_length_stops_verify(self):
        self.assertIn("'alpn'",
                      self.stops(ALPN_H2_DRAWN, "alpn_h2.py", FIREFOX))

    def test_a_drawn_field_needs_its_lengths(self):
        text = ECH_100 + ('DRAWN = {"encrypted_client_hello": '
                          '"payload length drawn"}\n')
        self.assertIn("'encrypted_client_hello'",
                      self.stops(text, "ech_note.py"))

    def test_one_more_group_fails_with_chrome155s_drawn(self):
        code, out = self.verify(ONE_MORE_GROUP, "one_more_group.py")
        self.assertEqual(code, 1, out)
        self.assertIn("UNEXPECTED", line_for(out, "supported_groups"))

    def test_an_ech_payload_outside_the_drawn_lengths_fails(self):
        code, out = self.verify(ECH_100, "ech_100.py")
        self.assertEqual(code, 1, out)
        line = line_for(out, "encrypted_client_hello")
        self.assertIn("UNEXPECTED", line)
        self.assertIn("payload length 100", line)
        self.assertIn("(144, 208, 240)", line)

    def test_a_capture_outside_the_drawn_lengths_fails(self):
        capture = write_capture(self.dir, "chrome-100.hex",
                                with_ech_payload(load_hex(CHROME), 100))
        code, out = run(verify.main, ["--local", "--profile", "chrome155",
                                      "--capture", capture])
        self.assertEqual(code, 1, out)
        line = line_for(out, "encrypted_client_hello")
        self.assertIn("UNEXPECTED", line)
        self.assertIn("100 in the capture", line)

    def test_grease_extensions_moved_off_the_ends_fail(self):
        code, out = self.verify(GREASE_MOVED_IN, "grease_moved_in.py")
        self.assertEqual(code, 1, out)
        line = line_for(out, "GREASE extensions")
        self.assertIn("UNEXPECTED", line)
        self.assertIn("positions 1 and 18, 0 and 19 in the capture", line)


class VerifyEchHeaderTests(unittest.TestCase):
    """The greased ECH's random parts are free; its header is not."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def verify(self, text: str, name: str):
        path = write_profile(self.dir, text, name)
        return run(verify.main, ["--local", "--profile", str(path),
                                 "--capture", FIREFOX])

    def test_each_header_field_that_differs_fails_and_is_named(self):
        for field, text, words in (
                ("outer type", firefox_ech("outer", outer=1), "outer type 1, 0"),
                ("KDF", firefox_ech("kdf", kdf=2), "KDF 0x0002, 0x0001"),
                ("enc length", firefox_ech("enc", enc=64, payload=208),
                 "enc length 64, 32")):
            with self.subTest(field=field):
                code, out = self.verify(text, field.replace(" ", "_") + ".py")
                self.assertEqual(code, 1, out)
                line = line_for(out, "encrypted_client_hello")
                self.assertIn("UNEXPECTED -- ECH header", line)
                self.assertIn(words, line)

    def test_the_aead_is_free(self):
        # Firefox draws its AEAD, 0x0001 or 0x0003; the capture has 0x0001.
        self.assertEqual(parse_client_hello(load_hex(FIREFOX))
                         .extension(0xFE0D).data[3:5], b"\x00\x01")
        code, out = self.verify(firefox_ech("aead_3", aead="3"), "aead_3.py")
        self.assertEqual(code, 0, out)
        self.assertIn("same string as the capture", out)


class VerifyGreaseRegularitiesTests(unittest.TestCase):
    """What GREASE normalising would hide: the value supported_groups and
    key_share share, and an extension type sent twice."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def test_key_share_must_share_supported_groups_grease(self):
        path = write_profile(self.dir, OWN_SLOT, "own_slot.py")
        profile = profiles.load(str(path))
        for seed in range(100):
            hello = parse_client_hello(emitter.build_client_hello(
                HOSTNAME, profile=profile, rng=random.Random(seed).randbytes))
            if (hello.extension(10).data[2:4]
                    != hello.extension(51).data[2:4]):
                break
        else:
            self.fail("no seed draws two different GREASE values")
        build = functools.partial(emitter.build_client_hello,
                                  rng=random.Random(seed).randbytes)
        with mock.patch.object(verify, "build_client_hello", build):
            code, out = run(verify.main, ["--local", "--profile", str(path),
                                          "--capture", CHROME])
        self.assertEqual(code, 1, out)
        self.assertIn("UNEXPECTED", line_for(out, "shared GREASE"))

    def test_an_extension_type_sent_twice_fails(self):
        path = write_profile(self.dir, REPEATED_GREASE, "repeated_grease.py")
        code, out = run(verify.main, ["--local", "--profile", str(path),
                                      "--capture", CHROME])
        self.assertEqual(code, 1, out)
        self.assertIn("UNEXPECTED", line_for(out, "repeated type"))


class VerifyPaddingTests(unittest.TestCase):
    def test_padding_bytes_are_free_and_its_size_is_not(self):
        raw = load_hex(FIREFOX)
        hello = parse_client_hello(raw)
        hello.extensions = list(hello.extensions) + [Extension(21, bytes(10))]
        with tempfile.TemporaryDirectory() as tmp:
            capture = write_capture(Path(tmp), "padded.hex",
                                    emitter.serialise(hello, 0x0301))
            for size, code_wanted in ((10, 0), (12, 1)):
                path = write_profile(
                    Path(tmp),
                    "from pybrws.profiles import firefox157\n"
                    "from pybrws.profiles.firefox157 import *\n"
                    "NAME = 'padded'\n"
                    "EXTENSIONS = list(firefox157.EXTENSIONS) + "
                    "[(21, b'\\xff' * %d)]\n" % size, "padded_%d.py" % size)
                with self.subTest(size=size):
                    code, out = run(verify.main, ["--local", "--profile",
                                                  str(path), "--capture",
                                                  capture])
                    self.assertEqual(code, code_wanted, out)
                    self.assertIn("must (" if size == 10 else
                                  "UNEXPECTED -- 12 bytes, 10 in the capture",
                                  line_for(out, "padding"))


class VerifyBareCaptureTests(unittest.TestCase):
    """A hello copied from Wireshark's handshake layer has no record header."""

    def test_a_capture_without_its_record_header_passes_with_a_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = write_capture(Path(tmp), "bare.hex",
                                    load_hex(FIREFOX)[5:])
            code, out = run(verify.main, ["--local", "--profile",
                                          "firefox157", "--capture", capture])
        self.assertEqual(code, 0, out)
        self.assertIn("same string as the capture", out)
        self.assertIn("none in the capture", line_for(out, "record"))


class _Recorder:
    """A socket that keeps what is sent and then hangs up."""

    def __init__(self):
        self.sent = bytearray()

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        return b""

    def settimeout(self, timeout):
        pass

    def close(self):
        pass


class VerifyBuildsWhatAConnectionSendsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def first_flight(self, profile) -> bytes:
        """The ClientHello `handshake.connect` writes, with no network."""
        recorder = _Recorder()
        with mock.patch.object(handshake, "open_socket",
                               lambda *args, **kwargs: recorder):
            with self.assertRaises(Exception):
                handshake.connect(HOSTNAME, 4443, profile=profile)
        return bytes(recorder.sent)

    def test_a_copy_with_its_own_groups_is_built_as_a_connection_builds_it(self):
        path = write_profile(self.dir, TWO_SHARES, "two_shares.py")
        _, out = run(verify.main, ["--local", "--profile", str(path),
                                   "--capture", FIREFOX])
        ours = int(re.search(r"^ours\s+(\d+) bytes", out, re.M).group(1))
        sent = self.first_flight(profiles.load(str(path)))
        self.assertEqual(ours, len(sent))
        shares = parse_client_hello(sent).extension(51)
        self.assertEqual(len(shares.data), 2 + (4 + 1216) + (4 + 32))

    def test_a_hello_that_cannot_be_built_is_reported_in_one_line(self):
        path = write_profile(self.dir, X25519_FIRST, "x25519_first.py")
        with self.assertRaises(SystemExit) as caught:
            verify.main(["--local", "--profile", str(path),
                         "--capture", FIREFOX])
        self.assertRegex(str(caught.exception), FAILED_IN_FIREFOX157)

    def test_the_place_a_profiles_own_code_failed_is_named(self):
        path = write_profile(self.dir, NAME_ERROR, "name_error.py")
        with self.assertRaises(SystemExit) as caught:
            verify.main(["--local", "--profile", str(path),
                         "--capture", FIREFOX])
        self.assertEqual(str(caught.exception),
                         "cannot build a hello from profile 'name_error': "
                         "NameError: name 'undefined_name' is not defined "
                         "(name_error.py:8)")

    def test_the_library_raises_profile_error_before_any_socket(self):
        profile = profiles.load(str(write_profile(self.dir, X25519_FIRST,
                                                  "x25519_first.py")))
        with self.assertRaises(profiles.ProfileError) as caught:
            emitter.build_client_hello(HOSTNAME, profile=profile)
        self.assertTrue(str(caught.exception).startswith(
            "cannot build a hello from profile 'x25519_first': ValueError"))
        no_socket = AssertionError("a socket was opened")
        with mock.patch.object(handshake, "open_socket",
                               side_effect=no_socket), \
                self.assertRaises(profiles.ProfileError):
            handshake.connect(HOSTNAME, 4443, profile=profile)

    def test_ja4_reports_a_hello_that_cannot_be_built_in_one_line(self):
        from pybrws.tools import ja4
        path = write_profile(self.dir, X25519_FIRST, "x25519_first.py")
        with self.assertRaises(SystemExit) as caught:
            ja4.main(["--profile", str(path)])
        self.assertRegex(str(caught.exception), FAILED_IN_FIREFOX157)

    def test_the_builtin_profiles_are_built_as_a_connection_builds_them(self):
        for profile in (profiles.firefox157, profiles.chrome155):
            with self.subTest(profile=profile.NAME):
                rng = random.Random(3).randbytes
                built = emitter.build_client_hello(HOSTNAME, profile=profile,
                                                   rng=rng)
                with mock.patch.object(
                        handshake, "build_client_hello",
                        functools.partial(emitter.build_client_hello,
                                          rng=random.Random(3).randbytes)):
                    sent = self.first_flight(profile)
                self.assertEqual(len(built), len(sent))


class MeasuringToolsStopOnAHelloThatCannotBeBuiltTests(unittest.TestCase):
    """ab, isolate and probe build one hello from the profile first. One that
    cannot be built stops them in its one line, before their extras are
    imported and before any request. ab used to send its httpx arms anyway,
    then read every failed pybrws sample as a network failure."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.profile = str(write_profile(Path(tmp.name), X25519_FIRST,
                                         "x25519_first.py"))
        # ab's main sets these module globals; each patch puts one back.
        for name in ("CLIENTS", "CONTROL", "PROFILE", "PROXY"):
            patcher = mock.patch.object(ab_test, name, getattr(ab_test, name))
            patcher.start()
            self.addCleanup(patcher.stop)

    def pybrws(self, *argv):
        """`pybrws ARGV` with the extras missing and every socket refused:
        its exit status, stdout and stderr."""
        opened = []

        def refuse(sock, *args):
            opened.append(args)
            raise OSError("refused by the test")

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(sys.modules, {"httpx": None, "aioquic": None}), \
                mock.patch("socket.socket.connect", refuse), \
                mock.patch("socket.socket.sendto", refuse), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(list(argv))
            except SystemExit as exit_:
                code = exit_.code
                if isinstance(code, str):   # what the shell prints, status 1
                    err.write(code + "\n")
                    code = 1
        self.assertEqual(opened, [], "a socket was opened")
        return code, out.getvalue(), err.getvalue()

    def assert_stops_in_one_line(self, *argv):
        code, out, err = self.pybrws(*argv, "--profile", self.profile)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertRegex(err, FAILED_IN_FIREFOX157)

    def test_ab(self):
        self.assert_stops_in_one_line(
            "ab", "--targets", "https://127.0.0.1:9/", "--no-log",
            "--rounds", "1", "--pause", "0")

    def test_isolate(self):
        self.assert_stops_in_one_line(
            "isolate", "--targets", "https://127.0.0.1:9/",
            "--proxy", "http://127.0.0.1:9", "--rounds", "1")

    def test_probe(self):
        self.assert_stops_in_one_line("probe", "--url", "https://127.0.0.1:9/")


class _SocketOpened(Exception):
    pass


class OnlineVerifyRefusesWhatItWouldIgnoreTests(unittest.TestCase):
    """Without --local, verify sends firefox157 to tls.peet.ws, whatever
    --profile names, under that service's own name. So another --profile, or
    any --hostname, is refused in one line, as --capture is, before anything
    is sent: it used to print a pass for a profile that was never sent."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def refused(self, *argv) -> str:
        with mock.patch.object(handshake, "open_socket",
                               side_effect=_SocketOpened), \
                contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(SystemExit) as caught:
            cli.main(["verify", *argv])
        return caught.exception.code

    def test_a_profile_file_needs_local(self):
        path = write_profile(self.dir)
        self.assertEqual(self.refused("--profile", str(path)),
                         "--profile needs --local: without it, verify sends "
                         "firefox157")

    def test_another_builtin_profile_needs_local(self):
        self.assertEqual(self.refused("--profile", "chrome155"),
                         "--profile needs --local: without it, verify sends "
                         "firefox157")

    def test_a_hostname_needs_local(self):
        self.assertEqual(self.refused("--hostname", HOSTNAME),
                         "--hostname needs --local")

    def test_firefox157_by_name_is_what_it_sends(self):
        # Nothing would be ignored, so verify goes on to connect, which is
        # where the test stops it.
        with mock.patch.object(handshake, "open_socket",
                               side_effect=_SocketOpened), \
                self.assertRaises(_SocketOpened):
            cli.main(["verify", "--profile", "firefox157"])


if __name__ == "__main__":
    unittest.main()
