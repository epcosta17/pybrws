"""`pybrws verify --local --capture FILE`: any profile against your own hello."""

from __future__ import annotations

import contextlib
import functools
import io
import random
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pybrws import cli, emitter, handshake, profiles
from pybrws.hexio import load_hex
from pybrws.parser import parse_client_hello
from pybrws.tools import verify
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
        self.assertIn("250 bytes, 282 in the capture",
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

    def test_drawn_does_not_excuse_a_list_that_differs(self):
        code, out = self.verify(OTHER_GROUPS_DRAWN, "other_groups_drawn.py")
        self.assertEqual(code, 1, out)
        self.assertIn("UNEXPECTED", line_for(out, "supported_groups"))

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
        self.assertEqual(set(profiles.chrome155.DRAWN),
                         {"extensions", "encrypted_client_hello", "length"})


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
        message = str(caught.exception)
        self.assertIn("cannot build a hello from %s" % path, message)
        self.assertIn("ValueError: key_share for 0x11ec", message)
        self.assertNotIn("\n", message)

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


if __name__ == "__main__":
    unittest.main()
