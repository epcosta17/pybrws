#!/usr/bin/env python3
"""Compare this client's fingerprint against a reference capture.

Two modes, because they answer different questions.

`--local` diffs the hello this client builds against a browser's captured
bytes, field by field, with no network at all; for firefox157 and chrome155
the captures ship with pybrws. That is the one to reach
for: it is instant, it needs nothing to be reachable, and it shows which
fields match and which cannot match -- the random, the session id, the
key_share and the greased ECH payload are all freshly generated, so a clone
that reproduced them byte for byte would be broken rather than good.

Without it, this fetches tls.peet.ws/api/all and diffs every fingerprint
field against that service's reading of Firefox 157, which ships with pybrws
too. A third party is worth asking, but that one advertises HTTP/3 and does
not serve it, and has been unreachable often enough that a demo should not
depend on it. For an outside reading prefer `pybrws probe`.

    pybrws verify --local
    pybrws verify --local --profile chrome155
    pybrws verify --local --profile my_profile.py --capture my_hello.hex
    pybrws verify
"""

from __future__ import annotations

import argparse
import json
from collections import Counter

from pybrws import data, profiles
from pybrws.emitter import build_client_hello
from pybrws.handshake import connect
from pybrws.hexio import load_hex, parse_hex
from pybrws.http2 import Http2Connection
from pybrws.model import GREASE_VALUES, extension_name
from pybrws.parser import parse_client_hello
from pybrws.profiles import firefox157
from pybrws.tools import ja4 as ja4_tool

# tls.peet.ws's report on Firefox 157, as packaged in pybrws.data.
REFERENCE = "reference-firefox-157-peet.json"
HOST = "tls.peet.ws"
PATH = "/api/all"

# Each built-in profile and the packaged capture `--local` compares it with.
CAPTURES = {
    "firefox157": "reference-firefox-157-windows-fresh.hex",
    "chrome155": "chrome-1.hex",
}

# Fields that are freshly generated per connection. A clone that reproduced
# these would not be a better clone, it would be a broken one: the key_share
# carries a real keypair whose private half the server's answer is useless
# without, and a replayed random defeats the handshake's own replay
# protection. So they are reported as differing on purpose, and it is the
# only honest way to show a byte comparison of a live handshake. Their sizes
# are still compared: a wrong-sized key share or ECH payload is a fault that
# a byte comparison of fresh randomness would otherwise hide.
MUST_DIFFER = {
    "random": "32 fresh random bytes",
    "session_id": "32 fresh random bytes",
    "key_share": "a real keypair",
    "encrypted_client_hello": "greased payload",
    "padding": "sized to whatever precedes it",
}

# A profile that models a browser which varies declares DRAWN: what differs
# from one capture by design, and why; see pybrws/profiles/chrome155.py. It
# can excuse three things and nothing else: the order of the extensions
# ("extensions"), the size of the extension it names, and the size of the
# whole hello ("length"). Everything else is compared every time:
# - the versions and the compression methods;
# - the cipher suites, in order;
# - the set of extension types;
# - every payload, byte for byte, except the fields drawn per connection;
# - the size of every field.
# A GREASE value compares equal to any other, in the lists that carry one.

GREASED = "GREASE"
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51
# The payloads compared in a parsed form rather than as bytes, and what the
# report says when that form differs from the capture's.
RESHAPED = {
    EXT_SUPPORTED_GROUPS: "other groups",
    EXT_SIGNATURE_ALGORITHMS: "other signature algorithms",
    EXT_SUPPORTED_VERSIONS: "other versions",
    EXT_KEY_SHARE: "other groups or key sizes",
}
SHAPED = tuple(RESHAPED)


def _counted(values: list) -> str:
    """A row's note: how many values, in order, and how many are GREASE."""
    greased = values.count(GREASED)
    return "%d, same order%s" % (len(values) - greased,
                                 ", %d greased" % greased if greased else "")


def normalised(values) -> list:
    """`values` with every GREASE value replaced by one marker.

    A browser draws its GREASE values per connection, so any one compares
    equal to any other. Where they stand, and every other value in order,
    must still be the capture's.
    """
    return [GREASED if value in GREASE_VALUES else value for value in values]


def _vector(data: bytes, size: int) -> bytes:
    """The body of a length-prefixed vector that fills `data` exactly."""
    if (len(data) < size
            or int.from_bytes(data[:size], "big") != len(data) - size):
        raise ValueError("the length prefix does not match the payload")
    return data[size:]


def _u16s(data: bytes) -> list[int]:
    if len(data) % 2:
        raise ValueError("an odd number of bytes in a list of 16-bit values")
    return [int.from_bytes(data[i:i + 2], "big")
            for i in range(0, len(data), 2)]


def shape(ext_type: int, data: bytes):
    """What verify compares in an extension's payload.

    The bytes, except in the lists that can carry GREASE values, which are
    read with each one normalised, and in key_share, whose keys are new on
    every connection: there the groups and the key sizes are compared. A
    payload that does not parse is compared as bytes.
    """
    try:
        if ext_type in (EXT_SUPPORTED_GROUPS, EXT_SIGNATURE_ALGORITHMS):
            return normalised(_u16s(_vector(data, 2)))
        if ext_type == EXT_SUPPORTED_VERSIONS:
            return normalised(_u16s(_vector(data, 1)))
        if ext_type == EXT_KEY_SHARE:
            body, shares = _vector(data, 2), []
            while body:
                size = int.from_bytes(body[2:4], "big")
                if len(body) < 4 + size:
                    raise ValueError("a key share runs past the extension")
                group = int.from_bytes(body[:2], "big")
                shares.append((normalised([group])[0], size))
                body = body[4 + size:]
            return shares
    except ValueError:
        pass
    return data


def _record_version(hello) -> bytes:
    """The record header's version, or nothing for a bare handshake message."""
    return hello.raw[1:3] if hello.raw[:1] == b"\x16" else b""


def sni_of(hello) -> str:
    """The hostname inside server_name.

    Needed because the hostname is the one field whose length moves the
    whole message: comparing a hello built for one host against a capture
    taken against another reports a byte difference that is entirely the
    operator's doing. So the capture supplies its own.
    """
    ext = hello.extension(0x0000)
    if not ext or len(ext.data) < 5:
        return ""
    length = int.from_bytes(ext.data[3:5], "big")
    return ext.data[5:5 + length].decode("ascii", "replace")


def local(profile_name: str, hostname: str | None,
          capture: str | None = None) -> int:
    """Diff the built hello against the captured one, offline.

    `capture` is a hex ClientHello file of the reader's own; without it the
    built-in profile's shipped capture is used. A profile named by a file
    has no shipped capture, so it needs one.
    """
    try:
        profile = profiles.load(profile_name, transport="tcp")
    except profiles.ProfileError as error:
        raise SystemExit(str(error))
    if capture:
        try:
            captured = parse_client_hello(load_hex(capture))
        except (OSError, ValueError) as error:
            raise SystemExit("cannot read the capture %s: %s"
                             % (capture, error))
        capture_name = capture
    elif profile_name in CAPTURES:
        capture_name = CAPTURES[profile_name]
        captured = parse_client_hello(parse_hex(data.read_text(capture_name)))
    elif profiles.is_path(profile_name):
        raise SystemExit("%s is your own profile, so there is no shipped "
                         "capture to compare it with; pass --capture FILE "
                         "with a hello from your browser" % profile_name)
    else:
        raise SystemExit("no capture ships for %s; the shipped ones are for %s"
                         " (or pass --capture FILE)"
                         % (profile_name, " and ".join(sorted(CAPTURES))))
    given = bool(hostname)
    hostname = hostname or sni_of(captured)
    try:
        ours = parse_client_hello(build_client_hello(hostname, profile=profile))
    except Exception as error:
        # A profile's own function can refuse what it is given, such as a
        # firefox157 key_share handed groups firefox157 does not send. That
        # is a finding about the profile, said in one line like the others.
        raise SystemExit("cannot build a hello from %s: %s: %s"
                         % (profile_name, type(error).__name__, error))

    drawn = getattr(profile, "DRAWN", {})
    # Each field whose size differs from the capture's, as (ours, real). Its
    # bytes may differ by design; its size may not, unless DRAWN says why.
    resized: dict[str, tuple[int, int]] = {}
    # Why each field that differs in what it holds differs, as verify found it.
    found: dict[str, str] = {}

    # The record header's version is a version too, and a server reads it.
    record, real_record = _record_version(ours), _record_version(captured)
    if ours.legacy_version != captured.legacy_version:
        found["version"] = ("legacy version 0x%04x, 0x%04x in the capture"
                            % (ours.legacy_version, captured.legacy_version))
    elif record != real_record:
        found["version"] = ("record version 0x%s, 0x%s in the capture"
                            % (record.hex(), real_record.hex()))
    if len(ours.session_id) != len(captured.session_id):
        resized["session_id"] = (len(ours.session_id),
                                 len(captured.session_id))

    suites = normalised(ours.cipher_suites)
    real_suites = normalised(captured.cipher_suites)
    if suites != real_suites:
        found["cipher suites"] = ("the same suites in another order"
                                  if Counter(suites) == Counter(real_suites)
                                  else "other suites")

    # The set of extension types is compared even where DRAWN excuses their
    # order: a drawn order is no reason to miss an extension or add one.
    mine = normalised(e.type for e in ours.extensions)
    theirs = normalised(e.type for e in captured.extensions)
    missing = Counter(theirs) - Counter(mine)
    extra = Counter(mine) - Counter(theirs)
    if missing or extra:
        found["extensions"] = "; ".join(
            "%s %s" % (word, ", ".join(kind if kind == GREASED
                                       else extension_name(kind)
                                       for kind in kinds.elements()))
            for word, kinds in (("missing", missing), ("extra", extra))
            if kinds)
    elif mine != theirs and "extensions" not in drawn:
        found["extensions"] = "the same extensions in another order"

    # The fixed fields with no row of their own, named only when they differ.
    if list(ours.compression_methods) != list(captured.compression_methods):
        found["compression"] = ("%s, %s in the capture"
                                % (list(ours.compression_methods),
                                   list(captured.compression_methods)))
    greased = [e.data for e in ours.extensions if e.type in GREASE_VALUES]
    real_greased = [e.data for e in captured.extensions
                    if e.type in GREASE_VALUES]
    if greased != real_greased:
        found["GREASE extensions"] = (
            "payloads of %s bytes, %s in the capture"
            % (" and ".join(str(len(d)) for d in greased) or "no",
               " and ".join(str(len(d)) for d in real_greased) or "no"))

    # Every extension's payload, so "same list" cannot hide a wrong body.
    differing = []
    byte_for_byte = greased_alike = 0
    real = [kind for kind in theirs if kind != GREASED]
    for ext_type in real:
        a, b = ours.extension(ext_type), captured.extension(ext_type)
        if a is None or b is None:
            continue    # the extensions line names it
        name = extension_name(ext_type)
        if len(a.data) != len(b.data):
            resized[name] = (len(a.data), len(b.data))
        if a.data == b.data:
            byte_for_byte += 1
            continue
        same_shape = shape(ext_type, a.data) == shape(ext_type, b.data)
        if same_shape and name not in MUST_DIFFER:
            greased_alike += 1      # the same list, once GREASE is normalised
            continue
        differing.append(name)
        if not same_shape and ext_type in SHAPED:
            found[name] = RESHAPED[ext_type]

    # The whole hello's size is drawn only when DRAWN says so and every byte
    # of the difference is in a field whose size DRAWN names.
    difference = len(ours.raw) - len(captured.raw)
    explained = sum(size - real_size
                    for name, (size, real_size) in resized.items()
                    if name in drawn)
    length_unexplained = bool(difference) and (
        "length" not in drawn or difference != explained)

    def note_for(name: str) -> str:
        sizes = resized.get(name)
        if sizes:
            return ("drawn (%s)" % drawn[name] if name in drawn
                    else "UNEXPECTED -- %d bytes, %d in the capture" % sizes)
        if name in found:
            return "UNEXPECTED -- " + found[name]
        if name == "extensions":    # the order alone, which DRAWN excuses
            return "drawn (%s)" % drawn[name]
        if name in MUST_DIFFER:
            return "must (%s)" % MUST_DIFFER[name]
        return "UNEXPECTED -- investigate"

    rows: list[tuple[str, bool, str]] = [
        ("version", "version" not in found, ""),
        ("random", ours.random == captured.random, ""),
        ("session_id", ours.session_id == captured.session_id,
         "%d bytes each" % len(captured.session_id)),
        ("cipher suites", suites == real_suites, _counted(real_suites)),
        ("extensions", mine == theirs, _counted(theirs)),
    ]
    extras = [name for name in ("compression", "GREASE extensions")
              if name in found]
    changed = [name for name, ok, _ in rows if not ok] + extras + differing
    notes = [(name, note_for(name)) for name in dict.fromkeys(changed)]

    print("$ pybrws verify --local --profile %s%s%s\n"
          % (profile_name, " --capture %s" % capture if capture else "",
             " --hostname %s" % hostname if given else ""))
    print("capture  %s" % capture_name)
    print("sni      %s   (%s)" % (hostname, "given with --hostname" if given
                                  else "taken from the capture"))
    if not difference:
        length_note = ""
    elif length_unexplained:
        length_note = "   UNEXPECTED -- investigate"
    else:
        length_note = "   drawn (%s)" % drawn["length"]
    print("ours     %d bytes%s" % (len(ours.raw), length_note))
    print("real     %d bytes" % len(captured.raw))
    print()

    width = max(len(name) for name, _, _ in rows) + 2
    for name, ok, note in rows:
        if ok:
            print(("%-*s %s   %s" % (width, (name + " ").ljust(width, "."),
                                     "match", note)).rstrip())
    # A count, not a verdict: the payloads that differ are listed below with
    # the reason each one has to, so "match" or "differs" here would be
    # either a contradiction or a repetition.
    print("%-*s %d of %d   %s"
          % (width, "payloads ".ljust(width, "."),
             byte_for_byte + greased_alike, len(real),
             "byte for byte" if not greased_alike else
             "%d byte for byte, %d with GREASE normalised"
             % (byte_for_byte, greased_alike)))

    # One line per differing field, whether it came from the fixed rows or
    # from an extension payload. Printed in one place so nothing appears
    # twice, which the first version did for random and session_id.
    if notes:
        print()
    for name, note in notes:
        print("%-*s %s   %s"
              % (width, (name + " ").ljust(width, "."), "differs", note))

    computed = ja4_tool.compute(ours, set())
    reference = ja4_tool.compute(captured, set())
    print()
    print("ja4  %s" % computed["ja4"])
    print("     %s" % ("same string as the capture"
                       if computed["ja4"] == reference["ja4"]
                       else "DIFFERS from the capture: " + reference["ja4"]))

    bad = (length_unexplained
           or any(note.startswith("UNEXPECTED") for _, note in notes)
           or computed["ja4"] != reference["ja4"])
    if bad:
        print("\nSomething differs that should not. Not a pass.")
    return 1 if bad else 0


def fetch(profile) -> dict:
    with connect(HOST) as tls:
        response = Http2Connection(tls, profile=profile).get(PATH, HOST)
    if response.status != 200:
        raise SystemExit("unexpected status " + str(response.status))
    return json.loads(response.body)


def headers_of(report: dict) -> list[str]:
    for sent in report.get("http2", {}).get("sent_frames", []):
        if sent.get("frame_type") == "HEADERS":
            return sent.get("headers", [])
    return []


def headers_frame_of(report: dict) -> dict:
    for sent in report.get("http2", {}).get("sent_frames", []):
        if sent.get("frame_type") == "HEADERS":
            return sent
    return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pybrws verify",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="dump the full report")
    parser.add_argument("--local", action="store_true",
                        help="diff against the captured bytes, no network")
    parser.add_argument("--profile", default="firefox157",
                        help="with --local, the profile to build: a built-in "
                             "name or a .py file. Captures ship for "
                             + " and ".join(sorted(CAPTURES)))
    parser.add_argument("--capture", default=None, metavar="FILE",
                        help="with --local, a hex ClientHello from your own "
                             "browser (as `pybrws capture hello` writes it) "
                             "to compare the profile with; needed for a "
                             ".py profile")
    parser.add_argument("--hostname", default=None,
                        help="goes in server_name; the capture's own host, "
                             "so the SNI payload can be compared too")
    args = parser.parse_args(argv)

    if args.capture and not args.local:
        raise SystemExit("--capture needs --local")
    if args.local:
        return local(args.profile, args.hostname, args.capture)

    reference = json.loads(data.read_text(REFERENCE))
    report = fetch(firefox157)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    frame = headers_frame_of(report)
    ref_frame = reference["http2"]["headers_frame"]

    checks = [
        ("http_version", reference["http_version"], report.get("http_version")),
        ("user_agent", reference["user_agent"], report.get("user_agent")),
    ]
    for key in ("ja3", "ja3_hash", "ja4", "ja4_r", "peetprint", "peetprint_hash",
                "tls_version_record", "tls_version_negotiated"):
        checks.append(("tls." + key, reference["tls"][key], report.get("tls", {}).get(key)))
    for key in ("akamai_fingerprint", "akamai_fingerprint_hash"):
        checks.append(("http2." + key, reference["http2"][key],
                       report.get("http2", {}).get(key)))
    checks += [
        ("h2.stream_id", ref_frame["stream_id"], frame.get("stream_id")),
        ("h2.headers_length", ref_frame["length"], frame.get("length")),
        ("h2.flags", ref_frame["flags"], frame.get("flags")),
        ("h2.priority", ref_frame["priority"], frame.get("priority")),
        ("h2.header_order", ref_frame["headers"], headers_of(report)),
        ("tcpip.p0f", reference["tcpip"]["p0f"], report.get("tcpip", {}).get("p0f")),
    ]

    failures = 0
    for name, expected, actual in checks:
        ok = expected == actual
        failures += not ok
        print(("  PASS  " if ok else "  FAIL  ") + name)
        if not ok:
            if isinstance(expected, list) and isinstance(actual, list):
                for i in range(max(len(expected), len(actual))):
                    want = expected[i] if i < len(expected) else None
                    got = actual[i] if i < len(actual) else None
                    if want != got:
                        print("          [%d] expected %r" % (i, want))
                        print("              got      %r" % (got,))
            else:
                print("          expected " + repr(expected))
                print("          got      " + repr(actual))

    print()
    print("%d of %d checks passed" % (len(checks) - failures, len(checks)))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
