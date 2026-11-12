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
# protection. So their bytes are reported as differing on purpose, and it is
# the only honest way to show a byte comparison of a live handshake. What is
# not random in them is still compared: every size, key_share's groups and
# key sizes, and the greased ECH's header.
MUST_DIFFER = {
    "random": "32 fresh random bytes",
    "session_id": "32 fresh random bytes",
    "key_share": "a real keypair",
    "encrypted_client_hello": "greased payload",
    "padding": "sized to whatever precedes it",
}

# A profile that models a browser which varies declares DRAWN: what differs
# from one capture by design; see pybrws/profiles/chrome155.py. It holds two
# kinds of key and nothing else:
# - "extensions", with a note: the extension order is drawn. Only the order
#   is excused; the set of types, and where the GREASE extensions stand, are
#   still the capture's.
# - a field of MUST_DIFFER, with the tuple of lengths it is drawn from. Its
#   length is excused when ours and the capture's are both in the tuple; for
#   encrypted_client_hello, the length is the greased payload's.
# A field's content is compared first, whatever DRAWN says, and the whole
# hello's size only differs by what DRAWN excused.
DRAWN_CAN_HOLD = ('DRAWN can hold "extensions" with a note, and a field drawn '
                  'per connection (%s) with the tuple of lengths it is drawn '
                  'from' % ", ".join(MUST_DIFFER))

GREASED = "GREASE"
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51
EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D
# The payloads compared in a parsed form rather than as bytes, and what the
# report says when that form differs from the capture's.
RESHAPED = {
    EXT_SUPPORTED_GROUPS: "other groups",
    EXT_SIGNATURE_ALGORITHMS: "other signature algorithms",
    EXT_SUPPORTED_VERSIONS: "other versions",
    EXT_KEY_SHARE: "other groups or key sizes",
}


def drawn_of(profile, label: str) -> dict:
    """The profile's DRAWN, after checking it holds only what it can.

    Raises:
        SystemExit: in one line naming the key, for any other key or a value
            of the wrong kind.
    """
    drawn = getattr(profile, "DRAWN", {})
    if not isinstance(drawn, dict):
        raise SystemExit("DRAWN in %s is a %s, not a dict. %s."
                         % (label, type(drawn).__name__, DRAWN_CAN_HOLD))
    for key, value in drawn.items():
        if key == "extensions":
            if isinstance(value, str):
                continue
            wanted = "a note, a str"
        elif key in MUST_DIFFER:
            if (isinstance(value, tuple) and value
                    and all(type(n) is int and n >= 0 for n in value)):
                continue
            wanted = "the lengths it is drawn from, a tuple of ints"
        else:
            raise SystemExit("DRAWN in %s names %r. %s."
                             % (label, key, DRAWN_CAN_HOLD))
        raise SystemExit("DRAWN in %s gives %r a %s, where it needs %s. %s."
                         % (label, key, type(value).__name__, wanted,
                            DRAWN_CAN_HOLD))
    return drawn


def _counted(values: list) -> str:
    """A row's note: how many values, in order, and how many are GREASE."""
    greased = values.count(GREASED)
    return "%d, same order%s" % (len(values) - greased,
                                 ", %d greased" % greased if greased else "")


def _and(items) -> str:
    items = [str(item) for item in items]
    if not items:
        return "none"
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


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


def _key_shares(data: bytes) -> list[tuple[int, int]]:
    """key_share's entries as (group, key size), raw."""
    body, shares = _vector(data, 2), []
    while body:
        size = int.from_bytes(body[2:4], "big")
        if len(body) < 4 + size:
            raise ValueError("a key share runs past the extension")
        shares.append((int.from_bytes(body[:2], "big"), size))
        body = body[4 + size:]
    return shares


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
            return [(normalised([group])[0], size)
                    for group, size in _key_shares(data)]
    except ValueError:
        pass
    return data


def ech_header(data: bytes) -> dict | None:
    """A greased ECH's fixed fields, or None if it does not parse.

    The config id, the enc and payload bytes and the AEAD are left out:
    they are drawn per connection, the AEAD by Firefox from 0x0001 and
    0x0003. What is left is the shape a browser keeps.
    """
    if len(data) < 10:
        return None
    enc = int.from_bytes(data[6:8], "big")
    end = 8 + enc
    if len(data) < end + 2:
        return None
    payload = int.from_bytes(data[end:end + 2], "big")
    if len(data) != end + 2 + payload:
        return None
    return {"outer type": data[0], "KDF": int.from_bytes(data[1:3], "big"),
            "enc length": enc, "payload length": payload}


ECH_FORMATS = {"outer type": "%d", "KDF": "0x%04x", "enc length": "%d",
               "payload length": "%d"}


def shares_grease(hello) -> bool:
    """Whether key_share's GREASE group is a GREASE value supported_groups
    carries, as Chrome's always is: a share must name an offered group."""
    groups = hello.extension(EXT_SUPPORTED_GROUPS)
    shares = hello.extension(EXT_KEY_SHARE)
    if groups is None or shares is None:
        return False
    try:
        offered = _u16s(_vector(groups.data, 2))
        greased = [group for group, _ in _key_shares(shares.data)
                   if group in GREASE_VALUES]
    except ValueError:
        return False
    return bool(greased) and all(group in offered for group in greased)


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
    drawn = drawn_of(profile, profile_name)
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
    except profiles.ProfileError as error:
        # A profile's own function can refuse what it is given, such as a
        # firefox157 key_share handed groups firefox157 does not send. That
        # is a finding about the profile, said in one line like the others.
        raise SystemExit(str(error))

    # Why each field that differs differs, in the order the report lists
    # them. A note that starts with UNEXPECTED fails the run.
    notes: dict[str, str] = {}
    # The bytes of size difference DRAWN excused, and the fields they are in.
    excused, excusing = 0, []

    def resized(name: str, size: int, real_size: int) -> str:
        """The note for a drawn field whose length differs, counting what
        DRAWN excuses: both lengths must be in the field's tuple."""
        nonlocal excused
        lengths = drawn.get(name)
        if lengths and size in lengths and real_size in lengths:
            excused += size - real_size
            excusing.append(name)
            return "drawn (length drawn from %s)" % ", ".join(
                str(n) for n in lengths)
        return "UNEXPECTED -- %d bytes, %d in the capture%s" % (
            size, real_size,
            ", not both in %s" % (tuple(lengths),) if lengths else "")

    # A hello copied from Wireshark's handshake layer has no record header.
    # Then the record version is not compared, and our header is left out
    # of the sizes.
    headed = bool(_record_version(captured))
    if ours.legacy_version != captured.legacy_version:
        notes["version"] = ("UNEXPECTED -- legacy version 0x%04x, 0x%04x in "
                            "the capture" % (ours.legacy_version,
                                             captured.legacy_version))
    elif headed and _record_version(ours) != _record_version(captured):
        notes["version"] = ("UNEXPECTED -- record version 0x%s, 0x%s in the "
                            "capture" % (_record_version(ours).hex(),
                                         _record_version(captured).hex()))

    if ours.random != captured.random:
        notes["random"] = "must (%s)" % MUST_DIFFER["random"]
    if ours.session_id != captured.session_id:
        size, real_size = len(ours.session_id), len(captured.session_id)
        notes["session_id"] = ("must (%s)" % MUST_DIFFER["session_id"]
                               if size == real_size
                               else resized("session_id", size, real_size))

    suites = normalised(ours.cipher_suites)
    real_suites = normalised(captured.cipher_suites)
    if suites != real_suites:
        notes["cipher suites"] = ("UNEXPECTED -- the same suites in another "
                                  "order"
                                  if Counter(suites) == Counter(real_suites)
                                  else "UNEXPECTED -- other suites")

    # The set of extension types is compared even where DRAWN excuses their
    # order: a drawn order is no reason to miss an extension or add one.
    mine_raw = [e.type for e in ours.extensions]
    theirs_raw = [e.type for e in captured.extensions]
    mine, theirs = normalised(mine_raw), normalised(theirs_raw)
    missing = Counter(theirs) - Counter(mine)
    extra = Counter(mine) - Counter(theirs)
    if missing or extra:
        notes["extensions"] = "UNEXPECTED -- " + "; ".join(
            "%s %s" % (word, ", ".join(kind if kind == GREASED
                                       else extension_name(kind)
                                       for kind in kinds.elements()))
            for word, kinds in (("missing", missing), ("extra", extra))
            if kinds)
    elif mine != theirs:
        notes["extensions"] = ("drawn (%s)" % drawn["extensions"]
                               if "extensions" in drawn else
                               "UNEXPECTED -- the same extensions in "
                               "another order")

    if list(ours.compression_methods) != list(captured.compression_methods):
        notes["compression"] = ("UNEXPECTED -- %s, %s in the capture"
                                % (list(ours.compression_methods),
                                   list(captured.compression_methods)))

    # A drawn order still keeps the GREASE extensions where the capture has
    # them, with the capture's payloads.
    places = [i for i, kind in enumerate(mine_raw) if kind in GREASE_VALUES]
    real_places = [i for i, kind in enumerate(theirs_raw)
                   if kind in GREASE_VALUES]
    greased = [e.data for e in ours.extensions if e.type in GREASE_VALUES]
    real_greased = [e.data for e in captured.extensions
                    if e.type in GREASE_VALUES]
    if places != real_places:
        notes["GREASE extensions"] = ("UNEXPECTED -- at positions %s, %s in "
                                      "the capture" % (_and(places),
                                                       _and(real_places)))
    elif greased != real_greased:
        notes["GREASE extensions"] = (
            "UNEXPECTED -- payloads of %s bytes, %s in the capture"
            % (_and(len(d) for d in greased),
               _and(len(d) for d in real_greased)))

    # Two regularities GREASE normalising would hide: key_share's GREASE
    # group is the one supported_groups offers, and no type is sent twice.
    if shares_grease(captured) and not shares_grease(ours):
        notes["shared GREASE"] = ("UNEXPECTED -- key_share's GREASE group is "
                                  "not supported_groups' GREASE value, as it "
                                  "is in the capture")
    repeated = [kind for kind, count in Counter(mine_raw).items() if count > 1]
    if repeated:
        notes["repeated type"] = ("UNEXPECTED -- %s sent more than once "
                                  "(RFC 8446, section 4.2)"
                                  % _and("0x%04x" % kind for kind in repeated))

    # Every extension's payload, so "same list" cannot hide a wrong body.
    byte_for_byte = greased_alike = 0
    real = [kind for kind in theirs if kind != GREASED]
    for ext_type in real:
        a, b = ours.extension(ext_type), captured.extension(ext_type)
        if a is None or b is None:
            continue    # the extensions line names it
        name = extension_name(ext_type)
        sizes = (len(a.data), len(b.data))
        if a.data == b.data:
            byte_for_byte += 1
        elif ext_type == EXT_ENCRYPTED_CLIENT_HELLO:
            note, difference = _ech_note(a.data, b.data, drawn.get(name))
            notes[name] = note
            if difference:
                excused += difference
                excusing.append(name)
        elif name in MUST_DIFFER:
            # key_share's groups and key sizes are not random; the rest of a
            # field drawn per connection is, apart from its size.
            if (ext_type in RESHAPED
                    and shape(ext_type, a.data) != shape(ext_type, b.data)):
                notes[name] = "UNEXPECTED -- " + RESHAPED[ext_type] + (
                    " (%d bytes, %d in the capture)" % sizes
                    if sizes[0] != sizes[1] else "")
            elif sizes[0] != sizes[1]:
                notes[name] = resized(name, *sizes)
            else:
                notes[name] = "must (%s)" % MUST_DIFFER[name]
        elif shape(ext_type, a.data) == shape(ext_type, b.data):
            greased_alike += 1      # the same list, once GREASE is normalised
        else:
            # Fixed bytes cannot change size without changing content, and
            # content that differs fails whatever DRAWN says.
            what = RESHAPED.get(ext_type)
            if what:
                notes[name] = "UNEXPECTED -- " + what + (
                    " (%d bytes, %d in the capture)" % sizes
                    if sizes[0] != sizes[1] else "")
            elif sizes[0] != sizes[1]:
                notes[name] = "UNEXPECTED -- %d bytes, %d in the capture" % sizes
            else:
                notes[name] = "UNEXPECTED -- investigate"

    # The whole hello may differ in size only by what DRAWN excused.
    size = len(ours.raw) - (5 if _record_version(ours) and not headed else 0)
    real_size = len(captured.raw)
    if size == real_size:
        size_note = ""
    elif size - real_size == excused:
        size_note = "   drawn (%s)" % _and(excusing)
    else:
        size_note = "   UNEXPECTED -- investigate"

    print("$ pybrws verify --local --profile %s%s%s\n"
          % (profile_name, " --capture %s" % capture if capture else "",
             " --hostname %s" % hostname if given else ""))
    print("capture  %s" % capture_name)
    print("sni      %s   (%s)" % (hostname, "given with --hostname" if given
                                  else "taken from the capture"))
    if not headed:
        print("record   none in the capture: the record version is not "
              "compared, and our 5-byte header is left out of our size")
    print("ours     %d bytes%s" % (size, size_note))
    print("real     %d bytes" % real_size)
    print()

    rows = [("version", ""), ("random", ""),
            ("session_id", "%d bytes each" % len(captured.session_id)),
            ("cipher suites", _counted(real_suites)),
            ("extensions", _counted(theirs))]
    width = max(len(name) for name, _ in rows) + 2
    for name, note in rows:
        if name not in notes:
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
    # twice.
    if notes:
        print()
    for name, note in notes.items():
        print("%-*s %s   %s"
              % (width, (name + " ").ljust(width, "."), "differs", note))

    computed = ja4_tool.compute(ours, set())
    reference = ja4_tool.compute(captured, set())
    print()
    print("ja4  %s" % computed["ja4"])
    print("     %s" % ("same string as the capture"
                       if computed["ja4"] == reference["ja4"]
                       else "DIFFERS from the capture: " + reference["ja4"]))

    bad = (size_note.strip().startswith("UNEXPECTED")
           or any(note.startswith("UNEXPECTED") for note in notes.values())
           or computed["ja4"] != reference["ja4"])
    if bad:
        print("\nSomething differs that should not. Not a pass.")
    return 1 if bad else 0


def _ech_note(data: bytes, real: bytes, lengths) -> tuple[str, int]:
    """The greased ECH's line, and the size difference DRAWN excused in it.

    Its random parts are free; its outer type, KDF, enc length and payload
    length are compared, the payload length against DRAWN's lengths when
    the profile gives them.
    """
    header, real_header = ech_header(data), ech_header(real)
    if header is None or real_header is None:
        if len(data) == len(real):
            return "must (%s)" % MUST_DIFFER["encrypted_client_hello"], 0
        return ("UNEXPECTED -- %d bytes, %d in the capture"
                % (len(data), len(real)), 0)
    wrong = ["%s %s, %s in the capture" % (field, ECH_FORMATS[field]
                                           % header[field],
                                           ECH_FORMATS[field]
                                           % real_header[field])
             for field in ("outer type", "KDF", "enc length")
             if header[field] != real_header[field]]
    payload, real_payload = header["payload length"], real_header["payload length"]
    difference = 0
    if payload != real_payload:
        if lengths and payload in lengths and real_payload in lengths:
            difference = payload - real_payload
        else:
            wrong.append("payload length %d, %d in the capture%s"
                         % (payload, real_payload,
                            ", not both in %s" % (tuple(lengths),)
                            if lengths else ""))
    if wrong:
        return "UNEXPECTED -- ECH header: " + "; ".join(wrong), 0
    if difference:
        return ("drawn (payload length drawn from %s)"
                % ", ".join(str(n) for n in lengths)), difference
    return "must (%s)" % MUST_DIFFER["encrypted_client_hello"], 0


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
