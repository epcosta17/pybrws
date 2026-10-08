#!/usr/bin/env python3
"""Compare this client's fingerprint against a reference capture.

Two modes, because they answer different questions.

`--local` diffs the hello this client builds against the captured bytes in
fixtures/, field by field, with no network at all. That is the one to reach
for: it is instant, it needs nothing to be reachable, and it shows which
fields match and which cannot match -- the random, the session id, the
key_share and the greased ECH payload are all freshly generated, so a clone
that reproduced them byte for byte would be broken rather than good.

Without it, this fetches tls.peet.ws/api/all and diffs every fingerprint
field against fixtures/reference-firefox-157-peet.json. A third party is
worth asking, but that one advertises HTTP/3 and does not serve it, and has
been unreachable often enough that a demo should not depend on it. For an
outside reading prefer tools/probe_fingerprint.py.

    python tools/verify.py --local
    python tools/verify.py --local --profile chrome155
    python tools/verify.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(ROOT / "tools"))

from pybrws.emitter import build_client_hello  # noqa: E402
from pybrws.handshake import connect  # noqa: E402
from pybrws.hexio import load_hex  # noqa: E402
from pybrws.http2 import Http2Connection  # noqa: E402
from pybrws.model import GREASE_VALUES, extension_name  # noqa: E402
from pybrws.parser import parse_client_hello  # noqa: E402
from pybrws.profiles import firefox157  # noqa: E402

REFERENCE = ROOT / "fixtures" / "reference-firefox-157-peet.json"
HOST = "tls.peet.ws"
PATH = "/api/all"

CAPTURES = {
    "firefox157": "reference-firefox-157-windows-fresh.hex",
    "chrome155": "chrome-1.hex",
}

# Fields that are freshly generated per connection. A clone that reproduced
# these would not be a better clone, it would be a broken one: the key_share
# carries a real keypair whose private half the server's answer is useless
# without, and a replayed random defeats the handshake's own replay
# protection. So they are reported as differing on purpose, and it is the
# only honest way to show a byte comparison of a live handshake.
MUST_DIFFER = {
    "random": "32 fresh random bytes",
    "session_id": "32 fresh random bytes",
    "key_share": "a real keypair",
    "encrypted_client_hello": "greased payload",
    "padding": "sized to whatever precedes it",
}

# A profile that models a browser which varies cannot be checked for byte
# identity against one capture, and pretending otherwise would report the
# model working as the model failing. Chrome draws its extension order per
# connection and carries a greased value at the head of six separate lists,
# so those lists differ by design and the total length moves with the ECH
# payload size. Firefox varies in nothing but the four fields above.
DRAWN = {
    "chrome155": {
        "extensions": "order drawn per connection",
        "supported_groups": "greased value at the head",
        "supported_versions": "greased value at the head",
        "signature_algorithms": "greased value at the head",
        "cipher suites": "greased value at the head",
        "length": "ECH payload length drawn from 144, 208, 240",
    },
    "firefox157": {},
}


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


def local(profile_name: str, hostname: str | None) -> int:
    """Diff the built hello against the captured one, offline."""
    import importlib
    import ja4 as ja4_tool

    profile = importlib.import_module("pybrws.profiles." + profile_name)
    capture_path = ROOT / "fixtures" / CAPTURES[profile_name]
    captured = parse_client_hello(load_hex(capture_path))
    hostname = hostname or sni_of(captured)
    ours = parse_client_hello(build_client_hello(hostname, profile=profile))

    print("$ python tools/verify.py --local --profile %s\n" % profile_name)
    print("capture  %s" % capture_path.name)
    print("sni      %s   (taken from the capture)" % hostname)
    drawn = DRAWN.get(profile_name, {})
    same_length = len(ours.raw) == len(captured.raw)
    print("ours     %d bytes%s" % (len(ours.raw),
          "" if same_length or "length" not in drawn
          else "   drawn (%s)" % drawn["length"]))
    print("real     %d bytes" % len(captured.raw))
    print()

    rows: list[tuple[str, bool, str]] = [
        ("version", ours.legacy_version == captured.legacy_version, ""),
        ("random", ours.random == captured.random, ""),
        ("session_id", ours.session_id == captured.session_id,
         "%d bytes each" % len(captured.session_id)),
    ]

    def strip(values):
        return [v for v in values if v not in GREASE_VALUES]

    same_suites = strip(ours.cipher_suites) == strip(captured.cipher_suites)
    rows.append(("cipher suites", same_suites,
                 "%d, same order" % len(strip(captured.cipher_suites))))

    mine = [e.type for e in ours.extensions]
    theirs = [e.type for e in captured.extensions]
    greased = sum(1 for t in theirs if t in GREASE_VALUES)
    rows.append(("extensions", strip(mine) == strip(theirs),
                 "%d, same order%s" % (len(strip(theirs)),
                                       ", %d greased" % greased if greased
                                       else "")))

    # Every extension's payload, so "same list" cannot hide a wrong body.
    differing = []
    for ext_type in strip(theirs):
        a, b = ours.extension(ext_type), captured.extension(ext_type)
        if a is None or b is None or a.data != b.data:
            differing.append(ext_type)
    # Always reported, with the count, because "payloads match" next to a
    # list of differing payloads is a contradiction and the number is the
    # more useful fact anyway.
    total = len(strip(theirs))
    matched = total - len(differing)

    width = max(len(name) for name, _, _ in rows) + 2
    expected, unexpected = [], []
    for name, ok, note in rows:
        line = "%-*s %s   %s" % (width, (name + " ").ljust(width, "."),
                                 "match" if ok else "differs", note)
        (expected if ok else unexpected).append(line.rstrip())

    for line in expected:
        print(line)
    # A count, not a verdict: the payloads that differ are listed below with
    # the reason each one has to, so "match" or "differs" here would be
    # either a contradiction or a repetition.
    print("%-*s %d of %d   byte for byte"
          % (width, "payloads ".ljust(width, "."), matched, total))

    # One line per differing field, whether it came from the fixed rows or
    # from an extension payload. Printed in one place so nothing appears
    # twice, which the first version did for random and session_id.
    changed = [name for name, ok, _ in rows if not ok]
    changed += [extension_name(t) for t in differing]
    if changed:
        print()
    for name in dict.fromkeys(changed):
        why = MUST_DIFFER.get(name)
        if why:
            note = "must (%s)" % why
        elif name in drawn:
            note = "drawn (%s)" % drawn[name]
        else:
            note = "UNEXPECTED -- investigate"
        print("%-*s %s   %s"
              % (width, (name + " ").ljust(width, "."), "differs", note))

    computed = ja4_tool.compute(ours, set())
    reference = ja4_tool.compute(captured, set())
    print()
    print("ja4  %s" % computed["ja4"])
    print("     %s" % ("same string as the capture"
                       if computed["ja4"] == reference["ja4"]
                       else "DIFFERS from the capture: " + reference["ja4"]))

    allowed = set(MUST_DIFFER) | set(drawn)
    surprises = [t for t in differing if extension_name(t) not in allowed]
    surprises += [name for name, ok, _ in rows
                  if not ok and name not in allowed]
    bad = surprises or computed["ja4"] != reference["ja4"]
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="dump the full report")
    parser.add_argument("--local", action="store_true",
                        help="diff against the captured bytes, no network")
    parser.add_argument("--profile", default="firefox157",
                        choices=sorted(CAPTURES))
    parser.add_argument("--hostname", default=None,
                        help="goes in server_name; the capture's own host, "
                             "so the SNI payload can be compared too")
    args = parser.parse_args()

    if args.local:
        return local(args.profile, args.hostname)

    reference = json.loads(REFERENCE.read_text(encoding="utf-8"))
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
