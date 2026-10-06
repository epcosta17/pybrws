#!/usr/bin/env python3
"""Compare this client's fingerprint against a reference capture.

Fetches tls.peet.ws/api/all and diffs every fingerprint field against
fixtures/reference-firefox-157-peet.json, which was recorded from a real
browser.

    python tools/verify.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pybrws.handshake import connect  # noqa: E402
from pybrws.http2 import Http2Connection  # noqa: E402
from pybrws.profiles import firefox157  # noqa: E402

REFERENCE = ROOT / "fixtures" / "reference-firefox-157-peet.json"
HOST = "tls.peet.ws"
PATH = "/api/all"


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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="dump the full report")
    args = parser.parse_args()

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
