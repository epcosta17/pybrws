#!/usr/bin/env python3
"""What does a third party see when we connect? Over TCP and over QUIC.

Every other oracle in this repo is one we run ourselves: catch_hello.py,
catch_h2.py and catch_quic.py are our own servers reporting what arrived.
That is the better instrument -- it sees the whole hello, not a hash -- but
it cannot tell us whether the thing on the wire survives a real network
path, a real CDN and somebody else's parser.

thumbprint.me publishes an endpoint that reflects the caller's own
fingerprints as JSON, and it serves HTTP/3, which makes it the first
external oracle that can be asked the QUIC question at all. tls.peet.ws
advertises h3 and fails the handshake; browserleaks did not serve h3 to us.

    python tools/probe_fingerprint.py
    python tools/probe_fingerprint.py --profile chrome155
    python tools/probe_fingerprint.py --json

Prints every field the service returns, with the TCP answer and the QUIC
answer side by side and the differing rows marked. Expect them to differ in
more than the transport: the QUIC profile is a separate measurement with its
own cipher list, extension order and header order, so a row that differs is
not evidence that QUIC as such caused it.

Fields are discovered, not assumed. The service's schema is not ours and
may change; whatever it sends is what gets printed.
"""

from __future__ import annotations

import argparse
import importlib
import json as jsonlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import pybrws.h3 as h3
from pybrws.client import get

DEFAULT_URL = "https://thumbprint.me/api/v1/probe"

# Rows worth reading first, in this order. Anything the service returns that
# is not listed here still gets printed, below these, in its own order.
INTERESTING = [
    "ja4", "ja4_r", "ja4h", "ja4t", "ja4ts", "ja4x", "ja4l",
    "quic", "ja4q", "http", "protocol", "alpn", "tls", "client",
]


def flatten(value, prefix: str = "") -> dict[str, str]:
    """JSON to a flat {dotted.path: printable} map, so two trees can be
    compared row by row without knowing either one's shape."""
    rows: dict[str, str] = {}
    if isinstance(value, dict):
        for key, inner in value.items():
            rows.update(flatten(inner, "%s.%s" % (prefix, key) if prefix
                                else str(key)))
    elif isinstance(value, list):
        if value and all(not isinstance(v, (dict, list)) for v in value):
            rows[prefix] = ", ".join(str(v) for v in value)
        else:
            for index, inner in enumerate(value):
                rows.update(flatten(inner, "%s[%d]" % (prefix, index)))
    else:
        rows[prefix] = "" if value is None else str(value)
    return rows


def rank(path: str) -> tuple[int, str]:
    """Sort key putting the fingerprint fields at the top."""
    head = path.split(".")[0].split("[")[0].lower()
    for index, name in enumerate(INTERESTING):
        if head == name:
            return (index, path)
    return (len(INTERESTING), path)


def fetch(label: str, url: str, profile, timeout: float):
    """Return the parsed body, or None having said why not."""
    try:
        if label == "quic":
            response = h3.get(url, timeout=timeout)
        else:
            response = get(url, timeout=timeout, profile=profile,
                           follow_redirects=3)
    except Exception as exc:
        print("  %-6s failed: %s: %s" % (label, type(exc).__name__, exc))
        return None

    print("  %-6s %s %s, %d bytes" % (label, response.status,
                                      response.http_version or "?",
                                      len(response.body or b"")))
    if response.status != 200:
        print("         not a 200, so there is nothing to read off it")
        return None
    try:
        return response.json()
    except Exception:
        text = (response.body or b"").decode("utf-8", "replace")
        print("         body is not JSON: %r" % text[:200])
        return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--profile", default="firefox157",
                        help="the TCP arm's profile. The QUIC arm always "
                             "uses firefox157_quic; it is the only one "
                             "measured over QUIC.")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--json", action="store_true",
                        help="dump both raw responses instead of a table")
    parser.add_argument("--full", action="store_true",
                        help="one block per field, nothing truncated. The "
                             "columns cut off exactly the rows worth "
                             "reading: the sorted cipher lists, the header "
                             "order, and which real browsers share each "
                             "fingerprint.")
    parser.add_argument("--only", choices=["tcp", "quic"],
                        help="ask over one transport only")
    args = parser.parse_args()

    profile = importlib.import_module("pybrws.profiles." + args.profile)

    wanted = [args.only] if args.only else ["tcp", "quic"]
    print("%s\n  %-6s %s\n  %-6s firefox157_quic\n"
          % (args.url, "tcp", args.profile, "quic"))

    seen = {}
    for label in wanted:
        body = fetch(label, args.url, profile, args.timeout)
        if body is not None:
            seen[label] = body
    print()

    if not seen:
        print("Neither transport came back with a fingerprint. That is a "
              "result about reachability, not about our hellos.")
        return 1

    if args.json:
        for label, body in seen.items():
            print("--- %s ---" % label)
            print(jsonlib.dumps(body, indent=2, sort_keys=True))
            print()
        return 0

    tables = {label: flatten(body) for label, body in seen.items()}
    paths = sorted({p for t in tables.values() for p in t}, key=rank)
    width = min(max((len(p) for p in paths), default=10), 28)

    if len(tables) == 1:
        label, table = next(iter(tables.items()))
        for path in paths:
            print("%-*s  %s" % (width, path[:width], table.get(path, "")))
        return 0

    tcp, quic = tables.get("tcp", {}), tables.get("quic", {})

    if args.full:
        for path in paths:
            left, right = tcp.get(path, "--"), quic.get(path, "--")
            print("%s%s" % ("* " if left != right else "  ", path))
            print("    tcp   %s" % left)
            print("    quic  %s" % right)
        return 0

    print("%-*s  %-38s %-38s" % (width, "field", "over tcp", "over quic"))
    differing = 0
    for path in paths:
        left, right = tcp.get(path, "--"), quic.get(path, "--")
        mark = " " if left == right else "*"
        differing += left != right
        print("%s %-*s  %-38s %-38s" % (mark, width, path[:width],
                                        left[:38], right[:38]))

    print("\n%d of %d fields differ (*). Transport is one of several things "
          "that\ndiffer between the two arms, so a marked row names a "
          "difference and not\nits cause." % (differing, len(paths)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
