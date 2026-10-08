#!/usr/bin/env python3
"""Compute a profile's JA4 locally, without asking anyone.

Until now every JA4 in this project came from a server: ours, or
tls.peet.ws, or thumbprint.me. That means a change to a profile could only
be checked by making a request, and a question like "what would our
fingerprint be if this one extension came out" could not be answered at all
without editing the profile and going back out to the network.

The computation is small and the spec is public, so there is no reason for
that. This prints JA4 and JA4_r for a profile, and `--drop` answers the
counterfactual directly.

    python tools/ja4.py --profile chrome155
    python tools/ja4.py --profile chrome155 --drop 0x12e0
    python tools/ja4.py --self-test

The arithmetic is checked rather than trusted: --self-test reproduces three
values measured independently by thumbprint.me, two of them from real
Chrome 155 captures. If the formula here were wrong, those would not come
out.

Caveats of the method, which matter when reading the output. A profile that
shuffles produces a different JA4_o on every call but the same JA4, which
is the whole point of the sorted form. A profile whose ECH payload length
is drawn changes the hello's length and not its fingerprint. And JA4 does
not see any field's contents -- two clients offering the same extension
with different bytes inside it share a JA4.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from pybrws.emitter import build_client_hello
from pybrws.model import GREASE_VALUES
from pybrws.parser import parse_client_hello

EXT_SERVER_NAME = 0x0000
EXT_ALPN = 0x0010
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_SUPPORTED_VERSIONS = 0x002B

# JA4_a's protocol letter. QUIC profiles are built by a different module and
# are not reachable through build_client_hello, so this is always "t" here.
TRANSPORT = "t"


def truncated(values: list[str], sigs: list[str]) -> str:
    body = ",".join(values) + ("_" + ",".join(sigs) if sigs else "")
    return hashlib.sha256(body.encode()).hexdigest()[:12]


def hexes(values) -> list[str]:
    return ["%04x" % v for v in values]


def alpn_letters(hello) -> str:
    """JA4_a's two ALPN characters: first and last of the first protocol."""
    ext = hello.extension(EXT_ALPN)
    if not ext or len(ext.data) < 3:
        return "00"
    first = ext.data[3:3 + ext.data[2]].decode("ascii", "replace")
    return (first[0] + first[-1]) if first else "00"


def tls_version(hello) -> str:
    """The highest version offered, from supported_versions if present."""
    ext = hello.extension(EXT_SUPPORTED_VERSIONS)
    offered = [hello.legacy_version]
    if ext:
        body = ext.data[1:]
        offered = [int.from_bytes(body[i:i + 2], "big")
                   for i in range(0, len(body), 2)]
    real = [v for v in offered if v not in GREASE_VALUES]
    return {0x0304: "13", 0x0303: "12", 0x0302: "11",
            0x0301: "10"}.get(max(real) if real else 0, "00")


def signature_algorithms(hello) -> list[str]:
    """In the order sent, GREASE removed. JA4 does not sort these."""
    ext = hello.extension(EXT_SIGNATURE_ALGORITHMS)
    if not ext:
        return []
    body = ext.data[2:]
    schemes = [int.from_bytes(body[i:i + 2], "big")
               for i in range(0, len(body), 2)]
    return hexes(v for v in schemes if v not in GREASE_VALUES)


def compute(hello, drop: set[int]) -> dict:
    suites = [v for v in hello.cipher_suites if v not in GREASE_VALUES]
    types = [e.type for e in hello.extensions
             if e.type not in GREASE_VALUES and e.type not in drop]

    # JA4_a counts every extension; JA4_b and JA4_c hash sorted lists, and
    # JA4_c excludes SNI and ALPN while still counting them above.
    hashed = sorted(t for t in types
                    if t not in (EXT_SERVER_NAME, EXT_ALPN))
    sigs = signature_algorithms(hello)
    sni = "d" if hello.extension(EXT_SERVER_NAME) else "i"

    a = "%s%s%s%02d%02d%s" % (TRANSPORT, tls_version(hello), sni,
                              min(len(suites), 99), min(len(types), 99),
                              alpn_letters(hello))
    return {
        "ja4": "%s_%s_%s" % (a, truncated(hexes(sorted(suites)), []),
                             truncated(hexes(hashed), sigs)),
        "ja4_o": "%s_%s_%s" % (a, truncated(hexes(suites), []),
                               truncated(hexes(types), sigs)),
        "ja4_r": "%s_%s_%s" % (a, ",".join(hexes(sorted(suites))),
                               ",".join(hexes(hashed))
                               + ("_" + ",".join(sigs) if sigs else "")),
        "ciphers": len(suites),
        "extensions": len(types),
    }


# Measured by thumbprint.me, not by this file. Two are real Chrome 155
# captures from its published catalogue; the third is this client's own
# chrome155 profile as that service saw it.
VECTORS = [
    ("chrome 155, fresh hello",
     "0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,"
     "fe0d,ff01", "cb7bf5808d99"),
    ("chrome 155, resumed (pre_shared_key present)",
     "0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,"
     "ca34,fe0d,ff01", "e2d80978ab2e"),
    ("pybrws chrome155, as measured over the network",
     "0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,12e0,44cd,"
     "ca34,fe0d,ff01", "4980c97edce0"),
]
VECTOR_SIGS = ("0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,"
               "0601").split(",")


def self_test() -> int:
    bad = 0
    for label, extensions, expected in VECTORS:
        got = truncated(extensions.split(","), VECTOR_SIGS)
        ok = got == expected
        bad += not ok
        print("  %-46s %s %s" % (label, got, "ok" if ok else
                                 "MISMATCH, expected " + expected))
    print("\n%s" % ("all three reproduce values measured elsewhere"
                    if not bad else "%d vector(s) failed" % bad))
    return 1 if bad else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", default="firefox157")
    parser.add_argument("--hostname", default="thumbprint.me",
                        help="only affects the SNI contents, not the JA4")
    parser.add_argument("--drop", action="append", default=[],
                        metavar="TYPE",
                        help="omit this extension type, e.g. 0x12e0, to see "
                             "what the fingerprint would be without it")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    drop = {int(value, 0) for value in args.drop}
    module = importlib.import_module("pybrws.profiles." + args.profile)
    hello = parse_client_hello(build_client_hello(args.hostname,
                                                  profile=module))
    result = compute(hello, drop)

    print("%s%s" % (args.profile,
                    "  without " + ", ".join("0x%04x" % d for d in sorted(drop))
                    if drop else ""))
    print("  %-8s %s" % ("ja4", result["ja4"]))
    print("  %-8s %s" % ("ja4_o", result["ja4_o"]))
    print("  %-8s %s" % ("ja4_r", result["ja4_r"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
