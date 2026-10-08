#!/usr/bin/env python3
"""Which hosts actually serve HTTP/3, and is a transport comparison possible?

Run this before `ab_test.py --arms pybrws pybrws-h3 httpx`. If no target
serves h3, the transport experiment does not exist and the A/B would spend
minutes producing a column of connection errors.

    python tools/h3_probe.py
    python tools/h3_probe.py --targets www.zillow.com cloudflare-quic.com

Each host is probed by connecting, never by reading a header. Alt-Svc is
advertising, not service: tls.peet.ws advertises h3 and then fails the
handshake, which cost an afternoon once. The `advert` column is printed
anyway, because a host that advertises h3 and refuses to serve it is more
interesting than one that does neither.

Timeouts are deliberately short. The point is a yes or no per host, and a
slow answer here is a no for the purposes of the experiment that follows.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pybrws.h3 as h3
from pybrws.client import get

DEFAULT_TARGETS = [
    "www.zillow.com",
    "www.ticketmaster.com",
    "www.indeed.com",
    "www.g2.com",
    "www.etsy.com",
    "www.crunchbase.com",
    # Known-good, so a run where every column fails is visibly a local
    # problem rather than a finding about the targets.
    "cloudflare-quic.com",
]


def as_url(target: str) -> str:
    return target if "://" in target else "https://" + target + "/"


def over_h2(target: str, timeout: float) -> tuple[str, str]:
    """Status over TCP, and whether the response advertises h3."""
    try:
        response = get(as_url(target), timeout=timeout,
                       follow_redirects=5)
    except Exception as exc:
        return type(exc).__name__[:14], "?"
    advertised = (response.header("alt-svc") or "")
    return str(response.status), "yes" if "h3" in advertised else "no"


def over_h3(target: str, timeout: float) -> str:
    try:
        return str(h3.get(as_url(target), timeout=timeout).status)
    except Exception as exc:
        return type(exc).__name__[:24]


def verdict(h2: str, advert: str, h3_result: str) -> str:
    served = h3_result.isdigit()
    if served and h2.isdigit():
        return "both -- usable in the A/B"
    if served:
        return "h3 only"
    if advert == "yes":
        return "advertises h3, did not serve it"
    return "no h3"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--pause", type=float, default=1.0,
                        help="seconds between hosts, to stay polite")
    args = parser.parse_args()

    width = max(len(t) for t in args.targets) + 2
    print("host".ljust(width) + "h2".ljust(10) + "advert".ljust(9)
          + "h3".ljust(26) + "verdict", flush=True)

    usable = 0
    for target in args.targets:
        h2, advert = over_h2(target, args.timeout)
        h3_result = over_h3(target, args.timeout)
        reading = verdict(h2, advert, h3_result)
        if reading.startswith("both"):
            usable += 1
        print(target.ljust(width) + h2.ljust(10) + advert.ljust(9)
              + h3_result.ljust(26) + reading, flush=True)
        time.sleep(args.pause)

    print()
    if usable == 0:
        print("No target serves HTTP/3 over both transports, so there is no "
              "transport comparison to run.")
    else:
        print("%d of %d reachable over both transports. Those are the hosts "
              "where\n`ab_test.py --arms pybrws pybrws-h3 httpx` can say "
              "anything." % (usable, len(args.targets)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
