#!/usr/bin/env python3
"""How common is a fingerprint? Which arm of Chrome's trial is the busy one?

Chrome gates TLS extensions behind randomised field trials, so "Chrome
155's ClientHello" is not a value but a distribution over trial arms. This
machine's install joined the arm that sends 0x12e0; a fresh profile does
not. Both are real Chrome. The profile has to pick one, and the only
honest basis for picking is which arm more clients actually present.

thumbprint.me publishes ranked counts per signal at /api/v1/top/{signal},
built from the clients that connect to it rather than from its own
captures — which matters here, because its capture catalogue is CI
containers on fresh profiles and so holds only the control arm.

    python tools/population.py
    python tools/population.py --signal tls --limit 40
    python tools/population.py --rank t13d1518h2_8daaf6152771_4980c97edce0

Read the skew before reading the numbers. The population is whoever visits
a network-fingerprinting observatory: developers, scrapers, CI runners and
people reading about this. It is not the web. It is still the only
measurement of relative frequency available here, and it beats assuming.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from pybrws.client import get

TOP = "https://thumbprint.me/api/v1/top/%s"

# The two arms of the same Chrome 155, as measured on this machine.
OURS = {
    "t13d1518h2_8daaf6152771_4980c97edce0":
        "chrome 155, trial arm with 0x12e0 (this profile, this install)",
    "t13d1517h2_8daaf6152771_cb7bf5808d99":
        "chrome 155, control arm (fresh profiles, their whole catalogue)",
    "q13d0313h3_55b375c5d22e_eb028bd37c08":
        "chrome 155 over QUIC, trial arm",
    "q13d0312h3_55b375c5d22e_178839b6cec1":
        "chrome 155 over QUIC, control arm",
    "t13d1517h2_8daaf6152771_3cbfd9057e0d":
        "firefox 157 (this project's profile)",
    "q13d0315h3_55b375c5d22e_dc5437974b47":
        "firefox 157 over QUIC (this project's profile)",
}


def rows(body) -> list[dict]:
    """Find the ranked list wherever this service keeps it."""
    if isinstance(body, list):
        return body
    for key in ("top", "rows", "items", "results", "data", "fingerprints"):
        if isinstance(body.get(key), list):
            return body[key]
    raise SystemExit("no ranked list in the response; keys are %s"
                     % sorted(body))


def value_of(row) -> str:
    if isinstance(row, str):
        return row
    for key in ("value", "fingerprint", "ja4", "id", "name"):
        if isinstance(row.get(key), str):
            return row[key]
    return "?"


def count_of(row) -> int:
    if isinstance(row, dict):
        for key in ("count", "sessions", "observations", "n", "total"):
            if isinstance(row.get(key), int):
                return row[key]
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--signal", default="tls",
                        help="tls, http, h2, qtp, ja4t, tcp, ua")
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument("--rank", action="append", default=[],
                        metavar="FINGERPRINT",
                        help="report where this value sits; defaults to the "
                             "values this project presents")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    url = TOP % args.signal
    response = get(url, timeout=args.timeout, follow_redirects=3)
    if response.status != 200:
        raise SystemExit("%s returned %s" % (url, response.status))
    body = response.json()
    if args.json:
        print(json.dumps(body, indent=2, sort_keys=True))
        return 0

    ranked = rows(body)
    total = sum(count_of(r) for r in ranked) or 1
    print("%s -- %d ranked values\n" % (url, len(ranked)))

    print("%-5s %-38s %9s %7s" % ("rank", "value", "count", "share"))
    for index, row in enumerate(ranked[:args.limit], 1):
        value, count = value_of(row), count_of(row)
        mark = "*" if value in OURS else " "
        print("%s%-4d %-38s %9d %6.2f%%"
              % (mark, index, value, count, 100.0 * count / total))

    wanted = args.rank or list(OURS)
    print("\nwhere the values this project presents sit:")
    index = {value_of(r): (i, count_of(r))
             for i, r in enumerate(ranked, 1)}
    for value in wanted:
        label = OURS.get(value, "")
        if value in index:
            place, count = index[value]
            print("  %-38s rank %-5d %7d  %6.2f%%  %s"
                  % (value, place, count, 100.0 * count / total, label))
        else:
            print("  %-38s not in the top %-4d %21s %s"
                  % (value, len(ranked), "", label))

    print("\nThe population here is whoever connects to a fingerprinting\n"
          "observatory, so these shares describe that traffic and not the\n"
          "web. Use them to choose between two arms of the same browser,\n"
          "which is what they are good for, and not as a claim about how\n"
          "common any browser is.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
