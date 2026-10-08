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
import re
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


# A JA4 of any transport: t13d1517h2_8daaf6152771_3cbfd9057e0d and friends.
JA4ISH = re.compile(r"^[a-z0-9]{6,14}_[0-9a-f]{12}(_[0-9a-f]{12})*$")


def strings(value):
    """Every string anywhere in a row, for when the key names are not ours."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for inner in value.values():
            yield from strings(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from strings(inner)


def integers(value):
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        yield value
    elif isinstance(value, dict):
        for inner in value.values():
            yield from integers(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from integers(inner)


def folded(row):
    """The row with lower-cased keys.

    This service answers in PascalCase -- Key, Count, FPID, FirstSeen --
    and the first version looked only for lower-case names, so it found
    neither and fell back to guessing. Case is not a schema.
    """
    if not isinstance(row, dict):
        return {}
    return {str(k).lower(): v for k, v in row.items()}


def value_of(row) -> str:
    """The fingerprint, by name if the name is one we know, else by shape."""
    if isinstance(row, str):
        return row
    flat = folded(row)
    for key in ("key", "value", "fingerprint", "ja4", "fp", "name"):
        if isinstance(flat.get(key), str) and flat[key]:
            return flat[key]
    for text in strings(row):
        if JA4ISH.match(text):
            return text
    return "?"


def count_of(row) -> int:
    flat = folded(row)
    for key in ("count", "sessions", "observations", "clients", "n",
                "total", "hits"):
        if isinstance(flat.get(key), int) and not isinstance(flat[key], bool):
            return flat[key]
    # Deliberately no fall back to "the largest integer in the row". The
    # first version did, and picked each fingerprint's dimension id, which
    # is of the same magnitude as a count and is not one. Unknown is a
    # better answer than a plausible wrong number.
    return 0


def sorted_by_count(counts: list[int]) -> bool:
    """An endpoint called `top` returns its rows ranked.

    So if the field we read is not non-increasing down the list, we are
    reading the wrong field, and the service's own ordering is what says
    so. This is the check the first version lacked.
    """
    present = [n for n in counts if n]
    return all(a >= b for a, b in zip(present, present[1:]))


def seen(row) -> tuple[str, str]:
    """First and last observation, trimmed to the day.

    Worth printing for its own sake: a fingerprint first seen months ago is
    a population, and one first seen today might be nothing but our own
    visit arriving in someone else's database.
    """
    flat = folded(row)
    def day(key):
        text = flat.get(key)
        return text[:10] if isinstance(text, str) and len(text) >= 10 else "?"
    return day("firstseen"), day("lastseen")


def explain(row) -> None:
    """Print what actually came back, rather than a column of question marks.

    Guessing another service's field names and then rendering "?" when the
    guess misses is how a tool reports a schema change as data. The shape
    goes on screen instead.
    """
    print("\nCould not read the ranked rows. The first one looks like:\n")
    print("    " + json.dumps(row, indent=2, sort_keys=True)
          .replace("\n", "\n    "))
    print("\nRe-run with --json for the whole response, or add the right "
          "key\nnames to value_of/count_of in this file.")


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
    print("%s -- %d ranked values" % (url, len(ranked)))

    if ranked and value_of(ranked[0]) == "?":
        explain(ranked[0])
        return 1

    counts = [count_of(r) for r in ranked]
    if not any(counts) or not sorted_by_count(counts):
        print("\nThe field being read as a count is %s."
              % ("missing" if not any(counts)
                 else "not ranked, so it is not the count"))
        explain(ranked[0])
        return 1

    total = sum(counts) or 1
    print()

    print("%-5s %-38s %9s %7s  %-10s %-10s"
          % ("rank", "value", "count", "share", "first seen", "last seen"))
    for index, row in enumerate(ranked[:args.limit], 1):
        value, count = value_of(row), count_of(row)
        first, last = seen(row)
        mark = "*" if value in OURS else " "
        print("%s%-4d %-38s %9d %6.2f%%  %-10s %-10s"
              % (mark, index, value, count, 100.0 * count / total,
                 first, last))

    wanted = args.rank or list(OURS)
    print("\nwhere the values this project presents sit:")
    index = {value_of(r): (i, count_of(r), seen(r))
             for i, r in enumerate(ranked, 1)}
    for value in wanted:
        label = OURS.get(value, "")
        if value in index:
            place, count, (first, last) = index[value]
            print("  %-38s rank %-4d %8d %6.2f%%  since %s  %s"
                  % (value, place, count, 100.0 * count / total,
                     first, label))
        else:
            print("  %-38s not in the top %-4d %26s %s"
                  % (value, len(ranked), "", label))

    print("\nThe population here is whoever connects to a fingerprinting\n"
          "observatory, so these shares describe that traffic and not the\n"
          "web. Use them to choose between two arms of the same browser,\n"
          "which is what they are good for, and not as a claim about how\n"
          "common any browser is.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
