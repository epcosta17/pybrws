"""Cross fingerprint against address, so neither can hide behind the other.

Routing one client through a proxy changes two things at once. This crosses
them: pybrws and httpx, each direct and each proxied. Only the full square
says whether a result comes from the protocol fingerprint, from the address,
or from needing both.

    $env:PYBRWS_PROXY = "http://user:pass@exit.example:33335"
    python tools/isolate.py
"""

import os
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pybrws.client import get  # noqa: E402

PROXY = os.environ.get("PYBRWS_PROXY")
if not PROXY:
    raise SystemExit("set PYBRWS_PROXY to a proxy URL first")
TARGETS = [
    "www.glassdoor.com",
    "www.g2.com",
    "www.etsy.com",
    "www.zillow.com",
    "www.crunchbase.com",
]
ROUNDS = 3


def pybrws(url, proxy):
    return get(url, proxy=proxy or False, timeout=30, follow_redirects=5).status


def hx(url, proxy):
    with httpx.Client(timeout=25, http2=True, follow_redirects=True,
                      proxy=proxy or None) as client:
        return client.get(url).status_code


ARMS = [
    ("pybrws direct", pybrws, None),
    ("pybrws proxy", pybrws, PROXY),
    ("httpx direct", hx, None),
    ("httpx proxy", hx, PROXY),
]

results = {(host, label): [] for host in TARGETS for label, _, _ in ARMS}

for round_no in range(ROUNDS):
    for host in TARGETS:
        for label, call, proxy in ARMS:
            try:
                status = call("https://" + host + "/", proxy)
            except Exception as exc:
                status = type(exc).__name__[:9]
            results[(host, label)].append(status)
            time.sleep(0.5)
    print("round %d of %d done" % (round_no + 1, ROUNDS), flush=True)


def served(runs):
    return sum(1 for s in runs if isinstance(s, int) and s not in (403, 429, 503))


print()
print("target".ljust(22) + "".join(label.ljust(16) for label, _, _ in ARMS))
for host in TARGETS:
    cells = "".join(
        ("%d/%d" % (served(results[(host, label)]), ROUNDS)).ljust(16)
        for label, _, _ in ARMS
    )
    print(host.ljust(22) + cells)

print()
for host in TARGETS:
    print(host)
    for label, _, _ in ARMS:
        print("    %-14s %s" % (label, results[(host, label)]))
