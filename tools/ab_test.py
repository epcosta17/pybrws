#!/usr/bin/env python3
"""Compare this client against a plain one across targets, and keep the log.

Scored protections answer the same request differently from one minute to the
next, so a single observation says nothing and "it works now" is not a result.
This runs interleaved rounds, reports pass rates rather than verdicts, and
appends every sample to a JSONL file so a change next week is visible as a
change rather than a surprise.

    python tools/ab_test.py
    python tools/ab_test.py --rounds 10 --targets www.zillow.com www.etsy.com
    python tools/ab_test.py --history
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pybrws.client import get  # noqa: E402
from pybrws.profiles import firefox157  # noqa: E402

LOG = ROOT / "fixtures" / "ab-test-log.jsonl"

# A control that serves both clients belongs in every run: without it, a table
# of pybrws 200s cannot be told apart from a target that blocks nobody.
DEFAULT_TARGETS = [
    "www.zillow.com",
    "www.ticketmaster.com",
    "www.indeed.com",
    "www.g2.com",
    "www.etsy.com",
    "https://www.etsy.com/?q=",
    "https://www.etsy.com/c/jewelry",
    "www.crunchbase.com",
]
CONTROL = "www.crunchbase.com"


# Both clients follow redirects: the question is whether the page arrives,
# and a 3xx counted as success would hide a block one hop later.
MAX_REDIRECTS = 5


def as_url(target: str) -> str:
    """Accept either a bare host or a full URL, so paths can be compared."""
    return target if "://" in target else "https://" + target + "/"


def via_pybrws(target: str, timeout: float) -> int:
    return get(as_url(target), timeout=timeout,
               follow_redirects=MAX_REDIRECTS).status


def via_baseline(target: str, timeout: float) -> int:
    import httpx

    with httpx.Client(timeout=timeout, http2=True, follow_redirects=True,
                      max_redirects=MAX_REDIRECTS) as client:
        return client.get(as_url(target)).status_code


CLIENTS = {"pybrws": via_pybrws, "httpx": via_baseline}


def blocked(status) -> bool:
    return status in (403, 429, 503)


def run(targets: list[str], rounds: int, timeout: float, pause: float) -> list[dict]:
    samples = []
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for round_no in range(rounds):
        # Interleaving matters: drift during a run then hits every cell, not
        # whichever client happens to be measured last.
        for target in targets:
            for name, call in CLIENTS.items():
                try:
                    status = call(target, timeout)
                    error = None
                except Exception as exc:
                    status = None
                    error = type(exc).__name__
                samples.append(
                    {
                        "run": started,
                        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "round": round_no,
                        "host": target,
                        "client": name,
                        "status": status,
                        "error": error,
                        "profile": firefox157.NAME,
                    }
                )
                print(".", end="", flush=True)
                time.sleep(pause)
    print()
    return samples


def summarise(samples: list[dict]) -> None:
    grouped = defaultdict(list)
    for sample in samples:
        grouped[(sample["host"], sample["client"])].append(
            sample["status"] if sample["status"] is not None else sample["error"]
        )

    hosts = sorted({host for host, _ in grouped})
    width = max(len(h) for h in hosts) + 2
    print()
    print("host".ljust(width) + "pybrws".ljust(26) + "httpx".ljust(26) + "reading")
    for host in hosts:
        cells = {}
        for client in CLIENTS:
            results = grouped.get((host, client), [])
            served = sum(1 for r in results if isinstance(r, int) and not blocked(r))
            cells[client] = (served, len(results), results)

        rendered = []
        for client in CLIENTS:
            served, total, results = cells[client]
            spread = "" if len(set(map(str, results))) == 1 else " flapping"
            rendered.append(("%d/%d served%s" % (served, total, spread)).ljust(26))

        p_served, p_total, _ = cells["pybrws"]
        b_served, b_total, _ = cells["httpx"]
        if host == CONTROL:
            reading = "control"
        elif p_total and b_total and p_served == p_total and b_served == 0:
            reading = "pybrws passes, baseline blocked"
        elif p_served > b_served:
            reading = "pybrws better, not deterministic"
        elif p_served == b_served:
            reading = "no difference"
        else:
            reading = "baseline better"
        print(host.ljust(width) + "".join(rendered) + reading)


def show_history() -> None:
    if not LOG.exists():
        raise SystemExit("no log at " + str(LOG))
    runs = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for line in LOG.read_text(encoding="utf-8").splitlines():
        sample = json.loads(line)
        cell = runs[sample["run"]][(sample["host"], sample["client"])]
        cell[1] += 1
        if sample["status"] is not None and not blocked(sample["status"]):
            cell[0] += 1
    for started in sorted(runs):
        print(started)
        for (host, client), (served, total) in sorted(runs[started].items()):
            print("    %-24s %-8s %d/%d served" % (host, client, served, total))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=25.0)
    parser.add_argument("--pause", type=float, default=1.0,
                        help="seconds between requests, to stay polite")
    parser.add_argument("--no-log", action="store_true")
    parser.add_argument("--history", action="store_true",
                        help="summarise past runs and exit")
    args = parser.parse_args()

    if args.history:
        show_history()
        return 0

    targets = list(args.targets)
    if CONTROL not in targets:
        targets.append(CONTROL)

    samples = run(targets, args.rounds, args.timeout, args.pause)
    summarise(samples)

    if not args.no_log:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open("a", encoding="utf-8") as handle:
            for sample in samples:
                handle.write(json.dumps(sample) + "\n")
        print()
        print("%d samples appended to %s" % (len(samples), LOG))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
