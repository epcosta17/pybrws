#!/usr/bin/env python3
"""What did each transport actually receive? Not just the status code.

`ab_test.py` scores a host on its status, which is the right unit for
counting but cannot see a soft block: a challenge page, a cookie wall or a
"we detected unusual activity" notice is an ordinary 200 and gets counted as
served. Any finding that rests on a status deserves one look at the body
before it is believed.

    python tools/show_transport.py www.indeed.com
    python tools/show_transport.py www.indeed.com --save

Prints, for TCP and for QUIC: the final URL after redirects, the status, the
body size, the <title>, and whether anything in the page looks like a block
rather than a page. --save writes both bodies next to each other so they can
be diffed by eye.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import urljoin

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import pybrws.h3 as h3
from pybrws.client import get

MAX_REDIRECTS = 5

# Phrases that appear on an interstitial rather than on the page asked for.
# Matching one is a reason to look, never a verdict on its own: plenty of
# ordinary pages contain the word "robot".
SUSPECT = [
    "unusual activity", "are you a robot", "verify you are human",
    "checking your browser", "enable javascript", "access denied",
    "captcha", "cf-challenge", "px-captcha", "incident id",
    "request blocked", "suspicious activity",
]


def follow(fetch, url: str, timeout: float):
    """Walk redirects by hand so both transports do the same thing."""
    hops = [url]
    response = None
    for _ in range(MAX_REDIRECTS + 1):
        response = fetch(url, timeout=timeout)
        if not 300 <= response.status < 400:
            return response, hops
        location = response.header("location")
        if not location:
            return response, hops
        url = urljoin(url, location)
        hops.append(url)
    return response, hops


def describe(label: str, response, hops, save: str | None) -> None:
    body = response.body or b""
    text = body.decode("utf-8", "replace")
    title = re.search(r"<title[^>]*>(.*?)</title>", text,
                      re.I | re.S)
    hits = sorted({p for p in SUSPECT if p in text.lower()})

    print("  %-14s %s" % ("status", response.status))
    print("  %-14s %s" % ("final url", hops[-1]))
    if len(hops) > 1:
        for hop in hops[1:]:
            print("  %-14s %s" % ("  via", hop))
    print("  %-14s %d bytes" % ("body", len(body)))
    print("  %-14s %s" % ("title", (title.group(1).strip()[:70]
                                    if title else "(none)")))
    print("  %-14s %s" % ("looks like",
                          "a block? " + ", ".join(hits) if hits
                          else "an ordinary page"))
    if save:
        out = REPO / ("%s-%s.html" % (save, label))
        out.write_bytes(body)
        print("  %-14s %s" % ("saved", out))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--save", nargs="?", const="transport", default=None,
                        metavar="PREFIX",
                        help="write both bodies to PREFIX-h2.html and "
                             "PREFIX-h3.html for diffing")
    args = parser.parse_args()

    url = args.target
    if "://" not in url:
        url = "https://" + url + "/"

    for label, fetch in (("h2", lambda u, timeout: get(
                              u, timeout=timeout, follow_redirects=0)),
                         ("h3", h3.get)):
        print("%s over %s" % (url, label))
        try:
            response, hops = follow(fetch, url, args.timeout)
        except Exception as exc:
            print("  %-14s %s: %s" % ("failed", type(exc).__name__, exc))
            print()
            continue
        describe(label, response, hops, args.save)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
