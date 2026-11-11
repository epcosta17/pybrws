#!/usr/bin/env python3
"""Compare this client against a plain one across targets, and keep the log.

Scored protections answer the same request differently from one minute to the
next, so a single observation says nothing and "it works now" is not a result.
This runs interleaved rounds, reports pass rates rather than verdicts, and
appends every sample to a JSONL file so a change next week is visible as a
change rather than a surprise.

    python tools/ab_test.py
    python tools/ab_test.py --rounds 10 --targets www.zillow.com www.etsy.com
    python tools/ab_test.py --arms pybrws pybrws-h3 httpx
    python tools/ab_test.py --history

With the h3 arm the question changes. pybrws against httpx asks whether the
fingerprint matters; pybrws against pybrws-h3 asks whether the transport
does, and it is the only pair that can, since it is the only one where the
transport is the single variable. The httpx arm earns its place by settling
the prior question: if a plain client is served too, the host is not
discriminating and the other two arms establish nothing either way.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import urljoin

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


PROXY = None  # set from --proxy; None means a direct connection


# Firefox's measured HTTP/2 navigation headers, used by the httpx+ff arm so
# that the one variable between it and the plain httpx arm is the header set.
FIREFOX_HEADERS = list(firefox157.H2_NAVIGATION_HEADERS)


def via_pybrws(target: str, timeout: float):
    response = get(as_url(target), timeout=timeout, proxy=PROXY or False,
                   follow_redirects=MAX_REDIRECTS)
    return response.status, response.body or b""


def via_baseline(target: str, timeout: float):
    import httpx

    with httpx.Client(timeout=timeout, http2=True, follow_redirects=True,
                      max_redirects=MAX_REDIRECTS) as client:
        response = client.get(as_url(target))
        return response.status_code, response.content


def via_baseline_ff(target: str, timeout: float):
    """httpx carrying Firefox's exact headers, over the OpenSSL TLS stack.

    The plain httpx arm differs from pybrws in two things at once: the
    protocol fingerprint AND the headers (httpx sends its own User-Agent and
    a bare Accept). So a target that serves pybrws and refuses httpx is not
    evidence the *fingerprint* did it -- the headers could have. This arm
    isolates that: same OpenSSL fingerprint as httpx, but Firefox's header
    list. If it is served where plain httpx is refused, the headers were the
    deciding factor and the fingerprint bought nothing on that host; if it is
    refused like plain httpx while pybrws is served, the fingerprint is what
    mattered. Without this arm the A/B credits the fingerprint for both.
    """
    import httpx

    with httpx.Client(timeout=timeout, http2=True, follow_redirects=True,
                      max_redirects=MAX_REDIRECTS) as client:
        url = as_url(target)
        request = client.build_request("GET", url)
        request.headers = httpx.Headers(
            [("host", httpx.URL(url).netloc.decode())] + FIREFOX_HEADERS)
        response = client.send(request, follow_redirects=True)
        return response.status_code, response.content


def via_pybrws_h3(target: str, timeout: float):
    """Same client and same headers as the h2 arm, over QUIC instead.

    This is the arm that answers whether the transport changes the outcome.
    Pairing it against the httpx arm would not: that moves fingerprint and
    transport at once, and a difference could not be attributed to either.
    No proxy here -- the QUIC path does not have one, so --proxy runs would
    silently be comparing a proxied arm against a direct one.
    """
    import pybrws.h3 as h3

    url = as_url(target)
    response = None
    for _ in range(MAX_REDIRECTS + 1):
        response = h3.get(url, timeout=timeout)
        if not 300 <= response.status < 400:
            return response.status, response.body or b""
        location = response.header("location")
        if not location:
            return response.status, response.body or b""
        # A redirect may point somewhere that does not serve h3 at all, in
        # which case the next call raises and the run records the error.
        # That is the honest answer: the page did not arrive over h3.
        url = urljoin(url, location)
    return response.status, response.body or b""


# Keyed by arm name, which is what goes in the log, so a run with the h3 arm
# stays readable alongside every run recorded before it existed.
ALL_CLIENTS = {
    "pybrws": via_pybrws,
    "pybrws-h3": via_pybrws_h3,
    "httpx": via_baseline,
    "httpx+ff": via_baseline_ff,
}
# httpx+ff is on by default: it is the control that keeps the A/B from
# crediting the protocol fingerprint for a result the headers produced.
DEFAULT_ARMS = ["pybrws", "httpx", "httpx+ff"]
CLIENTS = {name: ALL_CLIENTS[name] for name in DEFAULT_ARMS}

PROFILES = {"pybrws-h3": "firefox157_quic"}

# Phrases that mark a body as a block or a JavaScript challenge rather than
# the page, so a 200 that is really an interstitial is not scored as served.
# A JS challenge served with status 200 is the quietest way a run inflates
# itself -- macys returns a 2,843-byte Akamai reload shell as a 200.
CHALLENGE_MARKERS = (
    b"captcha-delivery", b"px-captcha", b"/cdn-cgi/challenge",
    b"Request unsuccessful", b"Access Denied", b"Pardon Our Interruption",
    b"Powered and protected", b"Just a moment", b"Checking your browser",
    b"enable JavaScript and cookies",
)


def blocked(status) -> bool:
    return status in (403, 429, 503)


def arrived(result) -> bool:
    """Did the page itself come back?

    `result` is a (status, body) pair from a live call, or a bare status int
    read back from the log (older rows carry no body).

    Not blocked is not the same as arrived. A 3xx has run out of redirects
    rather than reached anything; and a challenge page served with status 200
    is not the page either, which is why the body is inspected when it is
    available. Counting either as success is how a block hides.
    """
    if isinstance(result, tuple):
        status, body = result
    else:
        status, body = result, None
    if not isinstance(status, int) or blocked(status) or 300 <= status < 400:
        return False
    if body is not None and any(m.lower() in body[:60000].lower()
                                for m in CHALLENGE_MARKERS):
        return False
    return True


def run(targets: list[str], rounds: int, timeout: float, pause: float) -> list[dict]:
    samples = []
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for round_no in range(rounds):
        # Interleaving matters: drift during a run then hits every cell, not
        # whichever client happens to be measured last.
        for target in targets:
            for name, call in CLIENTS.items():
                body = b""
                try:
                    status, body = call(target, timeout)
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
                        # Recorded so a challenge served as a 200 is visible
                        # as a tiny "served" cell rather than passing silently.
                        "bytes": len(body) if status is not None else None,
                        "served": arrived((status, body)) if status is not None else False,
                        "error": error,
                        "profile": PROFILES.get(name, firefox157.NAME),
                        "proxy": bool(PROXY) if name == "pybrws" else False,
                    }
                )
                print(".", end="", flush=True)
                time.sleep(pause)
    print()
    return samples


def summarise(samples: list[dict]) -> None:
    grouped = defaultdict(list)
    for sample in samples:
        grouped[(sample["host"], sample["client"])].append(sample)

    hosts = sorted({host for host, _ in grouped})
    width = max(len(h) for h in hosts) + 2
    print()
    header = "host".ljust(width)
    for client in CLIENTS:
        header += client.ljust(26)
    print(header + "reading")
    for host in hosts:
        cells = {}
        for client in CLIENTS:
            rows = grouped.get((host, client), [])
            # `served` is decided per sample at capture time, so a 200 that
            # was really a challenge body is already counted as not served.
            served = sum(1 for r in rows if r.get("served"))
            statuses = [r["status"] if r["status"] is not None else r["error"]
                        for r in rows]
            cells[client] = (served, len(rows), statuses)

        rendered = []
        for client in CLIENTS:
            served, total, statuses = cells[client]
            spread = "" if len(set(map(str, statuses))) == 1 else " flapping"
            rendered.append(("%d/%d served%s" % (served, total, spread)).ljust(26))

        print(host.ljust(width) + "".join(rendered) + reading_for(host, cells))


def reading_for(host: str, cells: dict) -> str:
    """One sentence per host, saying what the cells do and do not establish.

    Written as an ordered set of questions rather than a comparison, because
    the first one disposes of most hosts: if a plain client is served too,
    nothing this tool measures is being discriminated against, and the other
    arms say nothing about detection no matter how they came out.
    """
    if host == CONTROL:
        return "control"

    def rate(arm):
        served, total, _ = cells.get(arm, (0, 0, []))
        return served, total

    def unreachable(arm) -> bool:
        """Did this arm never get an HTTP response at all?

        A host that does not speak h3 refuses the connection, and counting
        that as "blocked over h3" manufactures the mirror image of the
        finding we are looking for. Not reachable and not served are
        different claims and only one of them is about detection.
        """
        _served, total, results = cells.get(arm, (0, 0, []))
        return bool(total) and not any(isinstance(r, int) for r in results)

    plain, plain_n = rate("httpx")
    ff, ff_n = rate("httpx+ff")
    h2, h2_n = rate("pybrws")
    h3, h3_n = rate("pybrws-h3")

    if plain_n and plain == plain_n:
        return "host serves a plain client too -- discriminates on nothing here"

    if unreachable("pybrws-h3"):
        return "no HTTP/3 here -- not a transport comparison"
    if unreachable("pybrws"):
        return "no answer over TCP at all -- check the network, not the host"

    # With the h3 arm present the interesting pair is h2 against h3, because
    # it is the only pair where the single variable is the transport.
    if h3_n and h2_n:
        if h2 == h2_n and h3 == h3_n:
            return "served on both transports"
        if h3 == h3_n and h2 == 0:
            return "*** served over h3, blocked over h2 ***"
        if h2 == h2_n and h3 == 0:
            return "*** served over h2, blocked over h3 ***"
        if h2 == 0 and h3 == 0:
            return "blocked on both transports -- not a transport question"
        return "transport differs but neither arm is deterministic"

    if h2_n and plain_n and h2 == h2_n and plain == 0:
        # pybrws passes where plain httpx is refused. The httpx+ff arm, if it
        # ran, says whether the fingerprint or the headers did it.
        if ff_n and ff == ff_n:
            return ("*** headers alone suffice: httpx+ff served too, the "
                    "fingerprint bought nothing here ***")
        if ff_n and ff == 0:
            return "pybrws passes on the fingerprint: httpx+ff blocked like httpx"
        return "pybrws passes, baseline blocked (add httpx+ff to attribute it)"
    if ff_n and plain_n and ff == ff_n and plain == 0 and h2 == 0:
        return ("*** fingerprint is a liability here: httpx+ff served, pybrws "
                "blocked -- the browser hello is what gets refused ***")
    if h2 > plain:
        return "pybrws better, not deterministic"
    if h2 == plain:
        return "no difference"
    return "baseline better"


def show_history() -> None:
    if not LOG.exists():
        raise SystemExit("no log at " + str(LOG))
    runs = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for line in LOG.read_text(encoding="utf-8").splitlines():
        sample = json.loads(line)
        cell = runs[sample["run"]][(sample["host"], sample["client"])]
        cell[1] += 1
        # Rows written since the body was recorded carry a decided `served`;
        # older rows have only a status, so fall back to judging that.
        served = (sample["served"] if "served" in sample
                  else arrived(sample["status"]))
        if served:
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
    parser.add_argument("--arms", nargs="+", default=DEFAULT_ARMS,
                        choices=sorted(ALL_CLIENTS),
                        help="which clients to run. Adding pybrws-h3 turns "
                             "this into a transport comparison: pybrws-h3 "
                             "against pybrws is the only pair whose single "
                             "variable is the transport")
    parser.add_argument("--timeout", type=float, default=25.0)
    parser.add_argument("--pause", type=float, default=1.0,
                        help="seconds between requests, to stay polite")
    parser.add_argument("--proxy", metavar="URL",
                        help="route the pybrws arm through this proxy. Note "
                             "this confounds fingerprint with address; "
                             "tools/isolate.py crosses the two instead")
    parser.add_argument("--use-env", action="store_true",
                        help="take the proxy from PYBRWS_PROXY or HTTPS_PROXY")
    parser.add_argument("--no-log", action="store_true")
    parser.add_argument("--history", action="store_true",
                        help="summarise past runs and exit")
    args = parser.parse_args()

    if args.history:
        show_history()
        return 0

    global CLIENTS
    CLIENTS = {name: ALL_CLIENTS[name] for name in args.arms}
    if "pybrws-h3" in CLIENTS and (args.proxy or args.use_env):
        raise SystemExit("the h3 arm has no proxy path, so --proxy would "
                         "compare a proxied arm against a direct one")

    global PROXY
    if args.proxy:
        PROXY = args.proxy
    elif args.use_env:
        from pybrws.proxies import proxy_from_env

        PROXY = proxy_from_env()
        if not PROXY:
            raise SystemExit("--use-env given but no proxy variable is set")
    if PROXY:
        from pybrws.proxies import parse_proxy

        # str(Proxy) omits the password.
        print("pybrws arm through %s" % (parse_proxy(PROXY),))
        print("WARNING: this changes two variables at once. The proxied arm "
              "differs from the direct one in both fingerprint and address, "
              "so a difference cannot be attributed to either. Use "
              "tools/isolate.py for that.")

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
