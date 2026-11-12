"""Cross fingerprint against address, so neither can hide behind the other.

Routing one client through a proxy changes two things at once. This crosses
them: pybrws and httpx, each direct and each proxied. Only the full square
says whether a result comes from the protocol fingerprint, from the address,
or from needing both.

    pybrws isolate --targets https://example.com/ \\
                   --proxy http://user:pass@exit.example:33335

--proxy defaults to the PYBRWS_PROXY environment variable. The httpx arms
need httpx.
"""

import argparse
import os
import time
from functools import partial

from pybrws import profiles
from pybrws.client import get


def pybrws(url, proxy, profile):
    return get(url, proxy=proxy or False, profile=profile, timeout=30,
               follow_redirects=5).status


def hx(url, proxy):
    import httpx

    with httpx.Client(timeout=25, http2=True, follow_redirects=True,
                      proxy=proxy or None) as client:
        return client.get(url).status_code


def served(runs):
    return sum(1 for s in runs if isinstance(s, int) and s not in (403, 429, 503))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pybrws isolate",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--proxy", metavar="URL",
                        help="the proxy the proxied arms go through "
                             "(default: $PYBRWS_PROXY)")
    parser.add_argument("--targets", nargs="+", metavar="TARGET",
                        help="the hosts or URLs to measure")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--profile", default="firefox157",
                        help="the pybrws arms' profile, a built-in name or a "
                             ".py file")
    args = parser.parse_args(argv)

    proxy = args.proxy or os.environ.get("PYBRWS_PROXY")
    if not proxy:
        raise SystemExit("no proxy: pass --proxy URL or set PYBRWS_PROXY")
    if not args.targets:
        raise SystemExit("nothing to measure: --targets takes one or more "
                         "hosts or URLs, e.g. --targets https://example.com/")
    try:
        profile = profiles.load(args.profile, transport="tcp")
    except profiles.ProfileError as error:
        raise SystemExit(str(error))
    # Imported once the arguments are good and before the first request, so
    # a missing httpx stops the run instead of reading as a refusal.
    import httpx  # noqa: F401

    arms = {
        "pybrws direct": partial(pybrws, proxy=None, profile=profile),
        "pybrws proxy": partial(pybrws, proxy=proxy, profile=profile),
        "httpx direct": partial(hx, proxy=None),
        "httpx proxy": partial(hx, proxy=proxy),
    }
    targets = list(args.targets)
    results = {(target, label): [] for target in targets for label in arms}

    for round_no in range(args.rounds):
        for target in targets:
            url = target if "://" in target else "https://" + target + "/"
            for label, call in arms.items():
                try:
                    status = call(url)
                except Exception as exc:
                    status = type(exc).__name__[:9]
                results[(target, label)].append(status)
                time.sleep(0.5)
        print("round %d of %d done" % (round_no + 1, args.rounds), flush=True)

    width = max(22, max(len(target) for target in targets) + 2)
    print()
    print("target".ljust(width) + "".join(label.ljust(16) for label in arms))
    for target in targets:
        cells = "".join(
            ("%d/%d" % (served(results[(target, label)]), args.rounds)).ljust(16)
            for label in arms
        )
        print(target.ljust(width) + cells)

    print()
    for target in targets:
        print(target)
        for label in arms:
            print("    %-14s %s" % (label, results[(target, label)]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
