#!/usr/bin/env python3
"""Why does headed Chrome send extension 0x12e0 and headless Chrome not?

Established already, on this machine, with the binary, the version and the
network held constant:

    headed, by hand      q13d0313h3_55b375c5d22e_eb028bd37c08
    headless             q13d0312h3_55b375c5d22e_178839b6cec1

and the second list plus 0x12e0 hashes to the first exactly, so the single
extension is the whole difference. thumbprint's catalogue holds 110 Chrome
sessions, all headless, and none carries it.

Two mechanisms fit that, and they are worth different amounts:

  * headless omits the extension as such, which makes its absence a
    headless tell at the ClientHello, readable with no JavaScript; or
  * the extension sits behind a randomised field trial, and headless simply
    does not join trials. Then only some headed Chromes send it, presence
    implies not-headless, and absence implies nothing at all.

`--disable-field-trial-config` separates them, because it turns the trials
off without touching the window. Four arms, one machine, one variable each:

    python tools/headless_tell.py                  # the two new arms
    python tools/headless_tell.py --arms all       # all four, opens windows
    python tools/headless_tell.py --transport quic

A headed arm opens a real window and closes it again. The transport is
pinned, because the first version of this script did not and Chrome
answered over HTTP/3 against a table of TCP values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Separate origins, so the transport is chosen by the URL rather than hoped
# for. thumbprint serves h2 and h3 on these names respectively.
ORIGINS = {
    "tcp": "https://h2.thumbprint.me/api/v1/probe",
    "quic": "https://h3.thumbprint.me/api/v1/probe",
}

CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
]

# Measured, not computed here. The headed rows came from loading the site in
# a Chrome window by hand; the catalogue rows are thumbprint's own captures.
KNOWN = {
    ("tcp", "headed"): "t13d1518h2_8daaf6152771_4980c97edce0",
    ("tcp", "catalogue"): "t13d1517h2_8daaf6152771_cb7bf5808d99",
    ("quic", "headed"): "q13d0313h3_55b375c5d22e_eb028bd37c08",
    ("quic", "catalogue"): "q13d0312h3_55b375c5d22e_178839b6cec1",
}

# window?  trials?
ARMS = {
    "headless": (False, True),
    "headless-no-trials": (False, False),
    "headed": (True, True),
    "headed-no-trials": (True, False),
}
DEFAULT_ARMS = ["headless", "headed-no-trials"]


def find_chrome(given: str | None) -> str:
    if given:
        return given
    for path in CANDIDATES:
        if path and Path(path).exists():
            return path
    found = shutil.which("chrome") or shutil.which("chrome.exe")
    if found:
        return found
    raise SystemExit("could not find chrome.exe; pass --chrome")


def run(chrome: str, url: str, windowed: bool, trials: bool,
        timeout: float) -> dict:
    profile_dir = tempfile.mkdtemp(prefix="headless-tell-")
    command = [chrome, "--user-data-dir=" + profile_dir,
               "--no-first-run", "--no-default-browser-check",
               "--dump-dom", "--virtual-time-budget=8000"]
    if not windowed:
        command.append("--headless=new")
    if not trials:
        # Chrome's own switch for "ignore the trial configuration you were
        # handed". If the extension is gated on a trial, this drops it.
        command.append("--disable-field-trial-config")
    command.append(url)

    done = subprocess.run(command, capture_output=True, text=True,
                          timeout=timeout)
    shutil.rmtree(profile_dir, ignore_errors=True)
    if not done.stdout:
        raise SystemExit("chrome produced nothing; stderr was:\n"
                         + done.stderr[:2000])

    text = re.sub(r"<[^>]+>", "", done.stdout)
    for entity, char in (("&quot;", '"'), ("&amp;", "&"),
                         ("&lt;", "<"), ("&gt;", ">")):
        text = text.replace(entity, char)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise SystemExit("no JSON in the page:\n" + text[:1000])
    return json.loads(text[start:end + 1])


def verdict(results: dict, transport: str) -> None:
    headed = KNOWN[(transport, "headed")]
    has = {name: "12e0" in (body.get("ja4_r") or "")
           for name, body in results.items()}

    print()
    if "headed-no-trials" in has and "headless" in has:
        if has["headed-no-trials"] and not has["headless"]:
            print("Trials off and the window open still sends it; headless\n"
                  "with trials on does not. So the window is the variable\n"
                  "and 0x12e0 is a headless tell at the ClientHello --\n"
                  "before any HTTP, with no JavaScript involved.")
        elif not has["headed-no-trials"]:
            print("Turning the trials off removed it from a windowed Chrome.\n"
                  "So it is gated on a field trial, not on the window.\n"
                  "Presence then implies the client is not headless;\n"
                  "absence implies nothing. And this profile copies one\n"
                  "Chrome population rather than Chrome.")
        else:
            print("Both arms carry it, which contradicts the earlier\n"
                  "headless run. Read the raw lists before concluding.")
    else:
        print("Run both `headless` and `headed-no-trials` for a verdict.")

    if results.get("headless", {}).get("ja4") == headed:
        print("\nNote: the headless arm matched the headed value this time,\n"
              "which the earlier run did not. Something else moved.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--chrome")
    parser.add_argument("--transport", choices=["tcp", "quic"], default="quic",
                        help="quic by default, because the headed and "
                             "headless values already in hand were both "
                             "measured over it")
    parser.add_argument("--arms", nargs="+", choices=list(ARMS) + ["all"],
                        default=DEFAULT_ARMS)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    arms = list(ARMS) if "all" in args.arms else args.arms
    chrome = find_chrome(args.chrome)
    url = ORIGINS[args.transport]
    print("%s\n%s over %s\n" % (chrome, url, args.transport))

    results = {}
    for name in arms:
        windowed, trials = ARMS[name]
        print("  %-20s %s%s ..." % (name, "window" if windowed else "headless",
                                    "" if trials else ", trials off"),
              flush=True)
        results[name] = run(chrome, url, windowed, trials, args.timeout)

    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
        return 0

    print()
    width = max(len(n) for n in list(results) + ["headed, by hand"]) + 2
    print("%-*s %-38s %s" % (width, "arm", "ja4", "0x12e0"))
    for name, body in results.items():
        print("%-*s %-38s %s" % (width, name, body.get("ja4", "?"),
                                 "yes" if "12e0" in (body.get("ja4_r") or "")
                                 else "no"))
    print("%-*s %-38s %s" % (width, "headed, by hand",
                             KNOWN[(args.transport, "headed")], "yes"))
    print("%-*s %-38s %s" % (width, "catalogue, headless",
                             KNOWN[(args.transport, "catalogue")], "no"))

    verdict(results, args.transport)

    for name, body in results.items():
        if body.get("ja4_r"):
            print("\n  %s\n    %s" % (name, body["ja4_r"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
