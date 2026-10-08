#!/usr/bin/env python3
"""Does headless Chrome present a different ClientHello than headed Chrome?

thumbprint.me's catalogue holds 110 Chrome sessions across 40 versions and
three operating systems, and every one of them is headless. Extension
0x12e0 appears in none of them. It appears in this machine's headed Chrome
155, and in this project's chrome155 profile, which was built from captures
of that browser.

Two explanations fit, and only one of them is interesting:

  * headless Chrome omits 0x12e0, which would make it a TLS-level tell for
    headless -- readable before any HTTP, with no JavaScript involved; or
  * this install joined a randomised field trial that fresh CI containers
    do not, and the extension has nothing to do with headless.

The difference is decidable on one machine, because everything else is held
constant: same binary, same version, same profile directory, same field
trial state, same network. Run the same browser headless and look.

    python tools/headless_tell.py
    python tools/headless_tell.py --headed    # opens a window, for contrast

The headed value this is compared against came from loading thumbprint.me
in Chrome by hand, so it is not re-measured here.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROBE = "https://thumbprint.me/api/v1/probe"

CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
]

# Measured by hand in a real Chrome window on this machine, and by
# tools/ja4.py from the profile built out of its captures. Identical.
HEADED = "t13d1518h2_8daaf6152771_4980c97edce0"
OURS = "t13d1518h2_8daaf6152771_4980c97edce0"
# What every headless Chrome 155 in thumbprint's catalogue presents.
CATALOGUE = "t13d1517h2_8daaf6152771_cb7bf5808d99"


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


def run(chrome: str, headed: bool, timeout: float) -> str:
    """Load the probe endpoint and return the page text."""
    profile_dir = tempfile.mkdtemp(prefix="headless-tell-")
    command = [
        chrome,
        "--user-data-dir=" + profile_dir,
        "--no-first-run",
        "--no-default-browser-check",
        "--dump-dom",
        "--virtual-time-budget=8000",
    ]
    if not headed:
        command.insert(1, "--headless=new")
    command.append(PROBE)

    print("running %s%s" % (Path(chrome).name,
                            "" if headed else " --headless=new"),
          file=sys.stderr)
    done = subprocess.run(command, capture_output=True, text=True,
                          timeout=timeout)
    shutil.rmtree(profile_dir, ignore_errors=True)
    if not done.stdout:
        raise SystemExit("chrome produced nothing; stderr was:\n"
                         + done.stderr[:2000])
    return done.stdout


def extract(page: str) -> dict:
    """Pull the JSON back out of the DOM Chrome wrapped it in."""
    text = re.sub(r"<[^>]+>", "", page)
    text = (text.replace("&quot;", '"').replace("&amp;", "&")
                .replace("&lt;", "<").replace("&gt;", ">"))
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < 0:
        raise SystemExit("no JSON object in the page:\n" + text[:1000])
    return json.loads(text[start:end + 1])


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--chrome", help="path to chrome.exe")
    parser.add_argument("--headed", action="store_true",
                        help="run with a window instead, as a control")
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    body = extract(run(find_chrome(args.chrome), args.headed, args.timeout))
    if args.json:
        print(json.dumps(body, indent=2, sort_keys=True))
        return 0

    ja4 = body.get("ja4", "?")
    raw = body.get("ja4_r", "")

    print()
    print("  %-28s %s" % ("this run", ja4))
    print("  %-28s %s" % ("headed Chrome, by hand", HEADED))
    print("  %-28s %s" % ("pybrws chrome155", OURS))
    print("  %-28s %s" % ("catalogue, all headless", CATALOGUE))
    print()

    has_12e0 = "12e0" in raw
    print("  0x12e0 in this run's extension list: %s"
          % ("yes" if has_12e0 else "no"))
    print()

    if args.headed:
        print("This was the headed arm, so it is the control, not the test.")
    elif ja4 == CATALOGUE and not has_12e0:
        print("Headless drops 0x12e0 on this machine, with the version, the\n"
              "field trial state and the network all held constant. That\n"
              "makes it a headless tell at the TLS layer: visible before any\n"
              "HTTP, with no JavaScript. One machine, so it needs a second\n"
              "before it is more than a strong lead.")
    elif ja4 == HEADED:
        print("Headless presents the same hello as headed, so 0x12e0 is not\n"
              "about headless. The remaining explanation is a field trial\n"
              "this install joined and their CI containers did not, which\n"
              "would also mean our profile copies one Chrome population\n"
              "rather than Chrome.")
    else:
        print("Neither known value. Worth reading the full --json before\n"
              "concluding anything; the run may have differed in some other\n"
              "way.")
    if raw:
        print("\n  ja4_r %s" % raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
