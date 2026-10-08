#!/usr/bin/env python3
"""Is 0x12e0 about the window, or about this install's field trials?

What is measured so far, over QUIC, on this machine:

    Chrome window, normal profile, by hand   q13d0313h3_..._eb028bd37c08
    headless, a fresh temporary profile      q13d0312h3_..._178839b6cec1

and the second extension list plus 0x12e0 hashes to the first exactly. One
extension is the whole difference.

But two things changed between those runs, not one. The window, and the
profile directory: a script-launched Chrome gets `--user-data-dir` pointing
at an empty temp folder, and a fresh profile is handed a fresh field trial
seed. Chrome gates features behind randomised trials, so "headless omits
it" and "a new profile did not join the trial this install is in" both fit,
and only the first is a headless tell worth the name.

This holds the seed constant instead. Every arm runs headless -- so the
page is captured by the script rather than read off a screen, which is how
the previous version produced an answer nobody could attribute -- and the
arms differ only in which field trial state they start from:

    python tools/headless_tell.py

    fresh     a new profile, as any script-launched Chrome gets
    seeded    a new profile carrying this install's trial seed
    no-trials the seed present but ignored, via Chrome's own switch

If `seeded` carries 0x12e0, the trial seed was the variable all along and
the window is irrelevant. If it does not, the seed is controlled and the
window is the only difference left from the hand measurement.

A windowed arm is not offered: `--dump-dom` is a headless switch, and with
a window Chrome ignores it, writes nothing to stdout and leaves you
guessing which run you were looking at.
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

ORIGINS = {
    "tcp": "https://h2.thumbprint.me/api/v1/probe",
    "quic": "https://h3.thumbprint.me/api/v1/probe",
}

CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
]

USER_DATA = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data")

# The whole of Chrome's trial state, as four small files at the root of the
# user data directory. Copied out, never written to.
SEED_FILES = ["Local State", "Variations", "VariationsSeedV2",
              "VariationsSafeSeedV2"]

# Measured by hand in a Chrome window on this machine, on its normal
# profile. Not re-measured here, because a windowed run cannot be captured.
HEADED = {
    "tcp": "t13d1518h2_8daaf6152771_4980c97edce0",
    "quic": "q13d0313h3_55b375c5d22e_eb028bd37c08",
}

# seed?  trials?
ARMS = {
    "fresh": (False, True),
    "seeded": (True, True),
    "no-trials": (True, False),
}
DEFAULT_ARMS = ["fresh", "seeded"]


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


def seed(target: Path, source: Path) -> list[str]:
    copied = []
    for name in SEED_FILES:
        origin = source / name
        if origin.is_file():
            shutil.copy2(origin, target / name)
            copied.append(name)
    return copied


def run(chrome: str, url: str, with_seed: bool, trials: bool,
        source: Path, timeout: float) -> dict:
    profile = Path(tempfile.mkdtemp(prefix="headless-tell-"))
    note = ""
    if with_seed:
        copied = seed(profile, source)
        note = " (seed: %s)" % ", ".join(copied) if copied else " (no seed found!)"

    command = [chrome, "--headless=new", "--user-data-dir=" + str(profile),
               "--no-first-run", "--no-default-browser-check",
               "--dump-dom", "--virtual-time-budget=8000"]
    if not trials:
        command.append("--disable-field-trial-config")
    command.append(url)

    try:
        done = subprocess.run(command, capture_output=True, text=True,
                              timeout=timeout)
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    if not done.stdout:
        raise SystemExit("chrome produced nothing%s; stderr was:\n%s"
                         % (note, done.stderr[-2000:]))

    text = re.sub(r"<[^>]+>", "", done.stdout)
    for entity, char in (("&quot;", '"'), ("&amp;", "&"),
                         ("&lt;", "<"), ("&gt;", ">")):
        text = text.replace(entity, char)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise SystemExit("no JSON in the page%s:\n%s" % (note, text[:1000]))
    body = json.loads(text[start:end + 1])
    body["_seed"] = note.strip()
    return body


def read(body: dict) -> tuple[str, bool]:
    return body.get("ja4", "?"), "12e0" in (body.get("ja4_r") or "")


def verdict(results: dict, transport: str) -> None:
    has = {name: read(body)[1] for name, body in results.items()}
    print()
    if "seeded" not in has:
        print("Run the `seeded` arm for a verdict.")
        return

    if has["seeded"]:
        print("A headless Chrome carrying this install's trial seed sends\n"
              "0x12e0. So the seed was the variable and the window was\n"
              "never involved: the extension is gated on a field trial this\n"
              "install joined and a new profile does not.\n\n"
              "Which means the earlier reading was wrong, and it also means\n"
              "this profile imitates one Chrome population rather than\n"
              "Chrome. A detector seeing 0x12e0 can conclude the client is\n"
              "in that population; seeing it absent tells them nothing.")
        if "no-trials" in has and not has["no-trials"]:
            print("\nThe no-trials arm confirms it from the other side: the\n"
                  "same seed, ignored, drops the extension.")
    else:
        print("With the seed held constant, headless still does not send\n"
              "0x12e0 while the windowed run on the same seed does. The\n"
              "window is the remaining variable, which makes this a\n"
              "headless tell at the ClientHello -- before any HTTP, with no\n"
              "JavaScript involved.\n\n"
              "One machine and one browser, so it is a strong lead rather\n"
              "than a general fact. A second machine would settle it.")
    print("\nFor comparison, the windowed run on the normal profile:\n"
          "    %s   0x12e0 yes" % HEADED[transport])


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--chrome")
    parser.add_argument("--user-data", type=Path, default=Path(USER_DATA),
                        help="where to copy the trial seed from")
    parser.add_argument("--transport", choices=["tcp", "quic"], default="quic")
    parser.add_argument("--arms", nargs="+", choices=list(ARMS) + ["all"],
                        default=DEFAULT_ARMS)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not (args.user_data / "Local State").is_file():
        print("no Local State under %s; pass --user-data" % args.user_data)
        return 2

    arms = list(ARMS) if "all" in args.arms else args.arms
    chrome = find_chrome(args.chrome)
    url = ORIGINS[args.transport]
    print("%s\n%s over %s\nseed from %s\n"
          % (chrome, url, args.transport, args.user_data))

    results = {}
    for name in arms:
        with_seed, trials = ARMS[name]
        print("  %-12s ..." % name, flush=True, end="")
        results[name] = run(chrome, url, with_seed, trials,
                            args.user_data, args.timeout)
        print(" %s" % results[name].get("_seed", ""))

    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
        return 0

    print()
    print("%-12s %-38s %s" % ("arm", "ja4", "0x12e0"))
    for name, body in results.items():
        value, has = read(body)
        print("%-12s %-38s %s" % (name, value, "yes" if has else "no"))

    verdict(results, args.transport)

    for name, body in results.items():
        if body.get("ja4_r"):
            print("\n  %s\n    %s" % (name, body["ja4_r"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
