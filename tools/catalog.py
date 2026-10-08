#!/usr/bin/env python3
"""Does thumbprint.me's catalogue hold a browser as new as the one we model?

`probe_fingerprint.py` reported no matching TLS session for our Chrome
profile while HTTP/2 matched 96 and the request headers matched 49. Two
explanations fit that, and they are opposites:

  * their newest Chrome capture predates the extension set we send, so no
    match is possible and our profile is fine; or
  * they have a current Chrome and we differ from it, which is our bug.

The identities the probe returned name chrome 151 as the newest, but those
came from the HTTP/2 match, not from an inventory. /api/v1/catalog is the
inventory: every published session with client, version and OS, and the
fingerprints of each capture. It is roughly 5 MB, so this fetches it once
and caches it.

    python tools/catalog.py                 # what is in there
    python tools/catalog.py --client chrome # versions and their fingerprints
    python tools/catalog.py --find t13d1518h2_8daaf6152771_4980c97edce0

Fingerprints are located by shape, not by field name: anything matching a
JA4 pattern anywhere in a session is indexed, with the path it was found at
printed once so the schema is visible rather than assumed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from pybrws.client import get

CATALOG_URL = "https://thumbprint.me/api/v1/catalog"
CACHE = REPO / ".cache" / "thumbprint-catalog.json"

# t13d1517h2_8daaf6152771_3cbfd9057e0d, q13d0315h3_..., and the JA4H form.
JA4ISH = re.compile(r"^[a-z0-9]{6,14}_[0-9a-f]{12}(_[0-9a-f]{12})*$")


def load(url: str, cache: Path, refresh: bool, timeout: float) -> dict:
    if cache.exists() and not refresh:
        print("reading %s (%.1f MB cached)"
              % (cache, cache.stat().st_size / 1e6), file=sys.stderr)
        return json.loads(cache.read_text(encoding="utf-8"))

    print("fetching %s ..." % url, file=sys.stderr)
    response = get(url, timeout=timeout, follow_redirects=3)
    if response.status != 200:
        raise SystemExit("catalogue returned %s" % response.status)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(response.body)
    print("cached %.1f MB to %s" % (len(response.body) / 1e6, cache),
          file=sys.stderr)
    return json.loads(response.body)


def walk(value, prefix: str = ""):
    """Yield (path, string) for every string in the tree."""
    if isinstance(value, dict):
        for key, inner in value.items():
            yield from walk(inner, "%s.%s" % (prefix, key) if prefix else key)
    elif isinstance(value, list):
        for index, inner in enumerate(value):
            yield from walk(inner, "%s[]" % prefix)
    elif isinstance(value, str):
        yield prefix, value


def fingerprints(session) -> dict[str, set[str]]:
    """Every JA4-shaped string in one session, keyed by where it was found.

    The key keeps the list index stripped, so all captures of a session
    collapse onto the same path and the shape of the schema is readable.
    """
    found: dict[str, set[str]] = defaultdict(set)
    for path, text in walk(session):
        if JA4ISH.match(text):
            found[path].add(text)
    return found


def sessions_of(catalog) -> list:
    if isinstance(catalog, dict):
        for key in ("sessions", "captures", "entries", "data"):
            if isinstance(catalog.get(key), list):
                return catalog[key]
        raise SystemExit("no session list in catalogue; keys are %s"
                         % sorted(catalog))
    if isinstance(catalog, list):
        return catalog
    raise SystemExit("unexpected catalogue type %s" % type(catalog).__name__)


def version_key(version: str):
    """Sort 155.0.1 above 99.0 without choking on anything odd."""
    parts = []
    for piece in re.split(r"[.\-+]", version or ""):
        parts.append((0, int(piece)) if piece.isdigit() else (1, piece))
    return parts


def inventory(sessions, client_filter: str | None) -> None:
    by_client: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    paths: set[str] = set()

    for session in sessions:
        client = str(session.get("client", "?")).lower()
        if client_filter and client_filter not in client:
            continue
        by_client[client][str(session.get("version", "?"))] += 1
        paths.update(fingerprints(session))

    if not by_client:
        print("no sessions matched" + (" %r" % client_filter
                                       if client_filter else ""))
        return

    print("fingerprint fields found in a session:")
    for path in sorted(paths):
        print("    %s" % path)
    print()

    for client in sorted(by_client):
        versions = by_client[client]
        newest = max(versions, key=version_key)
        print("%-12s %3d sessions, %2d versions, newest %s"
              % (client, sum(versions.values()), len(versions), newest))
        if client_filter:
            for version in sorted(versions, key=version_key, reverse=True):
                print("    %-16s %d" % (version, versions[version]))


def detail(sessions, client_filter: str, limit: int) -> None:
    """The newest versions of one client, with their fingerprints."""
    picked = [s for s in sessions
              if client_filter in str(s.get("client", "")).lower()]
    picked.sort(key=lambda s: version_key(str(s.get("version", ""))),
                reverse=True)

    seen: set[str] = set()
    shown = 0
    for session in picked:
        version = str(session.get("version", "?"))
        if version in seen:
            continue
        seen.add(version)
        print("%s %s  %s %s" % (session.get("client"), version,
                                session.get("os", ""),
                                session.get("os_version", "")))
        for path, values in sorted(fingerprints(session).items()):
            for value in sorted(values):
                print("    %-28s %s" % (path, value))
        print()
        shown += 1
        if shown >= limit:
            break


def wire(sessions, client_filter: str, version: str | None,
         limit: int) -> None:
    """Dump the raw per-capture data, unfiltered.

    `fingerprints` and `ja4` are hashes, and a hash tells you two things
    differ without telling you where. The `wire` object carries the raw
    lists -- JA4_r and JA4_ro, the comma-separated cipher, extension and
    signature-algorithm values -- which the JA4-shaped filter skips because
    they contain commas. This is what a diff against our own profile needs.
    """
    picked = [s for s in sessions
              if client_filter in str(s.get("client", "")).lower()
              and (version is None
                   or str(s.get("version", "")).startswith(version))]
    picked.sort(key=lambda s: version_key(str(s.get("version", ""))),
                reverse=True)
    if not picked:
        print("no %s session matching version %r" % (client_filter, version))
        return

    for session in picked[:limit]:
        print("=== %s %s  %s %s ===" % (session.get("client"),
                                        session.get("version"),
                                        session.get("os", ""),
                                        session.get("os_version", "")))
        for capture in session.get("captures", []):
            print("  transport=%s http=%s host=%s"
                  % (capture.get("transport"), capture.get("http_version"),
                     capture.get("host")))
            for key in ("wire", "dims", "fingerprints"):
                block = capture.get(key)
                if not isinstance(block, dict):
                    continue
                for name in sorted(block):
                    value = block[name]
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, separators=(",", ":"))
                    print("    %-6s %-10s %s" % (key, name, value))
            print()


def find(sessions, wanted: str) -> None:
    hits = []
    for session in sessions:
        for path, values in fingerprints(session).items():
            if wanted in values:
                hits.append((session.get("client"), session.get("version"),
                             session.get("os"), path))
    if not hits:
        print("%s appears in no catalogued session." % wanted)
        print("That is consistent with their captures predating what we "
              "send, and\nconsistent with our profile being wrong. The "
              "inventory above decides which.")
        return
    print("%s appears in %d session(s):" % (wanted, len(hits)))
    for client, version, os_name, path in hits:
        print("    %-10s %-16s %-10s %s" % (client, version, os_name, path))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=CATALOG_URL)
    parser.add_argument("--cache", type=Path, default=CACHE)
    parser.add_argument("--refresh", action="store_true",
                        help="re-download instead of using the cache")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="it is a few megabytes over our own client")
    parser.add_argument("--client", help="restrict to one client, e.g. chrome")
    parser.add_argument("--detail", type=int, metavar="N",
                        help="show the N newest versions of --client with "
                             "their fingerprints")
    parser.add_argument("--find", metavar="FINGERPRINT",
                        help="which sessions carry this exact value")
    parser.add_argument("--wire", type=int, metavar="N", nargs="?", const=1,
                        help="dump the raw capture data for N sessions of "
                             "--client, which is where the sorted lists "
                             "behind a hash actually live")
    parser.add_argument("--version", help="restrict --wire to versions "
                                          "starting with this prefix")
    args = parser.parse_args()

    catalog = load(args.url, args.cache, args.refresh, args.timeout)
    sessions = sessions_of(catalog)
    print("%d sessions in the catalogue\n" % len(sessions))

    if args.find:
        find(sessions, args.find)
        return 0

    if args.wire:
        if not args.client:
            print("--wire needs --client")
            return 2
        wire(sessions, args.client.lower(), args.version, args.wire)
        return 0

    inventory(sessions, args.client.lower() if args.client else None)

    if args.detail:
        if not args.client:
            print("\n--detail needs --client")
            return 2
        print()
        detail(sessions, args.client.lower(), args.detail)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
