#!/usr/bin/env python3
"""Capture a raw ClientHello from a local TCP listener.

Listens on a local port, accepts one connection, and dumps the first bytes the
client sends. The handshake fails afterwards, which does not matter since the
ClientHello has already been transmitted.

    python tools/catch_hello.py fixtures/firefox.hex
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pybrws.hexio import hexdump, save_hex  # noqa: E402
from pybrws.model import GREASE_VALUES  # noqa: E402
from pybrws.parser import parse_client_hello  # noqa: E402

GREASE = "GREASE"


def catch(host: str, port: int, wait: float, quiet_after: float) -> bytes:
    """Accept one connection and return everything the client sends."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(8)
    srv.settimeout(wait)

    print(f"listening on {host}:{port} ({wait:.0f}s timeout)", flush=True)
    try:
        conn, peer = srv.accept()
    except TimeoutError:
        raise SystemExit("no connection received")
    finally:
        srv.close()

    print(f"connection from {peer[0]}:{peer[1]}", flush=True)
    return _read_until_quiet(conn, quiet_after)


def _read_until_quiet(conn, quiet_after: float) -> bytes:
    chunks: list[bytes] = []
    # A post-quantum ClientHello spans two TCP segments, so read until the
    # client goes quiet rather than taking a single recv().
    conn.settimeout(quiet_after)
    with conn:
        while True:
            try:
                chunk = conn.recv(65535)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def catch_many(host: str, port: int, count: int, wait: float,
               quiet_after: float) -> list[bytes]:
    """Accept `count` connections on one listener.

    Chrome shuffles its extension order per connection, so one capture says
    nothing about which part is the fingerprint. Several in one run beats
    several runs: the browser makes speculative connections while a page
    loads, so a single visit usually fills this on its own.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(8)

    print(f"listening on {host}:{port}, want {count} hello(s), "
          f"{wait:.0f}s timeout", flush=True)
    deadline = time.monotonic() + wait
    caught: list[bytes] = []
    try:
        while len(caught) < count and time.monotonic() < deadline:
            srv.settimeout(max(deadline - time.monotonic(), 0.1))
            try:
                conn, peer = srv.accept()
            except TimeoutError:
                break
            data = _read_until_quiet(conn, quiet_after)
            if not data:
                continue
            caught.append(data)
            print(f"  {len(caught)}: {len(data)} bytes from port {peer[1]}",
                  flush=True)
    finally:
        srv.close()
    return caught


def compare(hellos: list[bytes]) -> None:
    """Say whether the order is drawn or stored, and what is pinned.

    The same question the QUIC reader answers, asked here because Chrome has
    shuffled its extension order since version 110 and Firefox over TCP does
    not. A profile built from one capture of a shuffling client records one
    sample of a distribution as though it were a constant.
    """
    parsed = [parse_client_hello(data) for data in hellos]
    # GREASE collapses to one identity first, the way differ.py does it.
    # Chrome sends two greased extensions with a fresh value each connection,
    # so comparing raw types reports six different sets from six captures of
    # the same browser -- which is what this printed before the collapse, and
    # it was wrong.
    orders = [tuple(GREASE if t in GREASE_VALUES else t
                    for t in h.extension_types())
              for h in parsed]
    sets = {frozenset(order) for order in orders}

    print()
    print(f"{len(orders)} hello(s), {len(set(orders))} distinct order(s), "
          f"{len(sets)} distinct set(s), GREASE collapsed to {GREASE!r}")
    for order in dict.fromkeys(orders):
        print("  " + " ".join(str(t) for t in order))

    if len(sets) > 1:
        print("  -> the sets differ, so these are not all the same client.")
        return
    if len(orders) < 2:
        print("  -> one hello says nothing about stability.")
        return
    if len(set(orders)) == 1:
        print(f"  -> the same order {len(orders)} times: it is stored, and "
              "the profile can hold it as a list.")
        return
    print("  -> a different order each time: it is drawn per connection, so "
          "the profile has to draw one too.")
    pinned_head = _common_prefix(orders)
    pinned_tail = _common_suffix(orders)
    if pinned_head:
        print("     pinned at the front: "
              + " ".join(str(t) for t in pinned_head))
    if pinned_tail:
        print("     pinned at the end:   "
              + " ".join(str(t) for t in pinned_tail))
    if not pinned_head and not pinned_tail:
        print("     nothing is pinned at either end.")


def _common_prefix(orders) -> list[int]:
    out = []
    for position in range(min(len(o) for o in orders)):
        values = {o[position] for o in orders}
        if len(values) != 1:
            break
        out.append(orders[0][position])
    return out


def _common_suffix(orders) -> list[int]:
    out = []
    for depth in range(1, min(len(o) for o in orders) + 1):
        values = {o[-depth] for o in orders}
        if len(values) != 1:
            break
        out.insert(0, orders[0][-depth])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("out", help="path to write the hex dump to")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4443)
    ap.add_argument("--wait", type=float, default=120.0,
                    help="seconds to wait for a connection")
    ap.add_argument("--quiet-after", type=float, default=0.8,
                    help="seconds of silence that end the read")
    ap.add_argument("--peek", action="store_true", help="print a hexdump")
    ap.add_argument("--count", type=int, default=1,
                    help="capture this many hellos and compare them, which is "
                         "what a client that shuffles its extension order "
                         "needs")
    args = ap.parse_args()

    if args.count > 1:
        caught = catch_many(args.host, args.port, args.count, args.wait,
                            args.quiet_after)
        if not caught:
            raise SystemExit("no hellos captured")
        stem, _, suffix = args.out.rpartition(".")
        for index, data in enumerate(caught, 1):
            name = "%s-%d.%s" % (stem or args.out, index, suffix or "hex")
            save_hex(name, data)
            print("wrote %s" % name)
        compare(caught)
        return 0

    data = catch(args.host, args.port, args.wait, args.quiet_after)
    if not data:
        raise SystemExit("connection sent no data")

    save_hex(args.out, data)
    print(f"captured {len(data)} bytes -> {args.out}")

    if data[0] != 0x16:
        print(f"warning: first byte is 0x{data[0]:02x}, expected 0x16 (handshake)")
    if args.peek:
        print()
        print(hexdump(data[:160]))
        if len(data) > 160:
            print(f"... {len(data) - 160} more bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
