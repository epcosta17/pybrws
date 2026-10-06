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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pybrws.hexio import hexdump, save_hex  # noqa: E402


def catch(host: str, port: int, wait: float, quiet_after: float) -> bytes:
    """Accept one connection and return everything the client sends."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    srv.settimeout(wait)

    print(f"listening on {host}:{port} ({wait:.0f}s timeout)", flush=True)
    try:
        conn, peer = srv.accept()
    except TimeoutError:
        raise SystemExit("no connection received")
    finally:
        srv.close()

    print(f"connection from {peer[0]}:{peer[1]}", flush=True)
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
    args = ap.parse_args()

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
