#!/usr/bin/env python3
"""Catch a raw ClientHello without Wireshark, without admin rights.

Listens on a local port, accepts one connection, and dumps the first thing the
client sends - which is always the ClientHello. The handshake then dies, which
is fine: we already have what we came for.

    python tools/catch_hello.py fixtures/firefox.hex

Then point a client at https://pybrws.test:4443 (see fixtures/README.md - the
hostname matters, do not use 127.0.0.1 directly).
"""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pybrws.hexio import hexdump, save_hex  # noqa: E402


def catch(host: str, port: int, wait: float, quiet_after: float) -> bytes:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    srv.settimeout(wait)

    print(f"listening on {host}:{port} - point a TLS client at it "
          f"({wait:.0f}s timeout)", flush=True)
    try:
        conn, peer = srv.accept()
    except TimeoutError:
        raise SystemExit("nothing connected. Did the client reach this port?")
    finally:
        srv.close()

    print(f"connection from {peer[0]}:{peer[1]}", flush=True)
    chunks: list[bytes] = []
    # Read until the client goes quiet. A post-quantum ClientHello spans two
    # TCP segments, so a single recv() is not enough.
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
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", help="where to write the hex dump")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4443)
    ap.add_argument("--wait", type=float, default=120.0,
                    help="seconds to wait for a connection")
    ap.add_argument("--quiet-after", type=float, default=0.8,
                    help="seconds of silence that mean the client is done")
    ap.add_argument("--peek", action="store_true", help="print a hexdump")
    args = ap.parse_args()

    data = catch(args.host, args.port, args.wait, args.quiet_after)
    if not data:
        raise SystemExit("connected but sent nothing.")

    save_hex(args.out, data)
    print(f"captured {len(data)} bytes -> {args.out}")

    if data[0] != 0x16:
        print(f"WARNING: first byte is 0x{data[0]:02x}, expected 0x16 (handshake)")
    if args.peek:
        print()
        print(hexdump(data[:160]))
        if len(data) > 160:
            print(f"... {len(data) - 160} more bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
