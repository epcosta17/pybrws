#!/usr/bin/env python3
"""Capture a browser's resumed ClientHello, the one carrying pre_shared_key.

A Session resumes by default, so most requests after the first send a
ClientHello that no capture covered: adding pre_shared_key takes our own JA4
from t13d1517h2 to t13d1518h2 and changes every other hash with it. That is a
second identity, and until it is measured it is only a guess.

Capturing it needs two things at once that the other tools each do by half:
the handshake has to *complete*, so the server can issue a NewSessionTicket
for the browser to come back with, and the raw ClientHello bytes have to be
kept, which a terminated handshake normally consumes. Doing both means owning
the byte stream, so the TLS here runs over a pair of memory BIOs rather than
over the socket: every byte is recorded on its way in and replayed into
OpenSSL afterwards.

The reply closes the connection and the page reloads itself, so the browser
opens a fresh TCP connection and resumes on it.

    python tools/catch_resumed.py --fresh fixtures/reference-firefox-157-windows-fresh.hex \
                                  --resumed fixtures/reference-firefox-157-windows-resumed.hex

Then open the printed URL in the browser and accept the certificate warning.
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import _selfsigned  # noqa: E402

from pybrws.hexio import hexdump, save_hex  # noqa: E402
from pybrws.model import extension_name  # noqa: E402
from pybrws.parser import parse_client_hello  # noqa: E402

CRLF = "\r\n"
EXT_PRE_SHARED_KEY = 41
RECORD_HEADER = 5

PAGE = (
    b"<!doctype html><meta charset=utf-8><title>pybrws</title>"
    b"<body style='font:16px system-ui;padding:3rem'>"
    b"<p>Captured. Reloading on a new connection&hellip;</p>"
    b"<script>setTimeout(function(){location.reload()},600)</script>"
)


def reply() -> bytes:
    """An HTTP/1.1 response that forces the next request onto a new socket."""
    head = CRLF.join([
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=utf-8",
        "Content-Length: " + str(len(PAGE)),
        # Without this the browser reuses the connection and never resumes.
        "Connection: close",
    ]) + CRLF + CRLF
    return head.encode("latin-1") + PAGE


def first_record(buffer: bytes) -> bytes | None:
    """The complete first TLS record in `buffer`, or None if still partial."""
    if len(buffer) < RECORD_HEADER:
        return None
    length = int.from_bytes(buffer[3:5], "big")
    end = RECORD_HEADER + length
    return buffer[:end] if len(buffer) >= end else None


def serve_one(sock: socket.socket, context: ssl.SSLContext,
              timeout: float) -> bytes:
    """Handshake, answer the request, and return the raw ClientHello.

    The handshake has to finish for a ticket to be issued, and the raw bytes
    have to survive it, so OpenSSL is fed from a buffer this function keeps.

    The reply has to come *after* the request is read. Closing a socket that
    still holds unread data makes Windows send an RST, which throws away
    whatever was queued to go out, so answering first and reading never would
    lose the reply and with it the ticket.
    """
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=True)
    sock.settimeout(timeout)

    received = bytearray()
    hello: bytes | None = None

    def flush() -> None:
        pending = outgoing.read()
        if pending:
            sock.sendall(pending)

    def pump() -> None:
        """Move one socket read into OpenSSL, recording the first record."""
        nonlocal hello
        flush()
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionAbortedError("client closed the connection")
        if hello is None:
            received.extend(chunk)
            hello = first_record(bytes(received))
        incoming.write(chunk)

    while True:
        try:
            tls.do_handshake()
            break
        except ssl.SSLWantReadError:
            pump()
    flush()

    request = bytearray()
    while b"\r\n\r\n" not in request:
        try:
            data = tls.read(65536)
        except ssl.SSLWantReadError:
            pump()
            continue
        if not data:
            break
        request.extend(data)

    # The NewSessionTicket rides out with the first application data, so the
    # reply is what actually hands the browser something to resume with.
    tls.write(reply())
    flush()
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass

    if hello is None:
        raise ConnectionAbortedError("handshake finished without a full record")
    return hello


def describe(hello: bytes) -> tuple[list[int], bool]:
    """Extension ids in wire order, and whether pre_shared_key is among them."""
    parsed = parse_client_hello(hello)
    ids = [extension.type for extension in parsed.extensions]
    return ids, EXT_PRE_SHARED_KEY in ids


def label(kind: int) -> str:
    return extension_name(kind) + " (" + str(kind) + ")"


def serve(host: str, port: int, hostname: str, alpn: str,
          wait: float) -> tuple[bytes | None, bytes | None]:
    context, _tmp = _selfsigned.context(hostname, [alpn])
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(8)

    print("open https://%s:%d/ in the browser" % (hostname, port))
    print("the certificate is self-signed; accept the warning")
    print("(speculative connections that die before the warning are normal)")
    print()

    fresh: bytes | None = None
    resumed: bytes | None = None
    deadline = time.monotonic() + wait
    attempt = 0

    try:
        while time.monotonic() < deadline and resumed is None:
            listener.settimeout(max(deadline - time.monotonic(), 0.1))
            try:
                sock, peer = listener.accept()
            except TimeoutError:
                break

            attempt += 1
            try:
                hello = serve_one(sock, context, timeout=10.0)
            except (ssl.SSLError, OSError) as exc:
                print("  attempt %d from port %d: %s"
                      % (attempt, peer[1], type(exc).__name__))
                continue
            finally:
                sock.close()

            ids, has_psk = describe(hello)
            kind = "resumed" if has_psk else "fresh"
            print("  attempt %d from port %d: %s hello, %d bytes, %d extensions"
                  % (attempt, peer[1], kind, len(hello), len(ids)))
            if has_psk:
                resumed = hello
            elif fresh is None:
                fresh = hello
    finally:
        listener.close()

    return fresh, resumed


def report(fresh: bytes | None, resumed: bytes | None) -> None:
    if fresh is None and resumed is None:
        return
    print()
    if fresh is not None and resumed is not None:
        before, _ = describe(fresh)
        after, _ = describe(resumed)
        added = [kind for kind in after if kind not in before]
        dropped = [kind for kind in before if kind not in after]
        moved = before != [kind for kind in after if kind in before]
        print("fresh:   %d extensions, %d bytes" % (len(before), len(fresh)))
        print("resumed: %d extensions, %d bytes" % (len(after), len(resumed)))
        print("added:   " + (", ".join(label(k) for k in added) or "nothing"))
        print("dropped: " + (", ".join(label(k) for k in dropped) or "nothing"))
        print("the shared extensions kept their relative order: "
              + ("no" if moved else "yes"))
        if resumed is not None and after and after[-1] != EXT_PRE_SHARED_KEY:
            print("WARNING: pre_shared_key is not last, which RFC 8446 4.2.11"
                  " requires; check the parse before trusting this capture")
    elif resumed is None:
        print("no resumed hello captured: the browser never came back on a")
        print("new connection. Reload the page, or check that the reply still")
        print("says Connection: close.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fresh", type=Path,
                        help="where to write the first hello without a PSK")
    parser.add_argument("--resumed", type=Path,
                        help="where to write the first hello carrying a PSK")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4443)
    parser.add_argument("--hostname", default="pybrws.127.0.0.1.nip.io",
                        help="a name that resolves to the listener")
    parser.add_argument("--alpn", default="http/1.1", choices=["http/1.1", "h2"])
    parser.add_argument("--wait", type=float, default=180.0)
    parser.add_argument("--dump", action="store_true",
                        help="hexdump the resumed hello")
    args = parser.parse_args()

    fresh, resumed = serve(args.host, args.port, args.hostname, args.alpn,
                           args.wait)
    report(fresh, resumed)

    for path, hello in ((args.fresh, fresh), (args.resumed, resumed)):
        if path is not None and hello is not None:
            save_hex(path, hello)
            print("wrote " + str(path))
    if args.dump and resumed is not None:
        print()
        print(hexdump(resumed))
    return 0 if resumed is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
