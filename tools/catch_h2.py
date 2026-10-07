#!/usr/bin/env python3
"""Capture a browser's HTTP/2 request, decoded.

tools/catch_request.py offers only http/1.1, so everything this project knows
about Firefox's HTTP/2 headers is inferred from the HTTP/1.1 order rather
than measured. This speaks enough HTTP/2 to be a server: it answers the
preface, decodes the HEADERS frame with HPACK and prints the field list in
wire order, which is the thing in question.

    python tools/catch_h2.py fixtures/reference-firefox-157-h2.txt

Then open https://pybrws.127.0.0.1.nip.io:4443 and accept the certificate.
--set-cookie and --post work as they do in the HTTP/1.1 tool.
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _selfsigned  # noqa: E402
from hpack import Decoder, Encoder  # noqa: E402

from pybrws.http2 import (  # noqa: E402
    DATA,
    FLAG_ACK,
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    FLAG_PRIORITY,
    GOAWAY,
    HEADERS,
    PREFACE,
    SETTINGS,
    WINDOW_UPDATE,
    frame,
)

RELOADING_PAGE = (
    b"<!doctype html><title>pybrws</title>"
    b"<meta http-equiv=refresh content=1>"
    b"<p>cookie set, reloading to capture the request that carries it"
)
FORM_PAGE = (
    b"<!doctype html><title>pybrws</title>"
    b"<form id=f method=post action=/submit>"
    b"<input name=field value=value></form>"
    b"<script>document.getElementById('f').submit()</script>"
)
CLICK_PAGE = (
    b"<!doctype html><title>pybrws</title>"
    b"<style>body{font:16px system-ui;padding:3rem}"
    b"button{font:inherit;padding:.6rem 1.2rem}</style>"
    b"<form method=post action=/submit>"
    b"<input type=hidden name=field value=value>"
    b"<p>Click the button.<p><button type=submit>Submit</button></form>"
)
FETCH_PAGE = (
    b"<!doctype html><title>pybrws</title>"
    b"<script>fetch('/submit',{method:'POST',"
    b"headers:{'Content-Type':'application/json'},"
    b"body:JSON.stringify({field:'value'})})</script>"
)
PAGES = {"form": FORM_PAGE, "form-click": CLICK_PAGE, "fetch": FETCH_PAGE}


class Stream:
    def __init__(self) -> None:
        self.block = bytearray()
        self.body = bytearray()
        self.headers: list[tuple[str, str]] = []
        self.complete = False


class Session:
    """One HTTP/2 connection, serving whatever the capture needs."""

    def __init__(self, tls: ssl.SSLSocket, mode: str | None, set_cookie: bool) -> None:
        self.tls = tls
        self.mode = mode
        self.set_cookie = set_cookie
        self.decoder = Decoder()
        self.encoder = Encoder()
        self.buffer = bytearray()
        self.streams: dict[int, Stream] = {}
        self.captured: list[tuple[str, str]] | None = None
        self.captured_body = b""

    # -- wire ------------------------------------------------------------

    def read_exactly(self, n: int) -> bytes:
        while len(self.buffer) < n:
            chunk = self.tls.recv(65535)
            if not chunk:
                raise EOFError("client closed")
            self.buffer += chunk
        data = bytes(self.buffer[:n])
        del self.buffer[:n]
        return data

    def next_frame(self):
        header = self.read_exactly(9)
        length = int.from_bytes(header[:3], "big")
        return (header[3], header[4],
                int.from_bytes(header[5:9], "big") & 0x7FFFFFFF,
                self.read_exactly(length))

    def respond(self, stream_id: int, body: bytes, cookies: bool = False) -> None:
        fields = [(":status", "200"),
                  ("content-type", "text/html; charset=utf-8"),
                  ("content-length", str(len(body)))]
        if cookies:
            fields += [("set-cookie", "pybrws_probe=1; Path=/"),
                       ("set-cookie", "pybrws_second=2; Path=/")]
        self.tls.sendall(frame(HEADERS, FLAG_END_HEADERS, stream_id,
                               self.encoder.encode(fields)))
        self.tls.sendall(frame(DATA, FLAG_END_STREAM, stream_id, body))

    # -- behaviour -------------------------------------------------------

    def wanted(self, headers: list[tuple[str, str]]) -> bool:
        """Is this the request the run is waiting for?"""
        fields = {name: value for name, value in headers}
        dest = fields.get("sec-fetch-dest", "")
        if self.mode:
            return fields.get(":method", "").upper() == "POST"
        if self.set_cookie:
            return "cookie" in fields and dest == "document"
        return dest == "document"

    def page_for(self, headers: list[tuple[str, str]]) -> bytes | None:
        fields = {name: value for name, value in headers}
        if fields.get("sec-fetch-dest") != "document":
            return None
        if self.mode:
            return PAGES[self.mode]
        return RELOADING_PAGE

    def handle_complete(self, stream_id: int, stream: Stream) -> bool:
        """Returns True once the wanted request has been captured."""
        summary = " ".join(
            filter(None, [dict(stream.headers).get(":method"),
                          dict(stream.headers).get(":path")])
        )
        if self.wanted(stream.headers):
            print("  captured %s" % summary)
            self.captured = stream.headers
            self.captured_body = bytes(stream.body)
            self.respond(stream_id, b"captured")
            return True

        page = self.page_for(stream.headers)
        if page is None:
            print("  %s: not what is wanted, 404" % summary)
            self.tls.sendall(frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM,
                                   stream_id,
                                   self.encoder.encode([(":status", "404"),
                                                        ("content-length", "0")])))
            return False
        print("  %s: answering with the page that triggers the capture" % summary)
        self.respond(stream_id, page, cookies=self.set_cookie)
        return False

    def run(self, deadline: float) -> bool:
        if self.read_exactly(len(PREFACE)) != PREFACE:
            raise ValueError("client did not send the HTTP/2 preface")
        self.tls.sendall(frame(SETTINGS, 0, 0, b""))

        while time.monotonic() < deadline:
            frame_type, flags, stream_id, payload = self.next_frame()

            if frame_type == SETTINGS and not flags & FLAG_ACK:
                self.tls.sendall(frame(SETTINGS, FLAG_ACK, 0))
            elif frame_type == GOAWAY:
                return False
            elif frame_type in (HEADERS, 0x09):
                stream = self.streams.setdefault(stream_id, Stream())
                block = payload[5:] if flags & FLAG_PRIORITY else payload
                stream.block += block
                if flags & FLAG_END_HEADERS:
                    stream.headers = [
                        (name.decode() if isinstance(name, bytes) else name,
                         value.decode() if isinstance(value, bytes) else value)
                        for name, value in self.decoder.decode(bytes(stream.block),
                                                               raw=True)
                    ]
                if flags & FLAG_END_STREAM:
                    stream.complete = True
            elif frame_type == DATA:
                stream = self.streams.setdefault(stream_id, Stream())
                stream.body += payload
                if payload:
                    inc = len(payload).to_bytes(4, "big")
                    self.tls.sendall(frame(WINDOW_UPDATE, 0, 0, inc))
                    self.tls.sendall(frame(WINDOW_UPDATE, 0, stream_id, inc))
                if flags & FLAG_END_STREAM:
                    stream.complete = True

            stream = self.streams.get(stream_id)
            if stream and stream.complete and stream.headers:
                stream.complete = False
                if self.handle_complete(stream_id, stream):
                    return True
        return False


def render(headers: list[tuple[str, str]], body: bytes) -> str:
    lines = [name + ": " + value for name, value in headers]
    text = "\n".join(lines)
    if body:
        text += "\n\n" + body.decode("utf-8", "replace")
    return text


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("out")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4443)
    parser.add_argument("--hostname", default="pybrws.127.0.0.1.nip.io")
    parser.add_argument("--wait", type=float, default=120.0)
    parser.add_argument("--set-cookie", action="store_true",
                        help="answer with Set-Cookie and capture the reload")
    parser.add_argument("--post", choices=["form", "form-click", "fetch"],
                        dest="mode", help="answer with a page that posts")
    args = parser.parse_args()

    context, holder = _selfsigned.context(args.hostname, ["h2"])
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(8)
    print("listening on https://%s:%d, offering ALPN h2"
          % (args.hostname, args.port))
    print("the certificate is self-signed; accept the browser's warning")

    deadline = time.monotonic() + args.wait
    captured = None
    try:
        while time.monotonic() < deadline and captured is None:
            listener.settimeout(max(deadline - time.monotonic(), 0.1))
            try:
                raw, peer = listener.accept()
            except TimeoutError:
                break
            try:
                tls = context.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError):
                print("  handshake failed from port %d" % peer[1])
                raw.close()
                continue
            if tls.selected_alpn_protocol() != "h2":
                print("  client refused h2, got %r" % tls.selected_alpn_protocol())
                tls.close()
                continue
            with tls:
                tls.settimeout(15)
                session = Session(tls, args.mode, args.set_cookie)
                try:
                    if session.run(deadline):
                        captured = session
                except (EOFError, OSError, ValueError) as exc:
                    print("  connection ended: %s" % type(exc).__name__)
    finally:
        listener.close()
        holder.cleanup()

    if captured is None:
        raise SystemExit("nothing captured")

    text = render(captured.captured, captured.captured_body)
    Path(args.out).write_text(text + "\n", encoding="utf-8")
    print("wrote %s" % args.out)
    print()
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
