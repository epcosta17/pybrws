#!/usr/bin/env python3
"""Capture a browser's ClientHello as sent over QUIC.

QUIC does not run over TLS, it carries TLS 1.3 inside: the handshake travels
in CRYPTO frames inside Initial packets, which are encrypted under keys
derived from a salt published in RFC 9001. So the ClientHello is still there
and still readable, and everything the TCP profile measures still applies.

What does not carry over is the extension list. Firefox cannot send
session_ticket over QUIC, because that is the TLS 1.2 resumption mechanism;
nor record_size_limit, because QUIC has no TLS records to limit. It must send
quic_transport_parameters (57), which is a fingerprint in its own right --
an ordered list of values a client picks for itself. Assuming the TCP profile
applies would be inventing a measurement, so this tool exists to take one.

The server is aioquic's, which already decrypts Initial packets; the raw
ClientHello is lifted by recording the buffer that aioquic is about to parse.

    python tools/catch_quic.py --out fixtures/firefox-157-quic.hex

Getting a browser to speak HTTP/3 at all needs an Alt-Svc advertisement over
TCP first -- see --advertise, and the note it prints.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import _selfsigned  # noqa: E402

import aioquic.tls as aioquic_tls  # noqa: E402
from aioquic.asyncio import serve  # noqa: E402
from aioquic.asyncio.protocol import QuicConnectionProtocol  # noqa: E402
from aioquic.h3.connection import H3Connection  # noqa: E402
from aioquic.h3.events import HeadersReceived  # noqa: E402
from aioquic.quic.configuration import QuicConfiguration  # noqa: E402
from aioquic.quic.events import ProtocolNegotiated  # noqa: E402

from pybrws.hexio import hexdump, save_hex  # noqa: E402
from pybrws.model import extension_name  # noqa: E402
from pybrws.parser import parse_client_hello  # noqa: E402

EXT_QUIC_TRANSPORT_PARAMETERS = 57
HANDSHAKE_HEADER = 4  # one byte of type, three of length

PAGE = (
    b"<!doctype html><meta charset=utf-8><title>pybrws</title>"
    b"<body style='font:16px system-ui;padding:3rem'>"
    b"<p>Captured over HTTP/3.</p>"
)

captured: list[bytes] = []


def record_client_hellos() -> None:
    """Make aioquic hand us the raw ClientHello on its way through.

    aioquic parses the message out of a Buffer, so the bytes are there to be
    taken: the three-byte handshake length says exactly how far they run.
    """
    original = aioquic_tls.pull_client_hello

    def recording(buf):
        # Buffer.data stops at the read position, so it holds everything
        # *before* the message. data_slice reaches past it, which is what the
        # raw bytes need.
        start = buf.tell()
        length = int.from_bytes(
            buf.data_slice(start + 1, start + HANDSHAKE_HEADER), "big")
        captured.append(
            bytes(buf.data_slice(start, start + HANDSHAKE_HEADER + length)))
        return original(buf)

    aioquic_tls.pull_client_hello = recording


class Responder(QuicConnectionProtocol):
    """Answers any request with one small page, over HTTP/3."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: H3Connection | None = None

    def quic_event_received(self, event) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic)
        elif self._http is None:
            return

        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self._http.send_headers(
                    http_event.stream_id,
                    [
                        (b":status", b"200"),
                        (b"content-type", b"text/html; charset=utf-8"),
                        (b"content-length", str(len(PAGE)).encode()),
                    ],
                )
                self._http.send_data(http_event.stream_id, PAGE, end_stream=True)
                self.transmit()


def describe(hello: bytes) -> None:
    parsed = parse_client_hello(hello)
    print("  %d bytes, %d extensions, %d cipher suites"
          % (len(hello), len(parsed.extensions), len(parsed.cipher_suites)))
    for extension in parsed.extensions:
        marker = ""
        if extension.type == EXT_QUIC_TRANSPORT_PARAMETERS:
            marker = "   <- QUIC's own"
        print("    %-5d %-32s %5d%s"
              % (extension.type, extension_name(extension.type),
                 len(extension.data), marker))


async def run(host: str, port: int, hostname: str, wait: float) -> bytes | None:
    cert_path, key_path = _selfsigned.build(hostname, Path(_tempdir()))
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=["h3"],
        max_datagram_frame_size=65536,
    )
    configuration.load_cert_chain(cert_path, key_path)

    record_client_hellos()
    server = await serve(host, port, configuration=configuration,
                         create_protocol=Responder)
    print("listening on https://%s:%d/ over QUIC" % (hostname, port))
    print("the certificate is self-signed")
    print()

    deadline = asyncio.get_event_loop().time() + wait
    while not captured and asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(0.2)
    server.close()
    return captured[0] if captured else None


_tempdirs: list = []


def _tempdir() -> str:
    import tempfile

    directory = tempfile.TemporaryDirectory()
    _tempdirs.append(directory)
    return directory.name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path,
                        help="where to write the captured ClientHello")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4443)
    parser.add_argument("--hostname", default="pybrws.127.0.0.1.nip.io")
    parser.add_argument("--wait", type=float, default=180.0)
    parser.add_argument("--dump", action="store_true")
    args = parser.parse_args()

    hello = asyncio.run(run(args.host, args.port, args.hostname, args.wait))
    if hello is None:
        print("no ClientHello captured")
        return 1

    describe(hello)
    if args.out is not None:
        save_hex(args.out, hello)
        print()
        print("wrote " + str(args.out))
    if args.dump:
        print()
        print(hexdump(hello))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
