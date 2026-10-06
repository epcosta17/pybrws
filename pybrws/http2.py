"""Minimal HTTP/2 client with explicit control over the connection preamble.

Frames are built by hand because the connection preface, the SETTINGS values,
the initial WINDOW_UPDATE and the HEADERS priority field are all part of the
fingerprint a server sees. HPACK encoding is delegated to `hpack`.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field

from hpack import Decoder, Encoder

from .handshake import Connection
from .profiles import firefox157

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA = 0x00
HEADERS = 0x01
PRIORITY = 0x02
RST_STREAM = 0x03
SETTINGS = 0x04
PUSH_PROMISE = 0x05
PING = 0x06
GOAWAY = 0x07
WINDOW_UPDATE = 0x08
CONTINUATION = 0x09

FLAG_END_STREAM = 0x01
FLAG_ACK = 0x01
FLAG_END_HEADERS = 0x04
FLAG_PADDED = 0x08
FLAG_PRIORITY = 0x20


class Http2Error(Exception):
    pass


def frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + stream_id.to_bytes(4, "big")
        + payload
    )


def decompress(body: bytes, encoding: str) -> bytes:
    encoding = encoding.strip().lower()
    if encoding in ("", "identity"):
        return body
    if encoding == "gzip":
        return zlib.decompress(body, wbits=47)
    if encoding == "deflate":
        return zlib.decompress(body, wbits=-15)
    if encoding == "br":
        import brotli

        return brotli.decompress(body)
    if encoding == "zstd":
        from compression import zstd

        return zstd.decompress(body)
    raise Http2Error("unsupported content-encoding " + encoding)


@dataclass
class Response:
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str) -> str | None:
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def text(self, errors: str = "replace") -> str:
        return self.body.decode("utf-8", errors)


class Http2Connection:
    """Drives one HTTP/2 connection over an established TLS Connection."""

    def __init__(self, tls: Connection, *, profile=firefox157) -> None:
        if tls.alpn != "h2":
            raise Http2Error("ALPN negotiated " + repr(tls.alpn) + ", expected 'h2'")
        self.tls = tls
        self.profile = profile
        self.encoder = Encoder()
        self.decoder = Decoder()
        self.next_stream_id = profile.H2_FIRST_STREAM_ID
        self._buffer = bytearray()
        self._send_preamble()

    def _send_preamble(self) -> None:
        settings = b"".join(
            identifier.to_bytes(2, "big") + value.to_bytes(4, "big")
            for identifier, value in self.profile.H2_SETTINGS
        )
        preamble = PREFACE + frame(SETTINGS, 0, 0, settings)
        increment = self.profile.H2_CONNECTION_WINDOW_UPDATE
        if increment:
            preamble += frame(WINDOW_UPDATE, 0, 0, increment.to_bytes(4, "big"))
        self.tls.send(preamble)

    def _header_block(self, pseudo: dict[str, str], headers) -> bytes:
        ordered = [(name, pseudo[name]) for name in self.profile.H2_PSEUDO_ORDER]
        ordered += list(headers)
        return self.encoder.encode(ordered)

    def _next_frame(self) -> tuple[int, int, int, bytes]:
        while True:
            if len(self._buffer) >= 9:
                length = int.from_bytes(self._buffer[:3], "big")
                if len(self._buffer) >= 9 + length:
                    frame_type = self._buffer[3]
                    flags = self._buffer[4]
                    stream_id = int.from_bytes(self._buffer[5:9], "big") & 0x7FFFFFFF
                    payload = bytes(self._buffer[9 : 9 + length])
                    del self._buffer[: 9 + length]
                    return frame_type, flags, stream_id, payload
            self._buffer += self.tls.recv()

    def get(self, path: str, authority: str, *, headers=None) -> Response:
        """Send one GET and read its complete response."""
        stream_id = self.next_stream_id
        self.next_stream_id += 2

        pseudo = {
            ":method": "GET",
            ":path": path,
            ":authority": authority,
            ":scheme": "https",
        }
        if headers is None:
            headers = self.profile.H2_NAVIGATION_HEADERS
        block = self._header_block(pseudo, headers)

        flags = FLAG_END_STREAM | FLAG_END_HEADERS
        payload = block
        priority = getattr(self.profile, "H2_HEADERS_PRIORITY", None)
        if priority:
            flags |= FLAG_PRIORITY
            dependency = priority["depends_on"] | (0x80000000 if priority["exclusive"] else 0)
            # RFC 7540: the wire carries weight - 1.
            payload = (
                dependency.to_bytes(4, "big")
                + bytes([priority["weight"] - 1])
                + block
            )

        self.tls.send(frame(HEADERS, flags, stream_id, payload))
        return self._read_response(stream_id)

    def _read_response(self, stream_id: int) -> Response:
        header_block = bytearray()
        body = bytearray()
        done = False

        while not done:
            frame_type, flags, frame_stream, payload = self._next_frame()

            if frame_type == SETTINGS and not flags & FLAG_ACK:
                self.tls.send(frame(SETTINGS, FLAG_ACK, 0))
            elif frame_type == PING and not flags & FLAG_ACK:
                self.tls.send(frame(PING, FLAG_ACK, 0, payload))
            elif frame_type == GOAWAY:
                code = int.from_bytes(payload[4:8], "big")
                raise Http2Error("GOAWAY, error code " + str(code))
            elif frame_type == RST_STREAM and frame_stream == stream_id:
                code = int.from_bytes(payload[:4], "big")
                raise Http2Error("stream reset, error code " + str(code))
            elif frame_stream != stream_id:
                continue
            elif frame_type in (HEADERS, CONTINUATION):
                block = payload
                if frame_type == HEADERS and flags & FLAG_PRIORITY:
                    block = block[5:]
                header_block += block
                done = bool(flags & FLAG_END_STREAM)
            elif frame_type == DATA:
                body += payload
                if payload:
                    self.tls.send(
                        frame(WINDOW_UPDATE, 0, 0, len(payload).to_bytes(4, "big"))
                    )
                done = bool(flags & FLAG_END_STREAM)

        decoded = [
            (
                name.decode() if isinstance(name, bytes) else name,
                value.decode() if isinstance(value, bytes) else value,
            )
            for name, value in self.decoder.decode(bytes(header_block), raw=True)
        ]
        status = 0
        headers: list[tuple[str, str]] = []
        for name, value in decoded:
            if name == ":status":
                status = int(value)
            elif not name.startswith(":"):
                headers.append((name, value))

        response = Response(status=status, headers=headers)
        encoding = response.header("content-encoding") or ""
        response.body = decompress(bytes(body), encoding)
        return response
