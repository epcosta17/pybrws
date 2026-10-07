"""Minimal HTTP/2 client with explicit control over the connection preamble.

Frames are built by hand because the connection preface, the SETTINGS values,
the initial WINDOW_UPDATE and the HEADERS priority field are all part of the
fingerprint a server sees. HPACK encoding is delegated to `hpack`.
"""

from __future__ import annotations

from hpack import Decoder, Encoder

from . import headers as header_tools
from .handshake import Connection
from .message import (
    ContentEncodingError,
    IncrementalDecoder,
    Response,
    decompress,
)
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

SETTING_HEADER_TABLE_SIZE = 0x01
SETTING_INITIAL_WINDOW_SIZE = 0x04
SETTING_MAX_CONCURRENT_STREAMS = 0x03
SETTING_MAX_FRAME_SIZE = 0x05

# RFC 7540 defaults, in force until the peer's SETTINGS arrive.
DEFAULT_WINDOW = 65535
DEFAULT_MAX_FRAME = 16384
# No limit until the peer names one; a sane cap keeps a batch honest.
DEFAULT_MAX_STREAMS = 100

FLAG_END_STREAM = 0x01
FLAG_ACK = 0x01
FLAG_END_HEADERS = 0x04
FLAG_PADDED = 0x08
FLAG_PRIORITY = 0x20


class Http2Error(Exception):
    pass


class _Stream:
    """What has arrived for one request so far."""

    __slots__ = ("header_block", "fields", "body", "done", "error")

    def __init__(self) -> None:
        self.header_block = bytearray()
        self.fields: list[tuple[str, str]] = []
        self.body = bytearray()
        self.done = False
        self.error: Exception | None = None


def frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + stream_id.to_bytes(4, "big")
        + payload
    )


class Http2Connection:
    """Drives one HTTP/2 connection over an established TLS Connection."""

    def __init__(self, tls: Connection, *, profile=firefox157) -> None:
        if tls.alpn != "h2":
            raise Http2Error("ALPN negotiated " + repr(tls.alpn) + ", expected 'h2'")
        self.tls = tls
        self.profile = profile
        self.encoder = Encoder()
        self.decoder = Decoder()
        # The profile advertises a HEADER_TABLE_SIZE, which tells the peer how
        # large a dynamic table our decoder will accept. Announcing a size the
        # decoder cannot honour makes a conforming server break us.
        advertised = dict(profile.H2_SETTINGS).get(SETTING_HEADER_TABLE_SIZE)
        if advertised:
            self.decoder.max_allowed_table_size = advertised
        self.next_stream_id = profile.H2_FIRST_STREAM_ID
        self._buffer = bytearray()
        # Frames that arrive while a body is being sent are kept here, so
        # waiting for a WINDOW_UPDATE cannot swallow the response.
        self._pending: list[tuple[int, int, int, bytes]] = []
        # What the peer lets us send before it grants more. These are the
        # protocol defaults until its SETTINGS say otherwise.
        self.peer_window = DEFAULT_WINDOW
        self.peer_max_frame_size = DEFAULT_MAX_FRAME
        self._stream_windows: dict[int, int] = {}
        self._open: dict[int, _Stream] = {}
        self._peer_initial_window = DEFAULT_WINDOW
        self.peer_max_streams = DEFAULT_MAX_STREAMS
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
        # RFC 7540 section 8.1.2: field names are lowercase on the wire, and a
        # peer treats an uppercase one as a protocol error. Casing is part of
        # the fingerprint over HTTP/1.1 and is simply not expressible here.
        ordered += [(name.lower(), value) for name, value in headers]
        return self.encoder.encode(ordered)

    def _next_frame(self) -> tuple[int, int, int, bytes]:
        """The next frame, preferring any deferred while a body was sent."""
        if self._pending:
            return self._pending.pop(0)
        return self._frame_from_wire()

    def _frame_from_wire(self) -> tuple[int, int, int, bytes]:
        """Read a frame off the connection, ignoring the deferred queue.

        Separate from _next_frame because a reader that defers a frame must
        not then be handed its own deferral back, which spins forever.
        """
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

    def request(self, method: str, path: str, authority: str, *, headers=None,
                body: bytes = b"", context=None) -> Response:
        """Send one request and read its complete response."""
        stream_id = self.send_request(method, path, authority, headers=headers,
                                      body=body, context=context)
        return self._read_response(stream_id)

    def send_request(self, method: str, path: str, authority: str, *,
                     headers=None, body: bytes = b"", context=None) -> int:
        """Open a stream and send the request on it, without waiting.

        Returns the stream id, which `read_response` takes back. Several may
        be in flight at once, which is what HTTP/2 is for.
        """
        stream_id = self.next_stream_id
        self.next_stream_id += 2
        self._stream_windows[stream_id] = self._peer_initial_window
        self._open[stream_id] = _Stream()

        pseudo = {
            ":method": method,
            ":path": path,
            ":authority": authority,
            ":scheme": "https",
        }
        if headers is None:
            headers = self.profile.H2_NAVIGATION_HEADERS
        fields = {"authority": authority, "content_length": str(len(body))}
        if context:
            fields.update(context)
        headers = header_tools.fill(headers, **fields)
        if body and not header_tools.has(headers, "content-length"):
            headers = list(headers) + [("content-length", str(len(body)))]
        block = self._header_block(pseudo, headers)

        flags = FLAG_END_HEADERS if body else FLAG_END_STREAM | FLAG_END_HEADERS
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
        if body:
            self._send_body(stream_id, body)
        return stream_id

    def read_response(self, stream_id: int) -> Response:
        """Wait for one in-flight request to finish."""
        return self._read_response(stream_id)

    def stream_response(self, stream_id: int):
        """Yield (response, chunks) without holding the whole body.

        The response arrives with its headers filled and an empty body; the
        iterator then produces decoded chunks. A gigabyte CSV should not
        have to fit in memory twice.
        """
        stream = self._open[stream_id]
        while not stream.fields and not stream.done:
            self._pump()
        if stream.error is not None:
            self._open.pop(stream_id, None)
            raise stream.error

        status = 0
        headers: list[tuple[str, str]] = []
        for name, value in stream.fields:
            if name == ":status":
                status = int(value)
            elif not name.startswith(":"):
                headers.append((name, value))
        response = Response(status=status, headers=headers, http_version="h2")
        decoder = IncrementalDecoder(response.header("content-encoding") or "")

        def chunks():
            try:
                while True:
                    if stream.body:
                        raw = bytes(stream.body)
                        stream.body.clear()
                        decoded = decoder.feed(raw)
                        if decoded:
                            yield decoded
                    elif stream.done:
                        break
                    else:
                        self._pump()
                if stream.error is not None:
                    raise stream.error
                tail = decoder.finish()
                if tail:
                    yield tail
            finally:
                self._open.pop(stream_id, None)
                self._stream_windows.pop(stream_id, None)

        return response, chunks()

    def request_many(self, requests) -> list[Response]:
        """Send several requests over this connection and collect them all.

        Each entry is (method, path, authority) or a mapping of the keyword
        arguments `send_request` takes. They go out before any reply is
        read, which is the whole point: one round trip for the batch rather
        than one each.
        """
        batch = list(requests)
        limit = max(1, min(self.peer_max_streams, len(batch)))
        results: dict[int, Response] = {}
        order: list[int] = []
        queue = list(enumerate(batch))
        in_flight: dict[int, int] = {}

        def start(index, spec):
            if isinstance(spec, dict):
                stream_id = self.send_request(**spec)
            else:
                stream_id = self.send_request(*spec)
            in_flight[stream_id] = index
            order.append(stream_id)

        while queue and len(in_flight) < limit:
            start(*queue.pop(0))
        while in_flight:
            finished = self._pump()
            if finished is None or finished not in in_flight:
                continue
            index = in_flight.pop(finished)
            results[index] = self._finish(finished)
            if queue:
                start(*queue.pop(0))
        return [results[i] for i in range(len(batch))]

    def get(self, path: str, authority: str, *, headers=None) -> Response:
        return self.request("GET", path, authority, headers=headers)

    def _send_body(self, stream_id: int, body: bytes) -> None:
        """Write DATA frames, respecting both flow control windows."""
        offset = 0
        while offset < len(body):
            room = self._await_window(stream_id)
            size = min(room, self.peer_max_frame_size, len(body) - offset)
            chunk = body[offset : offset + size]
            offset += size
            last = offset >= len(body)
            self.tls.send(frame(DATA, FLAG_END_STREAM if last else 0,
                                stream_id, chunk))
            self.peer_window -= size
            self._stream_windows[stream_id] -= size

    def _await_window(self, stream_id: int) -> int:
        """Return how much may be sent now, reading frames until that is more
        than nothing. Anything that is not a window update is kept for the
        response reader rather than discarded."""
        while True:
            room = min(self.peer_window, self._stream_windows.get(stream_id, 0))
            if room > 0:
                return room
            frame_type, flags, frame_stream, payload = self._frame_from_wire()
            if frame_type == WINDOW_UPDATE:
                self._credit(frame_stream, int.from_bytes(payload[:4], "big"))
            elif frame_type == SETTINGS:
                if not flags & FLAG_ACK:
                    self._apply_settings(payload)
                    self.tls.send(frame(SETTINGS, FLAG_ACK, 0))
            elif frame_type == GOAWAY:
                raise Http2Error("GOAWAY while sending the request body")
            elif frame_type == RST_STREAM and frame_stream == stream_id:
                raise Http2Error("stream reset while sending the request body")
            else:
                self._pending.append((frame_type, flags, frame_stream, payload))

    def _credit(self, stream_id: int, increment: int) -> None:
        if stream_id == 0:
            self.peer_window += increment
        elif stream_id in self._stream_windows:
            self._stream_windows[stream_id] += increment

    def _apply_settings(self, payload: bytes) -> None:
        """Adopt the peer's limits: what it will decode, and what it will accept."""
        for offset in range(0, len(payload) - 5, 6):
            identifier = int.from_bytes(payload[offset:offset + 2], "big")
            value = int.from_bytes(payload[offset + 2:offset + 6], "big")
            if identifier == SETTING_HEADER_TABLE_SIZE:
                self.encoder.header_table_size = value
            elif identifier == SETTING_INITIAL_WINDOW_SIZE:
                # Applies to streams already open as a delta, per RFC 7540.
                delta = value - self._peer_initial_window
                self._peer_initial_window = value
                for open_stream in self._stream_windows:
                    self._stream_windows[open_stream] += delta
            elif identifier == SETTING_MAX_FRAME_SIZE:
                self.peer_max_frame_size = value
            elif identifier == SETTING_MAX_CONCURRENT_STREAMS:
                self.peer_max_streams = value

    def _pump(self) -> int | None:
        """Read one frame and file it against its stream.

        Returns the stream id if that stream just finished. HPACK has one
        decoder per connection and its state depends on every header block
        in order, so frames cannot be skipped for being someone else's:
        ignoring one corrupts every later header on the connection.
        """
        frame_type, flags, stream_id, payload = self._next_frame()

        if frame_type == WINDOW_UPDATE:
            self._credit(stream_id, int.from_bytes(payload[:4], "big"))
            return None
        if frame_type == SETTINGS:
            if not flags & FLAG_ACK:
                self._apply_settings(payload)
                self.tls.send(frame(SETTINGS, FLAG_ACK, 0))
            return None
        if frame_type == PING:
            if not flags & FLAG_ACK:
                self.tls.send(frame(PING, FLAG_ACK, 0, payload))
            return None
        if frame_type == GOAWAY:
            code = int.from_bytes(payload[4:8], "big")
            last = int.from_bytes(payload[:4], "big")
            for open_id, stream in self._open.items():
                if open_id > last:
                    stream.error = Http2Error("GOAWAY, error code " + str(code))
                    stream.done = True
            if not self._open:
                raise Http2Error("GOAWAY, error code " + str(code))
            return None

        stream = self._open.get(stream_id)
        if stream is None:
            return None

        if frame_type == RST_STREAM:
            code = int.from_bytes(payload[:4], "big")
            stream.error = Http2Error("stream reset, error code " + str(code))
            stream.done = True
        elif frame_type in (HEADERS, CONTINUATION):
            block = payload[5:] if (frame_type == HEADERS
                                    and flags & FLAG_PRIORITY) else payload
            stream.header_block += block
            if flags & FLAG_END_HEADERS:
                # Decoded here, not when the stream finishes. One HPACK
                # decoder serves the whole connection and its table evolves
                # with every block in wire order, so decoding in completion
                # order corrupts every header after the first reordering.
                stream.fields = self._decode(bytes(stream.header_block))
                stream.header_block = bytearray()
            if flags & FLAG_END_STREAM:
                stream.done = True
        elif frame_type == DATA:
            stream.body += payload
            if payload:
                # Both windows need replenishing. Topping up only the
                # connection stalls any response whose compressed size
                # passes the per-stream INITIAL_WINDOW_SIZE we advertised.
                increment = len(payload).to_bytes(4, "big")
                self.tls.send(frame(WINDOW_UPDATE, 0, 0, increment))
                if not flags & FLAG_END_STREAM:
                    self.tls.send(frame(WINDOW_UPDATE, 0, stream_id, increment))
            if flags & FLAG_END_STREAM:
                stream.done = True

        return stream_id if stream.done else None

    def _decode(self, block: bytes) -> list[tuple[str, str]]:
        return [
            (
                name.decode() if isinstance(name, bytes) else name,
                value.decode() if isinstance(value, bytes) else value,
            )
            for name, value in self.decoder.decode(block, raw=True)
        ]

    def _finish(self, stream_id: int) -> Response:
        stream = self._open.pop(stream_id)
        self._stream_windows.pop(stream_id, None)
        if stream.error is not None:
            raise stream.error

        decoded = stream.fields
        status = 0
        headers: list[tuple[str, str]] = []
        for name, value in decoded:
            if name == ":status":
                status = int(value)
            elif not name.startswith(":"):
                headers.append((name, value))

        response = Response(status=status, headers=headers, http_version="h2")
        response.body = decompress(bytes(stream.body),
                                   response.header("content-encoding") or "")
        return response

    def _read_response(self, stream_id: int) -> Response:
        while not self._open[stream_id].done:
            self._pump()
        return self._finish(stream_id)
