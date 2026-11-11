"""Minimal HTTP/2 client with explicit control over the connection preamble.

Frames are built by hand because the connection preface, the SETTINGS values,
the initial WINDOW_UPDATE and the HEADERS priority field are all part of the
fingerprint a server sees. HPACK encoding is delegated to `hpack`.
"""

from __future__ import annotations

from hpack import Decoder, Encoder
from hpack.exceptions import HPACKError

from . import headers as header_tools
from .handshake import Connection
from .message import (
    DEFAULT_MAX_BODY,
    ContentEncodingError,
    IncrementalDecoder,
    Response,
    body_too_large,
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
SETTING_ENABLE_PUSH = 0x02

# RFC 9113 section 6.5.2: the legal range of the values checked below.
MIN_MAX_FRAME = 16384
MAX_MAX_FRAME = 2**24 - 1
MAX_WINDOW = 2**31 - 1
# A header block may span CONTINUATION frames without end; this caps what is
# buffered before it decodes. The HTTP/1.1 head cap, for the same reason.
MAX_HEADER_BLOCK = 1 << 18

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


class StreamRefused(Http2Error):
    """Requests the server provably never processed: above a GOAWAY's
    last_stream_id, or reset with REFUSED_STREAM (RFC 9113 6.8, 8.7).

    `requests` carries them, in order, so a caller can send them again
    elsewhere -- safely for any method, since none of them was processed.
    """

    def __init__(self, message: str, requests=None) -> None:
        super().__init__(message)
        self.requests = list(requests or [])


class _Stream:
    """What has arrived for one request so far."""

    __slots__ = ("header_block", "fields", "trailers", "body", "done", "error")

    def __init__(self) -> None:
        self.header_block = bytearray()
        self.fields: list[tuple[str, str]] = []
        self.trailers: list[tuple[str, str]] = []
        self.body = bytearray()
        self.done = False
        self.error: Exception | None = None


def _status_of(fields) -> int:
    for name, value in fields:
        if name == ":status":
            try:
                return int(value)
            except ValueError:
                raise Http2Error("malformed :status %r" % value)
    return 0


def _strip_padding(flags: int, payload: bytes, *, priority: bool) -> bytes:
    """The content of a DATA or HEADERS payload, padding and priority removed.

    RFC 9113 6.1 and 6.2: with PADDED the payload starts with a pad length
    and ends with that much padding, and with PRIORITY (HEADERS only) five
    bytes of priority follow the pad length. A pad length that is not below
    the payload's is a connection error.
    """
    if flags & FLAG_PADDED:
        if not payload:
            raise Http2Error("PROTOCOL_ERROR: padded frame with no pad length")
        pad = payload[0]
        if pad >= len(payload):
            raise Http2Error(
                "PROTOCOL_ERROR: pad length %d is not below the frame payload "
                "of %d bytes (RFC 9113 6.1)" % (pad, len(payload)))
        payload = payload[1:len(payload) - pad]
    if priority:
        payload = payload[5:]
    return payload


def frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + stream_id.to_bytes(4, "big")
        + payload
    )


class Http2Connection:
    """Drives one HTTP/2 connection over an established TLS Connection."""

    def __init__(self, tls: Connection, *, profile=firefox157,
                 max_body_size: int | None = DEFAULT_MAX_BODY) -> None:
        """`max_body_size` caps what a stream may hold buffered, and what a
        buffered response decodes to (BodyTooLarge); None lifts the cap."""
        if tls.alpn != "h2":
            raise Http2Error("ALPN negotiated " + repr(tls.alpn) + ", expected 'h2'")
        self.tls = tls
        self.profile = profile
        self.max_body_size = max_body_size
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
        # What this client advertised it will accept: RFC 9113 4.2 makes a
        # larger frame a FRAME_SIZE_ERROR, checked before buffering it.
        self.local_max_frame = dict(profile.H2_SETTINGS).get(
            SETTING_MAX_FRAME_SIZE, DEFAULT_MAX_FRAME)
        self._stream_windows: dict[int, int] = {}
        self._open: dict[int, _Stream] = {}
        self._peer_initial_window = DEFAULT_WINDOW
        self.peer_max_streams = DEFAULT_MAX_STREAMS
        # Set once the connection can no longer be trusted to carry another
        # request -- its header table is unknown, or the peer is closing it.
        # A pool holding it drops it.
        self.broken = False
        # The last stream id a GOAWAY said the peer will process; None until
        # one arrives. No new stream may be opened after it.
        self.goaway_last: int | None = None
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
        # Before encoding: the encoder's table changes as it encodes, so a
        # refused field must stop the block before any of it is encoded.
        for name, value in ordered:
            header_tools.check_field(name, value)
        # Bytes, not str: hpack would encode a str as UTF-8, and a value is
        # the bytes it arrived as (headers.to_wire). Identical for ASCII.
        return self.encoder.encode(
            [(header_tools.to_wire(name), header_tools.to_wire(value))
             for name, value in ordered])

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
                if length > self.local_max_frame:
                    raise self._connection_error(
                        "FRAME_SIZE_ERROR: a %d-byte frame, above the %d this "
                        "client advertised (RFC 9113 4.2)"
                        % (length, self.local_max_frame))
                if len(self._buffer) >= 9 + length:
                    frame_type = self._buffer[3]
                    flags = self._buffer[4]
                    stream_id = int.from_bytes(self._buffer[5:9], "big") & 0x7FFFFFFF
                    payload = bytes(self._buffer[9 : 9 + length])
                    del self._buffer[: 9 + length]
                    return frame_type, flags, stream_id, payload
            chunk = self.tls.recv()
            if not chunk:
                # close_notify at a frame boundary: no frame is coming, so
                # whatever is still waiting for one has failed.
                raise Http2Error("connection closed")
            self._buffer += chunk

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
        if self.goaway_last is not None:
            raise StreamRefused("the peer sent GOAWAY, so no new stream may "
                                "be opened (RFC 9113 6.8)",
                                requests=[(method, path, authority)])
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
        # The block first: a refused header raises before a stream exists.
        block = self._header_block(pseudo, headers)

        stream_id = self.next_stream_id
        self.next_stream_id += 2
        self._stream_windows[stream_id] = self._peer_initial_window
        self._open[stream_id] = _Stream()

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
                        yield from decoder.pieces(raw)
                    elif stream.done:
                        break
                    else:
                        self._pump()
                if stream.error is not None:
                    raise stream.error
                tail = decoder.finish()
                if tail:
                    yield tail
                response.trailers = list(stream.trailers)
            finally:
                self._open.pop(stream_id, None)
                self._stream_windows.pop(stream_id, None)

        return response, chunks()

    def request_many(self, requests):
        """Send several requests over this connection; yield their responses.

        Each entry is (method, path, authority) or a mapping of the keyword
        arguments `send_request` takes. They go out before any reply is
        read, which is the whole point: one round trip for the batch rather
        than one each. Responses are yielded in request order.

        If the peer refuses some -- a GOAWAY below them, or REFUSED_STREAM --
        everything before the first refused one is yielded, then
        StreamRefused is raised carrying that request and every one after
        it, none of which the server processed. Before this it waited for
        them forever.
        """
        batch = list(requests)
        limit = max(1, min(self.peer_max_streams, len(batch))) if batch else 1
        outcomes: dict[int, object] = {}
        queue = list(enumerate(batch))
        in_flight: dict[int, int] = {}

        def start(index, spec) -> None:
            try:
                if isinstance(spec, dict):
                    stream_id = self.send_request(**spec)
                else:
                    stream_id = self.send_request(*spec)
            except StreamRefused as exc:
                outcomes[index] = exc
                return
            in_flight[stream_id] = index

        def fill() -> None:
            while queue and len(in_flight) < limit:
                start(*queue.pop(0))

        fill()
        for wanted in range(len(batch)):
            while wanted not in outcomes:
                if not in_flight:
                    fill()
                    if wanted in outcomes or not in_flight:
                        break
                self._pump()
                # Collect every stream that is now done, not only the one the
                # frame belonged to: a GOAWAY finishes several at once.
                done = [sid for sid in in_flight if self._open[sid].done]
                for stream_id in done:
                    index = in_flight.pop(stream_id)
                    try:
                        outcomes[index] = self._finish(stream_id)
                    except Exception as exc:   # kept, raised in request order
                        outcomes[index] = exc
                if done:
                    fill()
            outcome = outcomes.pop(wanted)
            if isinstance(outcome, StreamRefused):
                raise StreamRefused(str(outcome), requests=batch[wanted:])
            if isinstance(outcome, Exception):
                raise outcome
            yield outcome

    def get(self, path: str, authority: str, *, headers=None) -> Response:
        return self.request("GET", path, authority, headers=headers)

    def _send_body(self, stream_id: int, body: bytes) -> None:
        """Write DATA frames, respecting both flow control windows."""
        offset = 0
        while offset < len(body):
            room = self._await_window(stream_id)
            if room == 0:
                # The server already answered and told us to stop.
                return
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
                code = int.from_bytes(payload[:4], "big")
                if code == 0 and self._answered(stream_id):
                    # RFC 9113 8.1: a complete response followed by
                    # RST_STREAM(NO_ERROR) means "stop sending, here is the
                    # answer". The answer is in the deferred frames.
                    return 0
                raise Http2Error("stream reset while sending the request body")
            else:
                self._pending.append((frame_type, flags, frame_stream, payload))

    def _answered(self, stream_id: int) -> bool:
        """Whether the deferred frames already end this stream's response."""
        return any(kind in (HEADERS, DATA) and owner == stream_id
                   and flags & FLAG_END_STREAM
                   for kind, flags, owner, _payload in self._pending)

    def _credit(self, stream_id: int, increment: int) -> None:
        if stream_id == 0:
            self.peer_window += increment
        elif stream_id in self._stream_windows:
            self._stream_windows[stream_id] += increment

    def _connection_error(self, message: str) -> Http2Error:
        self.broken = True
        return Http2Error(message)

    def _apply_settings(self, payload: bytes) -> None:
        """Adopt the peer's limits: what it will decode, and what it will accept.

        Values outside RFC 9113's ranges are connection errors. A
        MAX_FRAME_SIZE of 0, accepted, made the body writer send empty DATA
        frames forever without reading.
        """
        if len(payload) % 6:
            raise self._connection_error(
                "FRAME_SIZE_ERROR: a SETTINGS payload of %d bytes is not a "
                "multiple of 6 (RFC 9113 6.5)" % len(payload))
        for offset in range(0, len(payload), 6):
            identifier = int.from_bytes(payload[offset:offset + 2], "big")
            value = int.from_bytes(payload[offset + 2:offset + 6], "big")
            if identifier == SETTING_ENABLE_PUSH and value not in (0, 1):
                raise self._connection_error(
                    "PROTOCOL_ERROR: SETTINGS_ENABLE_PUSH %d (RFC 9113 6.5.2)" % value)
            if identifier == SETTING_INITIAL_WINDOW_SIZE and value > MAX_WINDOW:
                raise self._connection_error(
                    "FLOW_CONTROL_ERROR: SETTINGS_INITIAL_WINDOW_SIZE %d "
                    "(RFC 9113 6.5.2)" % value)
            if (identifier == SETTING_MAX_FRAME_SIZE
                    and not MIN_MAX_FRAME <= value <= MAX_MAX_FRAME):
                raise self._connection_error(
                    "PROTOCOL_ERROR: SETTINGS_MAX_FRAME_SIZE %d outside "
                    "16384..16777215 (RFC 9113 6.5.2)" % value)
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
            last = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
            # The peer is closing. Streams up to `last` may still complete;
            # those above it were never processed and never will be.
            self.goaway_last = last
            self.broken = True
            for open_id, stream in self._open.items():
                if open_id > last and not stream.done:
                    stream.error = StreamRefused(
                        "GOAWAY (error code %d) above stream %d" % (code, last))
                    stream.done = True
            return None

        stream = self._open.get(stream_id)
        if stream is None:
            return None

        if frame_type == RST_STREAM:
            code = int.from_bytes(payload[:4], "big")
            if code == 0x7:   # REFUSED_STREAM: never processed (RFC 9113 8.7)
                stream.error = StreamRefused("stream refused by the peer")
            else:
                stream.error = Http2Error("stream reset, error code " + str(code))
            stream.done = True
        elif frame_type in (HEADERS, CONTINUATION):
            block = (_strip_padding(flags, payload,
                                    priority=bool(flags & FLAG_PRIORITY))
                     if frame_type == HEADERS else payload)
            if len(stream.header_block) + len(block) > MAX_HEADER_BLOCK:
                raise self._connection_error(
                    "a header block past %d bytes (CONTINUATION without end)"
                    % MAX_HEADER_BLOCK)
            stream.header_block += block
            if flags & FLAG_END_HEADERS:
                # Decoded here, not when the stream finishes. One HPACK
                # decoder serves the whole connection and its table evolves
                # with every block in wire order, so decoding in completion
                # order corrupts every header after the first reordering.
                fields = self._decode(bytes(stream.header_block))
                stream.header_block = bytearray()
                status = _status_of(fields)
                if _status_of(stream.fields) >= 200:
                    # A block after the final head is trailers (RFC 9113
                    # 8.1); it used to overwrite the head, status and all.
                    stream.trailers = [(n, v) for n, v in fields
                                       if not n.startswith(":")]
                elif 100 <= status < 200 and status != 101:
                    pass   # informational, such as 103 Early Hints
                else:
                    stream.fields = fields
            if flags & FLAG_END_STREAM:
                stream.done = True
        elif frame_type == DATA:
            data = _strip_padding(flags, payload, priority=False)
            if stream.error is not None:
                pass   # refused already; what still arrives is dropped
            elif (self.max_body_size is not None
                    and len(stream.body) + len(data) > self.max_body_size):
                # Refused before it is held whole. Nothing can tell the peer
                # to stop (D10), so the connection goes with the stream.
                stream.error = body_too_large(self.max_body_size)
                stream.body = bytearray()
                stream.done = True
                self.broken = True
            else:
                stream.body += data
            if payload:
                # The whole payload, padding included, counts against flow
                # control (RFC 9113 6.9.1), so the whole payload is credited.
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
        # latin-1 both ways (headers.from_wire): a header is bytes, and
        # decoding as UTF-8 crashed on a latin-1 byte and changed the bytes
        # the proxy sidecar passed on.
        try:
            fields = self.decoder.decode(block, raw=True)
        except HPACKError as exc:
            # The shared header table is now in an unknown state, so every
            # later block on this connection would decode wrongly.
            self.broken = True
            raise Http2Error("COMPRESSION_ERROR: " + str(exc)) from exc
        for name, value in fields:
            if any(c in part for part in (name, value) for c in (b"\r", b"\n", b"\x00")):
                # RFC 9113 8.2.1: a malformed response. Its stream would be
                # reset, but nothing is sent (D10), so the connection goes.
                raise self._connection_error(
                    "PROTOCOL_ERROR: response field %r carries CR, LF or NUL "
                    "(RFC 9113 8.2.1)" % header_tools.from_wire(name))
        return [
            (header_tools.from_wire(name), header_tools.from_wire(value))
            for name, value in fields
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
        response.trailers = list(stream.trailers)
        response.body = decompress(bytes(stream.body),
                                   response.header("content-encoding") or "",
                                   max_size=self.max_body_size)
        return response

    def _read_response(self, stream_id: int) -> Response:
        while not self._open[stream_id].done:
            self._pump()
        return self._finish(stream_id)
