"""HTTP/1.1 client.

Header order and capitalisation are part of the fingerprint at this layer, so
both come from the profile rather than from a dictionary.
"""

from __future__ import annotations

import re
import select

from .handshake import Connection
from . import headers as header_tools
from .message import DEFAULT_MAX_BODY, Response, body_too_large, decompress
from .profiles import firefox157

MAX_HEADER_BYTES = 1 << 18
MAX_STATUS_LINE = 8192


class Http1Error(Exception):
    pass


class _StreamReader:
    """Buffers the TLS stream so the parser can read lines and exact counts."""

    def __init__(self, tls: Connection) -> None:
        self.tls = tls
        self.buffer = bytearray()
        self.eof = False
        self.received = 0   # bytes read from the connection, all told

    def _fill(self) -> bool:
        """Read more into the buffer. False at a clean end of stream.

        Only close_notify is a clean end, and the TLS layer reports it as an
        empty read. A connection that simply stops (EOFError, which a bare
        FIN surfaces as) may have been cut by anyone on the path, so it
        raises: the caller cannot know what it did not receive.
        """
        if self.eof:
            return False
        try:
            chunk = self.tls.recv()
        except EOFError as exc:
            self.eof = True
            raise Http1Error("connection closed without close_notify, so the "
                             "message may be truncated") from exc
        if not chunk:
            self.eof = True
            return False
        self.received += len(chunk)
        self.buffer += chunk
        return True

    def read_until(self, delimiter: bytes, limit: int) -> bytes:
        while True:
            index = self.buffer.find(delimiter)
            if index >= 0:
                head = bytes(self.buffer[:index])
                del self.buffer[: index + len(delimiter)]
                return head
            if len(self.buffer) > limit:
                raise Http1Error("no " + repr(delimiter) + " within " + str(limit) + " bytes")
            if not self._fill():
                raise Http1Error("connection closed mid-message")

    def read_exactly(self, n: int) -> bytes:
        while len(self.buffer) < n:
            if not self._fill():
                raise Http1Error("connection closed mid-message")
        data = bytes(self.buffer[:n])
        del self.buffer[:n]
        return data

    def read_to_eof(self, limit: int | None = None) -> bytes:
        """A body whose length is the connection's: complete only at
        close_notify (RFC 9112 section 9.8). BodyTooLarge once more than
        `limit` bytes have arrived."""
        while self._fill():
            if limit is not None and len(self.buffer) > limit:
                raise body_too_large(limit)
        data = bytes(self.buffer)
        self.buffer.clear()
        return data


def _input_waiting(tls) -> bool:
    """Whether bytes or an EOF wait on the connection's socket."""
    sock = getattr(tls, "sock", None)
    if sock is None:
        return False   # not a socket (a scripted transport): nothing to see
    pending = getattr(sock, "pending", None)   # TLS to a proxy: decrypted, unread
    if pending is not None and pending():
        return True
    try:
        readable, _, _ = select.select([sock], [], [], 0)
    except (OSError, ValueError):
        return True    # closed underneath us
    return bool(readable)


def _size(text: bytes, pattern: bytes, base: int, what: str) -> int:
    """A framing number: digits only, as RFC 9112 writes them. int() also
    takes a sign, spaces and underscores, and a negative length sliced the
    buffer from its end."""
    text = text.strip()
    if not re.fullmatch(pattern, text):
        raise Http1Error("malformed %s %r" % (what, text[:40]))
    return int(text, base)


def _parse_status_line(line: bytes) -> tuple[str, int]:
    parts = line.split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        raise Http1Error("malformed status line " + repr(line[:80]))
    try:
        return parts[0].decode("ascii"), int(parts[1])
    except ValueError:
        raise Http1Error("malformed status code in " + repr(line[:80]))


def _parse_headers(block: bytes) -> list[tuple[str, str]]:
    headers = []
    for raw in block.split(b"\r\n"):
        if not raw:
            continue
        name, _, value = raw.partition(b":")
        headers.append(
            (name.decode("latin-1").strip(), value.decode("latin-1").strip())
        )
    return headers


class Http1Connection:
    """Drives one HTTP/1.1 connection over an established TLS Connection."""

    def __init__(self, tls: Connection, *, profile=firefox157,
                 max_body_size: int | None = DEFAULT_MAX_BODY) -> None:
        """`max_body_size` caps a body both as received and as decoded
        (BodyTooLarge); None lifts the cap."""
        if tls.alpn not in ("", "http/1.1"):
            raise Http1Error("ALPN negotiated " + repr(tls.alpn) + ", expected http/1.1")
        self.tls = tls
        self.profile = profile
        self.max_body_size = max_body_size
        # Set when a response is abandoned mid-body: what is left of it is
        # still on the wire, so the connection cannot carry another request.
        self.broken = False
        self.reader = _StreamReader(tls)
        self._sent_at = 0   # reader.received when the current request went out

    @property
    def response_started(self) -> bool:
        """Whether any byte of the current request's response has arrived."""
        return self.reader.received > self._sent_at

    def build_request(self, method: str, path: str, authority: str, headers=None,
                      body: bytes = b"", context=None) -> bytes:
        if headers is None:
            headers = self.profile.H1_HEADERS
        # No cookie unless the context gives one: a {cookie} slot nobody
        # filled is left out, never sent as written.
        fields = {"authority": authority, "content_length": str(len(body)),
                  "cookie": ""}
        if context:
            fields.update(context)
        headers = header_tools.fill(headers, **fields)
        if body and not header_tools.has(headers, "content-length"):
            # Only reached when the header set carries no slot of its own.
            headers = list(headers) + [("Content-Length", str(len(body)))]
        # Nothing is written until every line is known to be one line.
        header_tools.check_field(":method", method)
        header_tools.check_field(":path", path)
        for name, value in headers:
            header_tools.check_field(name, value)
        lines = [method + " " + path + " HTTP/1.1"]
        for name, value in headers:
            lines.append(name + ": " + value)
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        return head + body

    def request(self, method: str, path: str, authority: str, *, headers=None,
                body: bytes = b"", context=None) -> Response:
        """Send one request and read its complete response."""
        request = self.build_request(method, path, authority, headers, body, context)
        self._sent_at = self.reader.received
        try:
            self.tls.send(request)
            return self._read_response(method)
        except BaseException:
            # Whatever it was -- bad framing, a cap, a timeout, an interrupt
            # -- the connection is somewhere inside a message now, and the
            # next request written there would read the rest of this one.
            self.broken = True
            raise

    def can_reuse(self) -> bool:
        """Whether another request may be written here.

        Not once marked broken, and not once anything has arrived since the
        last response: on an idle HTTP/1.1 connection that is the server
        closing it -- a close_notify, an EOF, a 408 -- and a request written
        there would fail with no way to tell whether it was seen.
        """
        if self.broken or self.reader.buffer or self.reader.eof:
            return False
        return not _input_waiting(self.tls)

    def get(self, path: str, authority: str, *, headers=None) -> Response:
        return self.request("GET", path, authority, headers=headers)

    def _read_body(self, headers: list[tuple[str, str]], status: int,
                   method: str = "GET") -> bytes:
        lookup = {name.lower(): value for name, value in headers}
        if status < 200 or status in (204, 304) or method == "HEAD":
            return b""
        if "chunked" in lookup.get("transfer-encoding", "").lower():
            return self._read_chunked()
        length = lookup.get("content-length")
        if length is not None:
            size = _size(length.encode("latin-1"), rb"[0-9]+", 10, "Content-Length")
            if self.max_body_size is not None and size > self.max_body_size:
                raise body_too_large(self.max_body_size)   # before reading any
            return self.reader.read_exactly(size)
        return self.reader.read_to_eof(self.max_body_size)

    def _read_chunked(self) -> bytes:
        body = bytearray()
        while True:
            line = self.reader.read_until(b"\r\n", 1024)
            size = _size(line.split(b";", 1)[0], rb"[0-9A-Fa-f]+", 16, "chunk size")
            if size == 0:
                # Optional trailer fields, then an empty line.
                while self.reader.read_until(b"\r\n", MAX_HEADER_BYTES):
                    pass
                return bytes(body)
            if self.max_body_size is not None and len(body) + size > self.max_body_size:
                raise body_too_large(self.max_body_size)
            body += self.reader.read_exactly(size)
            self.reader.read_exactly(2)  # trailing CRLF

    def _read_response(self, method: str = "GET") -> Response:
        while True:
            head = self.reader.read_until(b"\r\n\r\n", MAX_HEADER_BYTES)
            status_line, _, header_block = head.partition(b"\r\n")
            version, status = _parse_status_line(status_line)
            # Every 1xx but 101 is informational: 100 Continue, 103 Early
            # Hints. Taking one as final leaves the real response unread, to
            # be mistaken for the answer to the next request on the
            # connection.
            if not 100 <= status < 200 or status == 101:
                break

        headers = _parse_headers(header_block)
        body = self._read_body(headers, status, method)
        tokens = {token.strip().lower() for name, value in headers
                  if name.lower() == "connection" for token in value.split(",")}
        if ("close" in tokens or self.reader.eof
                or (version == "HTTP/1.0" and "keep-alive" not in tokens)):
            # The server is done with this connection; it cannot carry
            # another request (RFC 9112 9.3, 9.6).
            self.broken = True
        response = Response(status=status, headers=headers, http_version=version)
        response.body = decompress(body, response.header("content-encoding") or "",
                                   max_size=self.max_body_size)
        return response
