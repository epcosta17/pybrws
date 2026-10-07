"""HTTP/1.1 client.

Header order and capitalisation are part of the fingerprint at this layer, so
both come from the profile rather than from a dictionary.
"""

from __future__ import annotations

from .handshake import Connection
from . import headers as header_tools
from .message import Response, decompress
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

    def _fill(self) -> None:
        if self.eof:
            raise Http1Error("connection closed mid-message")
        try:
            chunk = self.tls.recv()
        except EOFError:
            self.eof = True
            raise Http1Error("connection closed mid-message")
        if not chunk:
            self.eof = True
            raise Http1Error("connection closed mid-message")
        self.buffer += chunk

    def read_until(self, delimiter: bytes, limit: int) -> bytes:
        while True:
            index = self.buffer.find(delimiter)
            if index >= 0:
                head = bytes(self.buffer[:index])
                del self.buffer[: index + len(delimiter)]
                return head
            if len(self.buffer) > limit:
                raise Http1Error("no " + repr(delimiter) + " within " + str(limit) + " bytes")
            self._fill()

    def read_exactly(self, n: int) -> bytes:
        while len(self.buffer) < n:
            self._fill()
        data = bytes(self.buffer[:n])
        del self.buffer[:n]
        return data

    def read_to_eof(self) -> bytes:
        while True:
            try:
                self._fill()
            except Http1Error:
                break
        data = bytes(self.buffer)
        self.buffer.clear()
        return data


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

    def __init__(self, tls: Connection, *, profile=firefox157) -> None:
        if tls.alpn not in ("", "http/1.1"):
            raise Http1Error("ALPN negotiated " + repr(tls.alpn) + ", expected http/1.1")
        self.tls = tls
        self.profile = profile
        self.reader = _StreamReader(tls)

    def build_request(self, method: str, path: str, authority: str, headers=None,
                      body: bytes = b"", context=None) -> bytes:
        if headers is None:
            headers = self.profile.H1_HEADERS
        fields = {"authority": authority, "content_length": str(len(body))}
        if context:
            fields.update(context)
        headers = header_tools.fill(headers, **fields)
        if body and not header_tools.has(headers, "content-length"):
            # Only reached when the header set carries no slot of its own.
            headers = list(headers) + [("Content-Length", str(len(body)))]
        lines = [method + " " + path + " HTTP/1.1"]
        for name, value in headers:
            lines.append(name + ": " + value)
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        return head + body

    def request(self, method: str, path: str, authority: str, *, headers=None,
                body: bytes = b"", context=None) -> Response:
        """Send one request and read its complete response."""
        self.tls.send(self.build_request(method, path, authority, headers,
                                         body, context))
        return self._read_response(method)

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
            return self.reader.read_exactly(int(length))
        return self.reader.read_to_eof()

    def _read_chunked(self) -> bytes:
        body = bytearray()
        while True:
            line = self.reader.read_until(b"\r\n", 1024)
            size = int(line.split(b";", 1)[0] or b"0", 16)
            if size == 0:
                # Optional trailer fields, then an empty line.
                while self.reader.read_until(b"\r\n", MAX_HEADER_BYTES):
                    pass
                return bytes(body)
            body += self.reader.read_exactly(size)
            self.reader.read_exactly(2)  # trailing CRLF

    def _read_response(self, method: str = "GET") -> Response:
        while True:
            head = self.reader.read_until(b"\r\n\r\n", MAX_HEADER_BYTES)
            status_line, _, header_block = head.partition(b"\r\n")
            version, status = _parse_status_line(status_line)
            if status != 100:
                break

        headers = _parse_headers(header_block)
        body = self._read_body(headers, status, method)
        response = Response(status=status, headers=headers, http_version=version)
        response.body = decompress(body, response.header("content-encoding") or "")
        return response
