"""HTTP/3 requests, with the profile's ClientHello underneath.

aioquic is asyncio and the rest of this client is not, so this module offers
both: `Http3Client` for anyone already in an event loop, and `get`/`request`,
which run one of their own. The synchronous pair is what makes an HTTP/3
fetch look like the HTTP/2 one from the caller's side, which is the point --
a caller should not have to be rewritten because a host offers h3.

The request is the one captured from a browser over QUIC, not the HTTP/2
set carried over. HTTP/3 differs from HTTP/2 in the first fields of every
request:

- the pseudo-header order is `:method :scheme :authority :path` over QUIC
  against `:method :path :authority :scheme` over TCP;
- `te: trailers` is not sent, `te` being an HTTP/2 mechanism;
- `alt-used` is sent, carrying the authority.

The ten remaining headers keep their HTTP/2 values and order.

See `profiles/firefox157_quic.py` and
`fixtures/reference-firefox-157-quic-request.txt`.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from . import headers as header_tools
from . import hosts
from . import quic_impersonate
from .message import DEFAULT_MAX_BODY, Response, body_too_large, decompress, encode_body
from .profiles import firefox157, firefox157_quic

DEFAULT_PORT = 443

PSEUDO_ORDER = firefox157_quic.H3_PSEUDO_ORDER


class Http3Error(Exception):
    pass


def _pseudo(method: str, path: str, authority: str,
            order=None) -> list[tuple[bytes, bytes]]:
    values = {
        ":method": method.upper().encode(),
        ":path": path.encode(),
        ":authority": authority.encode(),
        ":scheme": b"https",
    }
    return [(name.encode(), values[name]) for name in (order or PSEUDO_ORDER)]


def request_fields(method: str, path: str, authority: str, headers=(),
                   pseudo_order=None) -> list[tuple[bytes, bytes]]:
    """The request's field list as bytes: pseudo-headers, then `headers`
    lowercased, each value the bytes it was received as (headers.to_wire).

    Raises ValueError for a field carrying CR, LF or NUL (headers.check_field).
    """
    headers = list(headers)
    for name, value in [(":method", method), (":path", path),
                        (":authority", authority), *headers]:
        header_tools.check_field(name, value)
    fields = _pseudo(method, path, authority, pseudo_order)
    fields += [(header_tools.to_wire(name.lower()), header_tools.to_wire(value))
               for name, value in headers]
    return fields


def _protocol():
    """The aioquic protocol subclass, imported late.

    aioquic is a development dependency for everything but this module, so
    importing it at module scope would make `import pybrws` need it.
    """
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.events import (ConnectionTerminated, HandshakeCompleted,
                                     ProtocolNegotiated, StreamReset)

    class Protocol(QuicConnectionProtocol):
        """One connection, several requests, each on its own stream."""

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            self._http = None
            self._pending: dict[int, asyncio.Future] = {}
            self._parts: dict[int, tuple[list, bytearray]] = {}
            # The most a response body may be, received or decoded; None
            # lifts it. open_connection sets it from the caller's.
            self.max_body_size: int | None = DEFAULT_MAX_BODY
            # Ours rather than aioquic's wait_connected(), which awaits a
            # shielded future: cancelling that wait on a timeout left an
            # exception in it that asyncio then logged as never retrieved.
            self.handshake = self._loop.create_future()

        # -- requests -------------------------------------------------------

        def send(self, method: str, path: str, authority: str,
                 headers=(), body: bytes = b"",
                 pseudo_order=None) -> asyncio.Future:
            # First, so a refused field raises before a stream is taken.
            fields = request_fields(method, path, authority, headers, pseudo_order)
            if self._http is None:
                # ProtocolNegotiated normally gets here first; a caller that
                # sends before the handshake settles should still work.
                self._http = H3Connection(self._quic)
            stream_id = self._quic.get_next_available_stream_id()
            self._http.send_headers(stream_id, fields, end_stream=not body)
            if body:
                self._http.send_data(stream_id, body, end_stream=True)
            waiter = self._loop.create_future()
            self._pending[stream_id] = waiter
            self._parts[stream_id] = ([], bytearray())
            self.transmit()
            return waiter

        # -- events ---------------------------------------------------------

        def quic_event_received(self, event) -> None:
            # A request whose stream or connection ends without an answer
            # fails now; it used to wait out its timeout, or forever.
            if isinstance(event, HandshakeCompleted) and not self.handshake.done():
                self.handshake.set_result(None)
            if isinstance(event, ConnectionTerminated):
                reason = "error 0x%x: %s" % (event.error_code,
                                            event.reason_phrase or "no reason given")
                if not self.handshake.done():
                    self.handshake.set_exception(Http3Error(
                        "the connection closed during the handshake (%s)" % reason))
                self._fail_all(Http3Error(
                    "the connection closed before the response was complete "
                    "(%s)" % reason))
                return
            if isinstance(event, StreamReset):
                self._fail(event.stream_id, Http3Error(
                    "the server reset the stream (error 0x%x)" % event.error_code))
            if isinstance(event, ProtocolNegotiated):
                self._http = H3Connection(self._quic)
            if self._http is None:
                return
            for http_event in self._http.handle_event(event):
                stream_id = getattr(http_event, "stream_id", None)
                if stream_id not in self._parts:
                    # A push or a control stream; nothing asked for it.
                    continue
                fields, body = self._parts[stream_id]
                if isinstance(http_event, HeadersReceived):
                    fields.extend(http_event.headers)
                elif isinstance(http_event, DataReceived):
                    if (self.max_body_size is not None
                            and len(body) + len(http_event.data) > self.max_body_size):
                        # Refused before it is held whole, as over TCP; what
                        # still arrives for the stream is dropped above.
                        self._fail(stream_id, body_too_large(self.max_body_size))
                        continue
                    body.extend(http_event.data)
                if http_event.stream_ended:
                    self._finish(stream_id)

        def _fail(self, stream_id: int, error: Exception) -> None:
            self._parts.pop(stream_id, None)
            waiter = self._pending.pop(stream_id, None)
            if waiter is not None and not waiter.done():
                waiter.set_exception(error)

        def _fail_all(self, error: Exception) -> None:
            for stream_id in list(self._pending):
                self._fail(stream_id, error)

        def _finish(self, stream_id: int) -> None:
            fields, body = self._parts.pop(stream_id)
            waiter = self._pending.pop(stream_id, None)
            if waiter is None or waiter.done():
                return
            try:
                waiter.set_result(self._response(fields, body))
            except Exception as exc:
                # This request's error, not the event loop's: raised here it
                # escaped into asyncio, and the caller waited out its timeout.
                waiter.set_exception(exc)

        def _response(self, fields, body: bytearray) -> Response:
            status = 0
            headers = []
            for name, value in fields:
                name = header_tools.from_wire(name)
                value = header_tools.from_wire(value)
                if name == ":status":
                    if not (len(value) == 3 and value.isascii() and value.isdigit()):
                        raise Http3Error("malformed :status %r" % value)
                    status = int(value)
                elif not name.startswith(":"):
                    headers.append((name, value))
            response = Response(status=status, headers=headers,
                                http_version="h3")
            encoding = response.header("content-encoding") or ""
            response.body = decompress(bytes(body), encoding,
                                       max_size=self.max_body_size)
            return response

        def connection_lost(self, exc) -> None:
            for waiter in self._pending.values():
                if not waiter.done():
                    waiter.set_exception(
                        exc or Http3Error("the connection closed before the "
                                          "response was complete"))
            self._pending.clear()
            super().connection_lost(exc)

    return Protocol


def split_target(url: str) -> tuple[str, int, str, str]:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise Http3Error("only https is supported, got " + repr(parts.scheme))
    if not parts.hostname:
        raise Http3Error("no host in " + repr(url))
    port = parts.port or DEFAULT_PORT
    host = hosts.ascii_host(parts.hostname)
    authority = hosts.authority_for(host, port, DEFAULT_PORT)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return host, port, authority, path


class Http3Client:
    """An open HTTP/3 connection. For callers already inside a loop."""

    def __init__(self, protocol, authority: str) -> None:
        self._protocol = protocol
        self._authority = authority

    async def request(self, method: str, path: str, *, headers=(),
                      body: bytes = b"", timeout: float = 30.0) -> Response:
        waiter = self._protocol.send(method, path, self._authority,
                                     headers=headers, body=body)
        return await asyncio.wait_for(waiter, timeout=timeout)

    async def get(self, path: str = "/", **kwargs) -> Response:
        return await self.request("GET", path, **kwargs)

    async def request_many(self, requests, timeout: float = 30.0):
        """Several requests at once on the one connection."""
        waiters = [
            self._protocol.send(method, path, self._authority,
                                headers=headers)
            for method, path, headers in requests
        ]
        return await asyncio.wait_for(asyncio.gather(*waiters), timeout=timeout)


async def open_connection(url: str, *, profile=firefox157_quic,
                          verify: bool = True, timeout: float = 30.0,
                          cadata: bytes | None = None,
                          max_body_size: int | None = DEFAULT_MAX_BODY):
    """Connect and hand back (client, closer). The caller closes.

    `cadata`: PEM certificates to trust as anchors, as aioquic takes them.
    `max_body_size`: the most a response body may be, received or decoded,
    before BodyTooLarge; None lifts it.
    """
    from aioquic.asyncio import connect

    quic_impersonate.install()
    host, port, authority, _path = split_target(url)
    configuration = quic_impersonate.configuration(host, profile=profile,
                                                   verify=verify, cadata=cadata)
    # aioquic's connect() can wait for the handshake itself, but with no
    # limit: a silent server held the caller until the idle timeout. So it
    # only opens the socket here, and the wait is ours, bounded.
    manager = connect(host, port, configuration=configuration,
                      create_protocol=_protocol(), wait_connected=False)
    protocol = await manager.__aenter__()
    protocol.max_body_size = max_body_size
    protocol.transmit()   # the first flight, which wait_connected=False holds
    try:
        await asyncio.wait_for(protocol.handshake, timeout=timeout)
    except BaseException:
        await manager.__aexit__(None, None, None)
        raise
    return Http3Client(protocol, authority), manager


async def fetch(url: str, *, method: str = "GET", headers=None,
                data=None, json=None, profile=firefox157_quic,
                verify: bool = True, timeout: float = 30.0,
                cadata: bytes | None = None,
                max_body_size: int | None = DEFAULT_MAX_BODY) -> Response:
    """One request on its own connection, from inside a loop.

    Raises:
        client.Unmeasured: for any method but GET and HEAD. No Firefox
            HTTP/3 POST has been captured, and sending the navigation set
            with a body attached is a request no browser makes (D8).
    """
    if method.upper() not in ("GET", "HEAD"):
        from .client import Unmeasured

        raise Unmeasured(
            "no Firefox HTTP/3 %s has been captured, so there is no measured "
            "header set to send. pybrws capture quic takes one; until then "
            "send it over TCP." % method.upper())
    body, content_type = encode_body(data, json)
    _host, _port, authority, _path = split_target(url)
    merged = header_tools.merge(profile.navigation_headers(authority), headers)
    if content_type and not header_tools.has(merged, "content-type"):
        merged = merged + [("Content-Type", content_type)]

    # One deadline for the whole operation, handshake and answer together.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    client, manager = await open_connection(url, profile=profile, verify=verify,
                                            timeout=timeout, cadata=cadata,
                                            max_body_size=max_body_size)
    try:
        _host, _port, _authority, path = split_target(url)
        response = await client.request(method, path, headers=merged, body=body,
                                        timeout=max(0.0, deadline - loop.time()))
        response.url = url
        return response
    finally:
        await manager.__aexit__(None, None, None)


def request(url: str, **kwargs) -> Response:
    """One HTTP/3 request, synchronously. Runs its own event loop."""
    return asyncio.run(fetch(url, **kwargs))


def get(url: str, **kwargs) -> Response:
    return request(url, method="GET", **kwargs)


def post(url: str, **kwargs) -> Response:
    return request(url, method="POST", **kwargs)
