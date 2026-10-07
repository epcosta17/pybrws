"""HTTP/3 requests, with the profile's ClientHello underneath.

aioquic is asyncio and the rest of this client is not, so this module offers
both: `Http3Client` for anyone already in an event loop, and `get`/`request`,
which run one of their own. The synchronous pair is what makes an HTTP/3
fetch look like the HTTP/2 one from the caller's side, which is the point --
a scraper should not have to be rewritten because a host offers h3.

The request is measured now, which it was not at first. The first version of
this module sent the HTTP/2 navigation set with the HTTP/2 pseudo-header
order, on the reasoning that HTTP/3 is HTTP/2 over QUIC. Two of the three
parts of that guess were wrong, and curl_cffi disagreeing is what prompted
the capture:

- the pseudo-header order is `:method :scheme :authority :path` over QUIC
  against `:method :path :authority :scheme` over TCP;
- `te: trailers` is not sent, `te` being an HTTP/2 mechanism;
- `alt-used` is, carrying the authority.

The ten shared headers do keep their HTTP/2 values and order, so the guess
was not worthless -- but the two it got wrong are both in the first four
fields of every request, which is the first thing anything looks at.

See `profiles/firefox157_quic.py` and
`fixtures/reference-firefox-157-quic-request.txt`.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from . import headers as header_tools
from . import quic_impersonate
from .message import Response, decompress, encode_body
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


def _protocol():
    """The aioquic protocol subclass, imported late.

    aioquic is a development dependency for everything but this module, so
    importing it at module scope would make `import pybrws` need it.
    """
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.events import ProtocolNegotiated

    class Protocol(QuicConnectionProtocol):
        """One connection, several requests, each on its own stream."""

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            self._http = None
            self._pending: dict[int, asyncio.Future] = {}
            self._parts: dict[int, tuple[list, bytearray]] = {}

        # -- requests -------------------------------------------------------

        def send(self, method: str, path: str, authority: str,
                 headers=(), body: bytes = b"",
                 pseudo_order=None) -> asyncio.Future:
            if self._http is None:
                # ProtocolNegotiated normally gets here first; a caller that
                # sends before the handshake settles should still work.
                self._http = H3Connection(self._quic)
            stream_id = self._quic.get_next_available_stream_id()
            fields = _pseudo(method, path, authority, pseudo_order)
            fields += [(name.lower().encode(), value.encode())
                       for name, value in headers]
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
                    body.extend(http_event.data)
                if http_event.stream_ended:
                    self._finish(stream_id)

        def _finish(self, stream_id: int) -> None:
            fields, body = self._parts.pop(stream_id)
            waiter = self._pending.pop(stream_id, None)
            if waiter is None or waiter.done():
                return
            status = 0
            headers = []
            for name, value in fields:
                name = name.decode("ascii", "replace")
                value = value.decode("ascii", "replace")
                if name == ":status":
                    status = int(value)
                elif not name.startswith(":"):
                    headers.append((name, value))
            response = Response(status=status, headers=headers,
                                http_version="h3")
            encoding = response.header("content-encoding") or ""
            response.body = decompress(bytes(body), encoding)
            waiter.set_result(response)

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
    authority = (parts.hostname if port == DEFAULT_PORT
                 else "%s:%d" % (parts.hostname, port))
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.hostname, port, authority, path


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
                          verify: bool = True, timeout: float = 30.0):
    """Connect and hand back (client, closer). The caller closes."""
    from aioquic.asyncio import connect

    quic_impersonate.install(profile=profile)
    host, port, authority, _path = split_target(url)
    configuration = quic_impersonate.configuration(host, profile=profile,
                                                   verify=verify)
    manager = connect(host, port, configuration=configuration,
                      create_protocol=_protocol())
    protocol = await manager.__aenter__()
    try:
        await asyncio.wait_for(protocol.wait_connected(), timeout=timeout)
    except BaseException:
        await manager.__aexit__(None, None, None)
        raise
    return Http3Client(protocol, authority), manager


async def fetch(url: str, *, method: str = "GET", headers=None,
                data=None, json=None, profile=firefox157_quic,
                verify: bool = True, timeout: float = 30.0) -> Response:
    """One request on its own connection, from inside a loop."""
    body, content_type = encode_body(data, json)
    _host, _port, authority, _path = split_target(url)
    merged = header_tools.merge(profile.navigation_headers(authority), headers)
    if content_type and not header_tools.has(merged, "content-type"):
        merged = merged + [("Content-Type", content_type)]

    client, manager = await open_connection(url, profile=profile,
                                            verify=verify, timeout=timeout)
    try:
        _host, _port, _authority, path = split_target(url)
        response = await client.request(method, path, headers=merged,
                                        body=body, timeout=timeout)
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
