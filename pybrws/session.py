"""A session: persistent cookies, reused connections, shared defaults.

Reuse is not only a speed matter. A browser opens one connection and carries
many requests over it; a client that performs a fresh handshake for every
request has a distinguishable rhythm no matter how right the bytes are.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from .client import REDIRECT_STATUSES, TooManyRedirects, UnsupportedUrl
from . import headers as header_tools
from .cookies import CookieJar
from .tickets import TicketStore
from .handshake import connect
from .http1 import Http1Connection, Http1Error
from .http2 import Http2Connection, Http2Error
from .message import Response, encode_body
from .profiles import firefox157
from .proxies import resolve
from .records import TlsAlert

DEFAULT_PORT = 443
# A pooled connection the peer has already closed surfaces as any of these.
# The retry is guarded on the connection having been reused, so the same
# failure on a fresh connection still propagates.
RETRYABLE = (EOFError, TlsAlert, Http1Error, Http2Error, ConnectionError, OSError)


def split_url(url: str) -> tuple[str, int, str, str]:
    """Return host, port, authority and path-with-query."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UnsupportedUrl("only https is supported, got " + repr(parts.scheme))
    if not parts.hostname:
        raise UnsupportedUrl("no host in " + repr(url))
    port = parts.port or DEFAULT_PORT
    authority = parts.hostname if port == DEFAULT_PORT else parts.hostname + ":" + str(port)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.hostname, port, authority, path


def insert_header(headers, name: str, value: str, before: str):
    """Place a header at a fixed point in the order, not at the end.

    Header order is part of the fingerprint, so a cookie appended after the
    last header would be wrong even with the right value.
    """
    out = []
    placed = False
    for existing, existing_value in headers:
        if not placed and existing.lower() == before.lower():
            out.append((name, value))
            placed = True
        if existing.lower() != name.lower():
            out.append((existing, existing_value))
    if not placed:
        out.append((name, value))
    return out


class Session:
    """Keeps cookies and connections across requests."""

    def __init__(self, *, profile=firefox157, proxy=None, timeout: float = 20.0,
                 follow_redirects: int = 5, verify: bool = True,
                 trust_store=None) -> None:
        self.profile = profile
        self.proxy = proxy
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify = verify
        self.trust_store = trust_store
        self.cookies = CookieJar()
        self.tickets = TicketStore()
        self._pool: dict[tuple, tuple] = {}

    # -- connections -------------------------------------------------------

    def _key(self, host: str, port: int) -> tuple:
        proxy = resolve(self.proxy)
        return (host, port, str(proxy) if proxy else None)

    def _open(self, host: str, port: int, timeout: float | None = None):
        tls = connect(host, port, profile=self.profile,
                      timeout=self.timeout if timeout is None else timeout,
                      proxy=self.proxy, verify=self.verify,
                      trust_store=self.trust_store, tickets=self.tickets)
        if tls.alpn == "h2":
            http = Http2Connection(tls, profile=self.profile)
        else:
            http = Http1Connection(tls, profile=self.profile)
        return tls, http

    def _connection(self, host: str, port: int, timeout: float | None = None):
        key = self._key(host, port)
        existing = self._pool.get(key)
        if existing is not None:
            return existing, True
        created = self._open(host, port, timeout)
        self._pool[key] = created
        return created, False

    def _discard(self, host: str, port: int) -> None:
        entry = self._pool.pop(self._key(host, port), None)
        if entry is not None:
            try:
                entry[0].close()
            except OSError:
                pass

    def close(self) -> None:
        for tls, _ in list(self._pool.values()):
            try:
                tls.close()
            except OSError:
                pass
        self._pool.clear()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- requests ----------------------------------------------------------

    def _headers_for(self, host: str, path: str, http2: bool, override):
        base = header_tools.merge(
            self.profile.H2_NAVIGATION_HEADERS if http2 else self.profile.H1_HEADERS,
            override,
        )
        cookies = self.cookies.matching(host, path.split("?", 1)[0])
        if not cookies:
            return base
        if http2:
            # Measured: Firefox sends one `cookie` field per cookie over
            # HTTP/2, which HPACK makes cheaper than one joined header.
            return header_tools.insert_all_before(
                base, "cookie",
                [c.name + "=" + c.value for c in cookies],
                self.profile.H2_COOKIE_BEFORE,
            )
        joined = "; ".join(c.name + "=" + c.value for c in cookies)
        return header_tools.insert_before(base, "Cookie", joined,
                                          self.profile.H1_COOKIE_BEFORE)

    def _once(self, url: str, headers, method: str = "GET",
              body: bytes = b"", timeout: float | None = None) -> Response:
        host, port, authority, path = split_url(url)
        (tls, http), reused = self._connection(host, port, timeout)
        request_headers = self._headers_for(host, path,
                                            isinstance(http, Http2Connection), headers)
        try:
            response = http.request(method, path, authority,
                                    headers=request_headers, body=body)
        except RETRYABLE:
            self._discard(host, port)
            if not reused:
                raise
            # A pooled connection the peer had already closed. One retry on a
            # fresh one, which is what a browser does rather than failing.
            (tls, http), _ = self._connection(host, port, timeout)
            request_headers = self._headers_for(
                host, path, isinstance(http, Http2Connection), headers
            )
            response = http.request(method, path, authority,
                                    headers=request_headers, body=body)

        self.cookies.absorb(response.headers, host, path.split("?", 1)[0])
        response.url = url
        return response

    def request(self, url: str, *, method: str = "GET", headers=None,
                data=None, json=None, timeout: float | None = None,
                follow_redirects: int | None = None) -> Response:
        """Send a request, carrying and collecting cookies.

        Args:
            url: an https URL.
            method: the HTTP method.
            headers: values merged into the profile's header list, keeping
                its order. A value of None drops that header.
            data: bytes, a string, or a mapping to form-encode.
            json: an object to serialise as JSON.
            timeout: overrides the session default for this request.
            follow_redirects: overrides the session default.

        Returns:
            The final response.

        Raises:
            TooManyRedirects: if the budget runs out while still redirecting.
        """
        body, content_type = encode_body(data, json)
        if content_type and not header_tools.has(header_tools.as_pairs(headers),
                                                 "content-type"):
            headers = header_tools.as_pairs(headers) + [("Content-Type", content_type)]

        budget = self.follow_redirects if follow_redirects is None else follow_redirects
        seen = []
        for hop in range(budget + 1):
            response = self._once(url, headers, method, body, timeout)
            response.history = list(seen)
            location = response.header("location")
            if response.status not in REDIRECT_STATUSES or not location:
                return response
            if hop == budget:
                if budget == 0:
                    return response
                raise TooManyRedirects(
                    "still redirecting after " + str(budget) + " hops, last "
                    + repr(urljoin(url, location))
                )
            seen.append(response)
            url = urljoin(url, location)
            if response.status in (301, 302, 303) and method != "HEAD":
                method, body = "GET", b""

    def get(self, url: str, **kwargs) -> Response:
        """Fetch a URL. See `request` for the arguments."""
        return self.request(url, method="GET", **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        """Send a POST. See `request` for the arguments."""
        return self.request(url, method="POST", **kwargs)
