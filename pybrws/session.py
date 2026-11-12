"""A session: persistent cookies, reused connections, shared defaults.

Reuse is not only a speed matter. A browser opens one connection and carries
many requests over it; a client that performs a fresh handshake for every
request has a distinguishable rhythm no matter how right the bytes are.
"""

from __future__ import annotations

import socket
from urllib.parse import urljoin, urlsplit

from . import hosts
from .client import (REDIRECT_STATUSES, TooManyRedirects, UnsupportedUrl,
                     header_set, origin_of, redirect_headers)
from . import headers as header_tools
from .cookies import CookieJar
from .tickets import TicketStore
from .handshake import connect
from .http1 import Http1Connection, Http1Error
from .http2 import Http2Connection, Http2Error, StreamRefused
from .message import DEFAULT_MAX_BODY, Response, encode_body
from .profiles import firefox157
from .proxies import resolve
from .records import TlsAlert

DEFAULT_PORT = 443
# Transport failures: a pooled connection the peer has already closed
# surfaces as any of these. Whether one is retried is `may_retry`'s call.
RETRYABLE =(EOFError, TlsAlert, Http1Error, Http2Error, ConnectionError, OSError)

# Safe to send twice: repeating one cannot repeat an action (D5).
IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS"})
# Failures after which the server is known never to have processed the
# request: a stream refused or above a GOAWAY (RFC 9113 6.8, 8.7), a
# connection refused, a name that did not resolve.
NEVER_PROCESSED = (StreamRefused, ConnectionRefusedError, socket.gaierror)


def may_retry(method: str, error: Exception, response_started: bool) -> bool:
    """Whether a request that failed with `error` may be sent again.

    If the server never processed it, any method may go again, POST
    included. Otherwise it may have acted on it -- a timeout or a reset says
    nothing either way -- so only GET, HEAD and OPTIONS go again, and only
    if no part of an answer had arrived.
    """
    if isinstance(error, NEVER_PROCESSED):
        return True
    return method.upper() in IDEMPOTENT and not response_started


def split_url(url: str) -> tuple[str, int, str, str]:
    """Return host, port, authority and path-with-query."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UnsupportedUrl("only https is supported, got " + repr(parts.scheme))
    if not parts.hostname:
        raise UnsupportedUrl("no host in " + repr(url))
    port = parts.port or DEFAULT_PORT
    host = hosts.ascii_host(parts.hostname)
    authority = hosts.authority_for(host, port, DEFAULT_PORT)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return host, port, authority, path


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
                 trust_store=None,
                 max_body_size: int | None = DEFAULT_MAX_BODY) -> None:
        self.profile = profile
        self.max_body_size = max_body_size
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
        proxy = resolve(self.proxy, host)
        return (host, port, str(proxy) if proxy else None)

    def _open(self, host: str, port: int, timeout: float | None = None):
        tls = connect(host, port, profile=self.profile,
                      timeout=self.timeout if timeout is None else timeout,
                      proxy=self.proxy, verify=self.verify,
                      trust_store=self.trust_store, tickets=self.tickets)
        if tls.alpn == "h2":
            http = Http2Connection(tls, profile=self.profile,
                                   max_body_size=self.max_body_size)
        else:
            http = Http1Connection(tls, profile=self.profile,
                                   max_body_size=self.max_body_size)
        return tls, http

    def _connection(self, host: str, port: int, timeout: float | None = None):
        key = self._key(host, port)
        existing = self._pool.get(key)
        if existing is not None:
            reusable = getattr(existing[1], "can_reuse", None)
            if reusable is None or reusable():
                return existing, True
            # The server closed it, or it cannot carry another request.
            self._discard(host, port)
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

    def _headers_for(self, host: str, path: str, http2: bool, override,
                     method: str = "GET", kind: str = "xhr"):
        # The measured set for this kind of request, as client.request picks
        # it: a navigation for GET and HEAD, a fetch or a form for a POST.
        base = header_tools.merge(header_set(self.profile, method, kind, http2),
                                  override)
        cookies = self.cookies.matching(host, path.split("?", 1)[0])
        if not cookies:
            return base
        # The cookie anchors were measured on navigations. No capture of a
        # POST that carries cookies exists, so on a POST set their place is
        # unmeasured: before the same anchor where the set has it, else last.
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

    def _send(self, host: str, port: int, http, method: str, path: str,
              authority: str, headers, body: bytes, context=None) -> Response:
        try:
            return http.request(method, path, authority, headers=headers,
                                body=body, context=context)
        except BaseException:
            # A failure that is not worth a retry can still leave the
            # connection mid-message -- a body refused for its size is
            # still on the wire -- and then the pool must not offer it again.
            if getattr(http, "broken", False):
                self._discard(host, port)
            raise

    def _once(self, url: str, headers, method: str = "GET",
              body: bytes = b"", timeout: float | None = None,
              kind: str = "xhr", context=None) -> Response:
        host, port, authority, path = split_url(url)
        (tls, http), reused = self._connection(host, port, timeout)
        request_headers = self._headers_for(host, path,
                                            isinstance(http, Http2Connection),
                                            headers, method, kind)
        try:
            response = self._send(host, port, http, method, path, authority,
                                  request_headers, body, context)
        except RETRYABLE as error:
            started = getattr(http, "response_started", False)
            self._discard(host, port)
            # Once, on a fresh connection. A request the server never saw
            # goes again wherever it failed; any other failure is retried
            # only on a pooled connection -- how one the peer had already
            # closed shows itself -- and only as may_retry allows.
            if not may_retry(method, error, started):
                raise
            if not reused and not isinstance(error, NEVER_PROCESSED):
                raise
            (tls, http), _ = self._connection(host, port, timeout)
            request_headers = self._headers_for(
                host, path, isinstance(http, Http2Connection), headers, method, kind
            )
            response = self._send(host, port, http, method, path, authority,
                                  request_headers, body, context)

        if getattr(http, "broken", False):
            # The peer is closing it, or its header state is lost: it may
            # not carry the next request, so the pool lets it go now.
            self._discard(host, port)
        self.cookies.absorb(response.headers, host, path.split("?", 1)[0])
        response.url = url
        return response

    def request(self, url: str, *, method: str = "GET", headers=None,
                data=None, json=None, timeout: float | None = None,
                follow_redirects: int | None = None, kind: str = "xhr",
                referer: str | None = None) -> Response:
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
            kind: which measured header set to send, as in client.request:
                "xhr" (what `fetch` produces), "form" (a person submitting),
                "form-script" (a page submitting), "image" (a subresource).
                A GET or HEAD is a navigation unless kind is "image".
            referer: the page a browser would have come from. Defaults to
                the target's own origin, as every captured POST carries one.

        Returns:
            The final response.

        Raises:
            TooManyRedirects: if the budget runs out while still redirecting.
        """
        body, content_type = encode_body(data, json)
        # The same slots client.request fills: a measured POST set carries
        # Origin, Referer and Content-Type in the places the capture put
        # them, instead of a Content-Type tacked on at the end.
        origin = origin_of(url)
        context = {
            "origin": origin,
            "referer": origin + "/" if referer is None else referer,
            "content_type": content_type or "application/octet-stream",
        }

        budget = self.follow_redirects if follow_redirects is None else follow_redirects
        seen = []
        for hop in range(budget + 1):
            response = self._once(url, headers, method, body, timeout, kind, context)
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
            next_url = urljoin(url, location)
            headers = redirect_headers(headers, url, next_url)
            url = next_url
            if response.status in (301, 302, 303) and method != "HEAD":
                method, body = "GET", b""

    def get(self, url: str, **kwargs) -> Response:
        """Fetch a URL. See `request` for the arguments."""
        return self.request(url, method="GET", **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        """Send a POST. See `request` for the arguments."""
        return self.request(url, method="POST", **kwargs)
