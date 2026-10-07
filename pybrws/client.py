"""Front door: fetch a URL over whichever protocol ALPN selects."""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from .handshake import connect
from .http1 import Http1Connection
from .http2 import Http2Connection
from . import headers as header_tools
from .message import Response, encode_body
from .profiles import firefox157

DEFAULT_PORT = 443


class UnsupportedUrl(Exception):
    pass


class TooManyRedirects(Exception):
    pass


REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def fetch_once(url: str, *, method: str = "GET", profile=firefox157,
               timeout: float = 20.0, headers=None, body: bytes = b"",
               proxy=None) -> Response:
    """Fetch one URL without following redirects.

    The server picks the protocol through ALPN; both branches are implemented,
    so a host that only speaks HTTP/1.1 is handled the same as one that
    speaks HTTP/2.

    Args:
        url: an https URL.
        profile: the client to imitate.
        timeout: socket timeout in seconds.
        headers: values merged into the profile's header list, keeping its
            order. A value of None drops that header.

    Returns:
        The response, with the body decompressed.
    """
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UnsupportedUrl("only https is supported, got " + repr(parts.scheme))
    if not parts.hostname:
        raise UnsupportedUrl("no host in " + repr(url))

    host = parts.hostname
    port = parts.port or DEFAULT_PORT
    authority = host if port == DEFAULT_PORT else host + ":" + str(port)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    with connect(host, port, profile=profile, timeout=timeout,
                 proxy=proxy) as tls:
        if tls.alpn == "h2":
            http = Http2Connection(tls, profile=profile)
            base = profile.H2_NAVIGATION_HEADERS
        else:
            http = Http1Connection(tls, profile=profile)
            base = profile.H1_HEADERS
        response = http.request(method, path, authority,
                                headers=header_tools.merge(base, headers),
                                body=body)
    response.url = url
    return response


def request(url: str, *, method: str = "GET", profile=firefox157,
            timeout: float = 20.0, headers=None, data=None, json=None,
            follow_redirects: int = 0, proxy=None) -> Response:
    """Send one request, optionally following redirects.

    Args:
        url: an https URL.
        method: the HTTP method. Only the request line changes; a profile
            carries no measured header set for anything but a navigation.
        profile: the client to imitate.
        timeout: socket timeout in seconds.
        headers: values merged into the profile's header list, keeping its
            order. A value of None drops that header.
        data: bytes, a string, or a mapping to form-encode.
        json: an object to serialise as JSON.
        follow_redirects: how many redirects to follow. 0 returns the
            redirect itself, as curl does without -L.
        proxy: a proxy URL or Proxy, applied to every hop.

    Returns:
        The final response, with the body decompressed.

    Raises:
        TooManyRedirects: only when following was requested and the budget ran
            out while the server was still redirecting.
    """
    body, content_type = encode_body(data, json)
    if content_type and not header_tools.has(header_tools.as_pairs(headers),
                                             "content-type"):
        headers = header_tools.as_pairs(headers) + [("Content-Type", content_type)]

    seen = []
    for hop in range(follow_redirects + 1):
        response = fetch_once(url, method=method, profile=profile,
                              timeout=timeout, headers=headers, body=body,
                              proxy=proxy)
        response.history = list(seen)
        location = response.header("location")
        if response.status not in REDIRECT_STATUSES or not location:
            return response
        if hop == follow_redirects:
            if follow_redirects == 0:
                return response
            raise TooManyRedirects(
                "still redirecting after " + str(follow_redirects)
                + " hops, last " + repr(urljoin(url, location))
            )
        seen.append(response)
        url = urljoin(url, location)
        if response.status in (301, 302, 303) and method != "HEAD":
            # A browser turns these into a GET and drops the body.
            method, body = "GET", b""


def get(url: str, **kwargs) -> Response:
    """Fetch a URL. See `request` for the arguments."""
    return request(url, method="GET", **kwargs)


def post(url: str, **kwargs) -> Response:
    """Send a POST. See `request` for the arguments."""
    return request(url, method="POST", **kwargs)
