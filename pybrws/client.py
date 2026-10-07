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


def header_set(profile, method: str, kind: str, http2: bool):
    """The profile's measured header list for this kind of request."""
    if method.upper() in ("GET", "HEAD"):
        return profile.H2_NAVIGATION_HEADERS if http2 else profile.H1_HEADERS
    if kind == "form":
        return profile.H2_POST_FORM_HEADERS if http2 else profile.H1_POST_FORM_HEADERS
    return profile.H2_POST_XHR_HEADERS if http2 else profile.H1_POST_XHR_HEADERS


def fetch_once(url: str, *, method: str = "GET", profile=firefox157,
               timeout: float = 20.0, headers=None, body: bytes = b"",
               proxy=None, kind: str = "xhr", context=None) -> Response:
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
        http2 = tls.alpn == "h2"
        http = (Http2Connection(tls, profile=profile) if http2
                else Http1Connection(tls, profile=profile))
        base = header_set(profile, method, kind, http2)
        response = http.request(method, path, authority,
                                headers=header_tools.merge(base, headers),
                                body=body, context=context)
    response.url = url
    return response


def request(url: str, *, method: str = "GET", profile=firefox157,
            timeout: float = 20.0, headers=None, data=None, json=None,
            follow_redirects: int = 0, proxy=None, kind: str = "xhr",
            referer: str | None = None) -> Response:
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
        kind: for a request with a body, which header set to send. "xhr" is
            what `fetch` produces and what an API client wants; "form" is
            what submitting a form produces.
        referer: the page a browser would have come from. Defaults to the
            target's own origin, since every captured POST carries one.

    Returns:
        The final response, with the body decompressed.

    Raises:
        TooManyRedirects: only when following was requested and the budget ran
            out while the server was still redirecting.
    """
    body, content_type = encode_body(data, json)
    origin = "https://" + (urlsplit(url).netloc or "")
    context = {
        "origin": origin,
        "referer": origin + "/" if referer is None else referer,
        "content_type": content_type or "application/octet-stream",
    }

    seen = []
    for hop in range(follow_redirects + 1):
        response = fetch_once(url, method=method, profile=profile,
                              timeout=timeout, headers=headers, body=body,
                              proxy=proxy, kind=kind, context=context)
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
