"""Front door: fetch a URL over whichever protocol ALPN selects."""

from __future__ import annotations

import ipaddress
from contextlib import contextmanager
from urllib.parse import urljoin, urlsplit

from .handshake import connect
from .http1 import Http1Connection
from .http2 import Http2Connection
from . import headers as header_tools
from . import hosts
from .message import DEFAULT_MAX_BODY, Response, encode_body
from .profiles import firefox157

DEFAULT_PORT = 443


class UnsupportedUrl(Exception):
    pass


class TooManyRedirects(Exception):
    pass


REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# What a caller sets for one origin and must not hand to another.
CREDENTIAL_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie"})
DEFAULT_PORTS = {"https": 443, "http": 80}


def split_target(url: str) -> tuple[str, int, str, str]:
    """Return host, port, authority and path-with-query for an https URL."""
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


class Unmeasured(Exception):
    """A profile has no capture for this kind of request."""


def origin_of(url: str) -> str:
    """The origin a browser serialises for Origin and Referer: https, the
    A-label host in lower case, an IPv6 literal in brackets, and the port
    only when it is not 443. Not the URL's netloc, which keeps whatever it
    was written with -- user:password@ included."""
    _host, _port, authority, _path = split_target(url)
    return "https://" + authority


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = hosts.ascii_host(parts.hostname or "")
    if hosts.is_ip_literal(host):
        host = ipaddress.ip_address(host).compressed   # [0:0::1] is [::1]
    return scheme, host, parts.port or DEFAULT_PORTS.get(scheme, DEFAULT_PORT)


def same_origin(a: str, b: str) -> bool:
    """Whether two URLs share scheme, host and port (RFC 6454), however they
    are spelled: case, an explicit default port, a U-label or its A-label.
    A URL that does not parse is another origin."""
    try:
        return _origin(a) == _origin(b)
    except ValueError:
        return False


def redirect_headers(headers, from_url: str, to_url: str):
    """The caller's headers for the next hop of a redirect.

    On a change of origin, Authorization, Proxy-Authorization and a Cookie
    the caller set are dropped, as curl and requests do: they were given for
    the first origin, and a redirect is the server's choice, not the
    caller's. Otherwise the headers are returned unchanged. A Session's own
    cookies are not affected; its jar picks them for each hop.
    """
    if headers is None or same_origin(from_url, to_url):
        return headers
    return [(name, value) for name, value in header_tools.as_pairs(headers)
            if name.lower() not in CREDENTIAL_HEADERS]


def _set(profile, name: str):
    """One of a profile's header lists, or a refusal that names it.

    A profile holds what was measured. Reaching for a list a browser was
    never captured sending raises Unmeasured, which says which measurement is
    missing and how to take it. Inventing a plausible set instead would
    produce a fingerprint that is wrong in a way nothing will reveal.
    """
    headers = getattr(profile, name, None)
    if headers is None:
        raise Unmeasured(
            "%s has no %s: that request kind was never captured for this "
            "browser. pybrws capture request and pybrws capture h2 take it."
            % (getattr(profile, "__name__", profile), name)
        )
    return headers


def header_set(profile, method: str, kind: str, http2: bool):
    """The profile's measured header list for this kind of request."""
    if kind == "image":
        # Measured in both profiles and, until now, unreachable: nothing in
        # the library routed to it, so a client fetching an image sent the
        # navigation headers. An image request differs in Accept, in all
        # three Sec-Fetch values and in Priority, so that was a navigation
        # claiming to be a subresource on every image a scraper pulled.
        return _set(profile, "H2_IMAGE_HEADERS" if http2 else "H1_IMAGE_HEADERS")
    if method.upper() in ("GET", "HEAD"):
        return _set(profile, "H2_NAVIGATION_HEADERS" if http2 else "H1_HEADERS")
    if kind == "form":
        return _set(profile, "H2_POST_FORM_HEADERS" if http2
                    else "H1_POST_FORM_HEADERS")
    if kind == "form-script":
        return _set(profile, "H2_POST_FORM_SCRIPT_HEADERS" if http2
                    else "H1_POST_FORM_SCRIPT_HEADERS")
    return _set(profile, "H2_POST_XHR_HEADERS" if http2
                else "H1_POST_XHR_HEADERS")


def fetch_once(url: str, *, method: str = "GET", profile=firefox157,
               timeout: float = 20.0, headers=None, body: bytes = b"",
               proxy=None, kind: str = "xhr", context=None,
               verify: bool = True, trust_store=None,
               max_body_size: int | None = DEFAULT_MAX_BODY) -> Response:
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
    host, port, authority, path = split_target(url)
    with connect(host, port, profile=profile, timeout=timeout,
                 proxy=proxy, verify=verify, trust_store=trust_store) as tls:
        http2 = tls.alpn == "h2"
        http = (Http2Connection(tls, profile=profile, max_body_size=max_body_size)
                if http2 else
                Http1Connection(tls, profile=profile, max_body_size=max_body_size))
        base = header_set(profile, method, kind, http2)
        response = http.request(method, path, authority,
                                headers=header_tools.merge(base, headers),
                                body=body, context=context)
    response.url = url
    return response


def request(url: str, *, method: str = "GET", profile=firefox157,
            timeout: float = 20.0, headers=None, data=None, json=None,
            follow_redirects: int = 0, proxy=None, kind: str = "xhr",
            referer: str | None = None, verify: bool = True,
            trust_store=None,
            max_body_size: int | None = DEFAULT_MAX_BODY) -> Response:
    """Send one request, optionally following redirects.

    Args:
        url: an https URL.
        method: the HTTP method. GET and HEAD send the profile's navigation
            headers, unless `kind` is "image"; any other method sends the
            set `kind` names.
        profile: the client to imitate.
        timeout: socket timeout in seconds.
        headers: values merged into the profile's header list, keeping its
            order. A value of None drops that header.
        data: bytes, a string, or a mapping to form-encode.
        json: an object to serialise as JSON.
        follow_redirects: how many redirects to follow. 0 returns the
            redirect itself, as curl does without -L.
        proxy: a proxy URL or Proxy, applied to every hop.
        kind: which header set to send. "xhr" is what `fetch` produces and
            what an API client wants; "form" is a person pressing a submit
            button; "form-script" is a page submitting on their behalf, which
            omits Sec-Fetch-User; "image" is a subresource fetch, which
            differs from a navigation in Accept, all three Sec-Fetch values
            and Priority, and applies to a GET.
        referer: the page a browser would have come from. Defaults to the
            target's own origin, since every captured POST carries one.
        verify: check the server's certificate. Off makes the connection
            interceptable without any sign of it.
        trust_store: the roots the chain must lead to, a
            `cryptography.x509.verification.Store`. None means
            `certs.default_store()`: Mozilla's roots plus the platform's.
        max_body_size: the most a body may be, received or decoded, before
            BodyTooLarge (128 MiB); None lifts the cap.

    Returns:
        The final response, with the body decompressed.

    Raises:
        TooManyRedirects: only when following was requested and the budget ran
            out while the server was still redirecting.
    """
    body, content_type = encode_body(data, json)
    origin = origin_of(url)
    context = {
        "origin": origin,
        "referer": origin + "/" if referer is None else referer,
        "content_type": content_type or "application/octet-stream",
    }

    seen = []
    for hop in range(follow_redirects + 1):
        response = fetch_once(url, method=method, profile=profile,
                              timeout=timeout, headers=headers, body=body,
                              proxy=proxy, kind=kind, context=context,
                              verify=verify, trust_store=trust_store,
                              max_body_size=max_body_size)
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
        next_url = urljoin(url, location)
        headers = redirect_headers(headers, url, next_url)
        url = next_url
        if response.status in (301, 302, 303) and method != "HEAD":
            # A browser turns these into a GET and drops the body.
            method, body = "GET", b""


def get(url: str, **kwargs) -> Response:
    """Fetch a URL. See `request` for the arguments."""
    return request(url, method="GET", **kwargs)


def post(url: str, **kwargs) -> Response:
    """Send a POST. See `request` for the arguments."""
    return request(url, method="POST", **kwargs)


@contextmanager
def stream(url: str, *, method: str = "GET", profile=firefox157,
           timeout: float = 20.0, headers=None, data=None, json=None,
           proxy=None, kind: str = "xhr", referer: str | None = None,
           verify: bool = True, trust_store=None):
    """Open a response and iterate its body without buffering it.

    Yields (response, chunks). The connection stays open for as long as the
    block runs, so the iterator has to be consumed inside it.

        with stream(url) as (response, chunks):
            for chunk in chunks:
                out.write(chunk)
    """
    body, content_type = encode_body(data, json)
    if content_type and not header_tools.has(header_tools.as_pairs(headers),
                                             "content-type"):
        headers = header_tools.as_pairs(headers) + [("Content-Type", content_type)]

    host, port, authority, path = split_target(url)
    origin = origin_of(url)
    context = {
        "origin": origin,
        "referer": origin + "/" if referer is None else referer,
        "content_type": content_type or "application/octet-stream",
    }

    with connect(host, port, profile=profile, timeout=timeout, proxy=proxy,
                 verify=verify, trust_store=trust_store) as tls:
        if tls.alpn != "h2":
            raise UnsupportedUrl("streaming needs HTTP/2; this server chose "
                                 + repr(tls.alpn))
        http = Http2Connection(tls, profile=profile)
        base = header_set(profile, method, kind, True)
        stream_id = http.send_request(method, path, authority,
                                      headers=header_tools.merge(base, headers),
                                      body=body, context=context)
        response, chunks = http.stream_response(stream_id)
        response.url = url
        yield response, chunks
