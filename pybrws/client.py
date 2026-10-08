"""Front door: fetch a URL over whichever protocol ALPN selects."""

from __future__ import annotations

from contextlib import contextmanager
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


def split_target(url: str) -> tuple[str, int, str, str]:
    """Return host, port, authority and path-with-query for an https URL."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UnsupportedUrl("only https is supported, got " + repr(parts.scheme))
    if not parts.hostname:
        raise UnsupportedUrl("no host in " + repr(url))
    port = parts.port or DEFAULT_PORT
    authority = (parts.hostname if port == DEFAULT_PORT
                 else parts.hostname + ":" + str(port))
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.hostname, port, authority, path


class Unmeasured(Exception):
    """A profile has no capture for this kind of request."""


def _set(profile, name: str):
    """One of a profile's header lists, or a refusal that names it.

    A profile holds what was measured. Reaching for a list a browser was
    never captured sending used to raise AttributeError from somewhere
    unhelpful; this says which measurement is missing and how to take it,
    because the alternative -- inventing a plausible set -- produces a
    fingerprint that is wrong in a way nothing will reveal.
    """
    headers = getattr(profile, name, None)
    if headers is None:
        raise Unmeasured(
            "%s has no %s: that request kind was never captured for this "
            "browser. tools/catch_request.py and tools/catch_h2.py take it."
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
               verify: bool = True, trust_store=None) -> Response:
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
            referer: str | None = None, verify: bool = True,
            trust_store=None) -> Response:
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
        trust_store: anchors to trust instead of the system's.

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
                              proxy=proxy, kind=kind, context=context,
                              verify=verify, trust_store=trust_store)
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
    origin = "https://" + (urlsplit(url).netloc or "")
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
