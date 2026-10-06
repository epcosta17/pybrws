"""Front door: fetch a URL over whichever protocol ALPN selects."""

from __future__ import annotations

from urllib.parse import urlsplit

from .handshake import connect
from .http1 import Http1Connection
from .http2 import Http2Connection
from .message import Response
from .profiles import firefox157

DEFAULT_PORT = 443


class UnsupportedUrl(Exception):
    pass


def get(url: str, *, profile=firefox157, timeout: float = 20.0, headers=None) -> Response:
    """Fetch one URL.

    The server picks the protocol through ALPN; both branches are implemented,
    so a host that only speaks HTTP/1.1 is handled the same as one that
    speaks HTTP/2.

    Args:
        url: an https URL.
        profile: the client to imitate.
        timeout: socket timeout in seconds.
        headers: overrides the profile's request headers.

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

    with connect(host, port, profile=profile, timeout=timeout) as tls:
        if tls.alpn == "h2":
            http = Http2Connection(tls, profile=profile)
        else:
            http = Http1Connection(tls, profile=profile)
        return http.get(path, authority, headers=headers)
