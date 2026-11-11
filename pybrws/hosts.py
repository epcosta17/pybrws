"""Host names as they go on the wire.

Three small rules every place that puts a host on the wire has to agree on:
whether it is an IP address, its ASCII form, and how it is written in an
authority. They used to be done inline and differently: Python's `idna`
codec (IDNA 2003, which maps `faß.de` to `fass.de`, a different domain from
the one a browser visits), and IPv6 literals written into an authority
without the brackets that tell the address from the port.
"""

from __future__ import annotations

import ipaddress

DEFAULT_PORT = 443


def is_ip_literal(host: str) -> bool:
    """Whether `host` is an IPv4 or IPv6 address rather than a name."""
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def ascii_host(host: str) -> str:
    """The form a browser puts in SNI, Host and :authority.

    An ASCII name is only lowercased, as a browser's URL parser does; going
    through IDNA 2008 would reject names browsers accept, such as one with
    an underscore. A name with non-ASCII characters becomes its A-label by
    UTS #46 non-transitional processing, which is what Firefox and Chrome
    do (`faß.de` -> `xn--fa-hia.de`). An IP literal is unchanged.
    """
    if is_ip_literal(host):
        return host.strip("[]")
    if host.isascii():
        return host.lower()
    import idna

    return idna.encode(host, uts46=True, transitional=False).decode("ascii")


def authority_for(host: str, port: int, default_port: int | None = DEFAULT_PORT) -> str:
    """`host[:port]`, with an IPv6 literal in brackets (RFC 3986 3.2.2).
    The port is left out when it is `default_port`; None always writes it."""
    written = "[%s]" % host if ":" in host else host
    return written if port == default_port else "%s:%d" % (written, port)
