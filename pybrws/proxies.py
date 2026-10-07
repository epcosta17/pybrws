"""Outbound proxy support.

The TLS handshake runs on whatever socket it is handed, so a proxy only has
to produce a connected socket to the target. Nothing about the fingerprint
changes above this layer.

One thing does change below it: the TCP/IP signature a server sees becomes
the proxy's, not this machine's. The p0f check in tools/verify.py will stop
matching, by design.
"""

from __future__ import annotations

import base64
import os
import socket
import struct
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

DEFAULT_PORTS = {"http": 8080, "https": 8080, "socks5": 1080, "socks5h": 1080}
SOCKS_VERSION = 0x05
SOCKS_NO_AUTH = 0x00
SOCKS_USERPASS = 0x02
SOCKS_CONNECT = 0x01
SOCKS_DOMAIN = 0x03

SOCKS_ERRORS = {
    0x01: "general failure",
    0x02: "connection not allowed",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


class ProxyError(Exception):
    pass


@dataclass(frozen=True)
class Proxy:
    scheme: str
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    @property
    def is_socks(self) -> bool:
        return self.scheme.startswith("socks")

    def __str__(self) -> str:
        credentials = (self.username + "@") if self.username else ""
        return self.scheme + "://" + credentials + self.host + ":" + str(self.port)


def parse_proxy(url: str) -> Proxy:
    """Parse a proxy URL.

    Accepts http, https, socks5 and socks5h. Both SOCKS spellings resolve the
    target at the proxy, which is what a remote exit is for and what keeps
    DNS off this machine.
    """
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise ProxyError("unsupported proxy scheme " + repr(parts.scheme))
    if not parts.hostname:
        raise ProxyError("no host in proxy URL " + repr(url))
    return Proxy(
        scheme=scheme,
        host=parts.hostname,
        port=parts.port or DEFAULT_PORTS[scheme],
        username=unquote(parts.username) if parts.username else None,
        password=unquote(parts.password) if parts.password else None,
    )


# Checked in order, matching the convention curl and requests follow. Keeping
# credentials in the environment rather than on the command line keeps them
# out of shell history and process listings.
ENV_VARS = ("PYBRWS_PROXY", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")


def proxy_from_env() -> str | None:
    for name in ENV_VARS:
        value = os.environ.get(name)
        if value:
            return value
    return None


def resolve(proxy) -> Proxy | None:
    """Turn a proxy argument into a Proxy, falling back to the environment.

    Pass False to force a direct connection regardless of the environment.
    """
    if proxy is False:
        return None
    if proxy is None:
        proxy = proxy_from_env()
        if not proxy:
            return None
    return parse_proxy(proxy) if isinstance(proxy, str) else proxy


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProxyError("proxy closed after " + str(n - remaining) + " of "
                             + str(n) + " bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _http_connect(sock: socket.socket, proxy: Proxy, host: str, port: int) -> None:
    target = host + ":" + str(port)
    lines = ["CONNECT " + target + " HTTP/1.1", "Host: " + target]
    if proxy.username is not None:
        token = base64.b64encode(
            ((proxy.username or "") + ":" + (proxy.password or "")).encode()
        ).decode("ascii")
        lines.append("Proxy-Authorization: Basic " + token)
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))

    head = bytearray()
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(4096)
        if not chunk:
            raise ProxyError("proxy closed during CONNECT")
        head += chunk
        if len(head) > 65536:
            raise ProxyError("CONNECT response head too large")

    status_line = bytes(head).split(b"\r\n", 1)[0].decode("latin-1")
    fields = status_line.split(" ", 2)
    if len(fields) < 2 or not fields[1].isdigit():
        raise ProxyError("malformed CONNECT response " + repr(status_line))
    status = int(fields[1])
    if status // 100 != 2:
        raise ProxyError("proxy refused CONNECT: " + status_line.strip())


def _socks5_connect(sock: socket.socket, proxy: Proxy, host: str, port: int) -> None:
    methods = [SOCKS_NO_AUTH]
    if proxy.username is not None:
        methods.append(SOCKS_USERPASS)
    sock.sendall(bytes([SOCKS_VERSION, len(methods)] + methods))

    version, method = _recv_exactly(sock, 2)
    if version != SOCKS_VERSION:
        raise ProxyError("proxy answered SOCKS version " + str(version))
    if method == 0xFF:
        raise ProxyError("proxy rejected every offered authentication method")

    if method == SOCKS_USERPASS:
        if proxy.username is None:
            raise ProxyError("proxy requires credentials and none were given")
        user = proxy.username.encode()
        secret = (proxy.password or "").encode()
        sock.sendall(bytes([0x01, len(user)]) + user + bytes([len(secret)]) + secret)
        _, result = _recv_exactly(sock, 2)
        if result != 0x00:
            raise ProxyError("proxy rejected the credentials")
    elif method != SOCKS_NO_AUTH:
        raise ProxyError("proxy chose unsupported auth method " + str(method))

    name = host.encode("idna")
    if len(name) > 255:
        raise ProxyError("hostname too long for SOCKS5")
    sock.sendall(
        bytes([SOCKS_VERSION, SOCKS_CONNECT, 0x00, SOCKS_DOMAIN, len(name)])
        + name
        + struct.pack("!H", port)
    )

    version, reply, _, address_type = _recv_exactly(sock, 4)
    if version != SOCKS_VERSION:
        raise ProxyError("proxy answered SOCKS version " + str(version))
    if reply != 0x00:
        raise ProxyError("SOCKS5 connect failed: "
                         + SOCKS_ERRORS.get(reply, "code " + str(reply)))

    if address_type == 0x01:
        _recv_exactly(sock, 4)
    elif address_type == 0x04:
        _recv_exactly(sock, 16)
    elif address_type == SOCKS_DOMAIN:
        length = _recv_exactly(sock, 1)[0]
        _recv_exactly(sock, length)
    else:
        raise ProxyError("proxy returned address type " + str(address_type))
    _recv_exactly(sock, 2)  # bound port


def open_socket(host: str, port: int, *, proxy: Proxy | str | None = None,
                timeout: float = 20.0) -> socket.socket:
    """Return a socket connected to host:port, through `proxy` if given.

    Args:
        host: the target hostname. With a proxy it is never resolved locally.
        port: the target port.
        proxy: a Proxy, a proxy URL, None to read the environment, or False
            to force a direct connection.
        timeout: socket timeout in seconds.

    Raises:
        ProxyError: if the proxy refuses or speaks unexpectedly.
    """
    proxy = resolve(proxy)
    if proxy is None:
        return socket.create_connection((host, port), timeout=timeout)

    sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    try:
        if proxy.is_socks:
            _socks5_connect(sock, proxy, host, port)
        else:
            _http_connect(sock, proxy, host, port)
    except Exception:
        sock.close()
        raise
    return sock
