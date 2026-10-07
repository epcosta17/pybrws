"""Cookie storage and matching, following RFC 6265.

Only what a client needs: parse Set-Cookie, decide which cookies a request
carries, and render the Cookie header. SameSite is stored but not enforced,
since every request this client makes is a top-level navigation and the
attribute only restricts cross-site subrequests.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime

BOOLEAN_ATTRIBUTES = {"secure", "httponly"}


@dataclass
class Cookie:
    name: str
    value: str
    domain: str
    path: str
    expires: float | None = None
    secure: bool = False
    http_only: bool = False
    host_only: bool = True
    same_site: str = ""
    created: float = field(default_factory=time.time)

    def expired(self, now: float | None = None) -> bool:
        return self.expires is not None and self.expires <= (now or time.time())

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.name, self.domain, self.path)


def default_path(request_path: str) -> str:
    """RFC 6265 section 5.1.4: the directory the request lives in."""
    if not request_path.startswith("/"):
        return "/"
    cut = request_path.rfind("/")
    return "/" if cut <= 0 else request_path[:cut]


def domain_matches(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    if host == domain:
        return True
    return host.endswith("." + domain)


def path_matches(request_path: str, cookie_path: str) -> bool:
    if request_path == cookie_path:
        return True
    if not request_path.startswith(cookie_path):
        return False
    return cookie_path.endswith("/") or request_path[len(cookie_path)] == "/"


def _parse_expires(value: str) -> float | None:
    try:
        return parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError):
        return None


def parse_set_cookie(header: str, request_host: str, request_path: str) -> Cookie | None:
    """Turn one Set-Cookie value into a Cookie, or None if it is unusable."""
    parts = header.split(";")
    name, separator, value = parts[0].partition("=")
    if not separator or not name.strip():
        return None

    cookie = Cookie(
        name=name.strip(),
        value=value.strip(),
        domain=request_host.lower(),
        path=default_path(request_path),
    )

    max_age = None
    for attribute in parts[1:]:
        key, _, raw = attribute.partition("=")
        key = key.strip().lower()
        raw = raw.strip()
        if key in BOOLEAN_ATTRIBUTES:
            setattr(cookie, "secure" if key == "secure" else "http_only", True)
        elif key == "domain" and raw:
            candidate = raw.lstrip(".").lower()
            # A cookie may only widen to a domain the response host sits under.
            if domain_matches(request_host, candidate):
                cookie.domain = candidate
                cookie.host_only = False
        elif key == "path" and raw.startswith("/"):
            cookie.path = raw
        elif key == "expires" and raw:
            cookie.expires = _parse_expires(raw)
        elif key == "max-age" and raw:
            try:
                max_age = int(raw)
            except ValueError:
                pass
        elif key == "samesite":
            cookie.same_site = raw.lower()

    if max_age is not None:
        # Max-Age wins over Expires, and a non-positive value deletes.
        cookie.expires = time.time() + max_age if max_age > 0 else 0.0
    return cookie


class CookieJar:
    """Cookies for one session, keyed by name, domain and path."""

    def __init__(self) -> None:
        self._cookies: dict[tuple[str, str, str], Cookie] = {}

    def __len__(self) -> int:
        return len(self._cookies)

    def __iter__(self):
        return iter(list(self._cookies.values()))

    def clear(self) -> None:
        self._cookies.clear()

    def set(self, cookie: Cookie) -> None:
        if cookie.expired():
            self._cookies.pop(cookie.key, None)
            return
        existing = self._cookies.get(cookie.key)
        if existing is not None:
            # A replacement keeps the original creation time, which decides
            # ordering in the Cookie header.
            cookie.created = existing.created
        self._cookies[cookie.key] = cookie

    def absorb(self, headers, request_host: str, request_path: str) -> int:
        """Store every Set-Cookie in a response. Returns how many were kept."""
        stored = 0
        for name, value in headers:
            if name.lower() != "set-cookie":
                continue
            cookie = parse_set_cookie(value, request_host, request_path)
            if cookie is not None:
                self.set(cookie)
                stored += 1
        return stored

    def matching(self, host: str, path: str, *, secure: bool = True) -> list[Cookie]:
        host = host.lower()
        now = time.time()
        found = []
        for cookie in list(self._cookies.values()):
            if cookie.expired(now):
                del self._cookies[cookie.key]
                continue
            if cookie.secure and not secure:
                continue
            if cookie.host_only:
                if host != cookie.domain:
                    continue
            elif not domain_matches(host, cookie.domain):
                continue
            if not path_matches(path, cookie.path):
                continue
            found.append(cookie)
        # RFC 6265 section 5.4: longer paths first, then oldest first.
        found.sort(key=lambda c: (-len(c.path), c.created))
        return found

    def header_for(self, host: str, path: str, *, secure: bool = True) -> str | None:
        cookies = self.matching(host, path, secure=secure)
        if not cookies:
            return None
        return "; ".join(c.name + "=" + c.value for c in cookies)
