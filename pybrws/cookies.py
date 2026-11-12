"""Cookie storage and matching, following RFC 6265.

Only what a client needs: parse Set-Cookie, decide which cookies a request
carries, and render the Cookie header. SameSite is stored but not enforced,
since every request this client makes is a top-level navigation and the
attribute only restricts cross-site subrequests.
"""

from __future__ import annotations

import functools
import threading
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime

from .hosts import is_ip_literal

BOOLEAN_ATTRIBUTES = {"secure", "httponly"}

# RFC 6265bis 5.6.1/5.6.2: no cookie outlives 400 days, whatever it asks for.
MAX_COOKIE_AGE = 400 * 24 * 3600


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
    """RFC 6265 5.1.3. The suffix case is for host names only: an IP address
    matches nothing but itself."""
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    if host == domain:
        return True
    return not is_ip_literal(host) and host.endswith("." + domain)


@functools.lru_cache(maxsize=1)
def _public_suffixes():
    """Mozilla's Public Suffix List as `publicsuffixlist` bundles it, loaded
    once, on the first Domain attribute. Both sections, ICANN and private
    (github.io), as browsers use them; a TLD the list does not name is a
    suffix too, by the list's default rule."""
    from publicsuffixlist import PublicSuffixList

    return PublicSuffixList()


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


def _has_control(text: str) -> bool:
    """A CTL other than HTAB: %x00-08 / %x0A-1F / %x7F. Only these: a byte
    such as 0x82, part of a UTF-8 sequence held as latin-1, is not one."""
    return any((ch < " " and ch != "\t") or ch == "\x7f" for ch in text)


def parse_set_cookie(header: str, request_host: str, request_path: str) -> Cookie | None:
    """Turn one Set-Cookie value into a Cookie, or None if it is unusable."""
    if _has_control(header):
        # RFC 6265bis 5.6 step 1, as browsers do: the whole cookie is
        # dropped. A CR or LF kept here would end a line of the Cookie header
        # on whichever connection the cookie later rides, another site's too.
        return None
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
    domain_attribute = ""
    for attribute in parts[1:]:
        key, _, raw = attribute.partition("=")
        key = key.strip().lower()
        raw = raw.strip()
        if key in BOOLEAN_ATTRIBUTES:
            setattr(cookie, "secure" if key == "secure" else "http_only", True)
        elif key == "domain" and raw:
            # The last Domain attribute is the one that counts (5.3 step 4).
            domain_attribute = raw.lstrip(".").lower().rstrip(".")
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

    if domain_attribute and _public_suffixes().is_public(domain_attribute):
        # 5.3 step 5: a public suffix would reach every site under it. Only
        # the suffix itself may set one, and then it is host-only.
        if domain_attribute != cookie.domain.rstrip("."):
            return None
        domain_attribute = ""
    # A cookie may only widen to a domain the response host sits under.
    if domain_attribute and domain_matches(request_host, domain_attribute):
        cookie.domain = domain_attribute
        cookie.host_only = False

    now = time.time()
    if max_age is not None:
        # Max-Age wins over Expires, and a non-positive value deletes. Capped
        # before adding: hundreds of digits overflow a float.
        cookie.expires = now + min(max_age, MAX_COOKIE_AGE) if max_age > 0 else 0.0
    elif cookie.expires is not None:
        cookie.expires = min(cookie.expires, now + MAX_COOKIE_AGE)
    return cookie


class CookieJar:
    """Cookies for one session, keyed by name, domain and path."""

    def __init__(self) -> None:
        self._cookies: dict[tuple[str, str, str], Cookie] = {}
        # Shared between the workers of a Fetcher, so every path that
        # touches the mapping takes the lock.
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._cookies)

    def __iter__(self):
        with self._lock:
            return iter(list(self._cookies.values()))

    def clear(self) -> None:
        with self._lock:
            self._cookies.clear()

    def set(self, cookie: Cookie) -> None:
        with self._lock:
            if cookie.expired():
                self._cookies.pop(cookie.key, None)
                return
            existing = self._cookies.get(cookie.key)
            if existing is not None:
                # A replacement keeps the original creation time, which
                # decides ordering in the Cookie header.
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
        with self._lock:
            candidates = list(self._cookies.values())
            for cookie in candidates:
                if cookie.expired(now):
                    self._cookies.pop(cookie.key, None)
        for cookie in candidates:
            if cookie.expired(now):
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
