"""Where a Session puts its cookies, against every capture that carries some.

Each case sends the request its capture shows, through a Session holding
the capture's two cookies, offline. The cookies must carry the capture's
values and sit right before the header they precede in the capture.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from hpack import Encoder

from pybrws.cookies import Cookie
from pybrws.http2 import FLAG_END_HEADERS, FLAG_END_STREAM, HEADERS, frame
from pybrws.profiles import chrome155, firefox157
from pybrws.session import Session
from tests.test_cookie_slot import h2_fields
from tests.test_session_proxy_hostile import OK_H1, Transports

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
HOST = "pybrws.127.0.0.1.nip.io"
ORIGIN = "https://" + HOST + ":4443"

# capture, profile, over HTTP/2, method, path, kind, JSON body
CASES = (
    ("reference-firefox-157-cookie.txt", firefox157, False, "GET", "/", "xhr", None),
    ("reference-firefox-157-h2-cookie.txt", firefox157, True, "GET", "/", "xhr", None),
    ("reference-firefox-157-image.txt", firefox157, False, "GET", "/favicon.ico",
     "image", None),
    ("reference-firefox-157-h2-post.txt", firefox157, True, "POST", "/submit", "xhr",
     {"field": "value"}),
    ("reference-chrome-155-cookie.txt", chrome155, False, "GET", "/", "xhr", None),
    ("reference-chrome-155-h2-cookie.txt", chrome155, True, "GET", "/", "xhr", None),
    ("reference-chrome-155-h2-image.txt", chrome155, True, "GET", "/favicon.png",
     "image", None),
    ("reference-chrome-155-h2-post.txt", chrome155, True, "POST", "/submit", "xhr",
     {"field": "value"}),
)


def captured(name: str) -> list[tuple[str, str]]:
    """The capture's fields in wire order, without the request line or the
    pseudo-headers."""
    text = (FIXTURES / name).read_text(encoding="utf-8").replace("\r\n", "\n")
    lines = text.split("\n\n", 1)[0].splitlines()
    if not lines[0].startswith(":"):
        lines = lines[1:]   # the HTTP/1.1 request line
    return [tuple(line.split(": ", 1)) for line in lines if not line.startswith(":")]


def sent(profile, http2: bool, method: str, path: str, kind: str, body):
    """The fields a Session holding the capture's two cookies sends."""
    if http2:
        ok = frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM,
                   profile.H2_FIRST_STREAM_ID, Encoder().encode([(b":status", b"200")]))
        transports = Transports([ok], alpn="h2")
    else:
        transports = Transports([OK_H1])
    with transports, Session(profile=profile, proxy=False) as session:
        session.cookies.set(Cookie("pybrws_probe", "1", HOST, "/"))
        session.cookies.set(Cookie("pybrws_second", "2", HOST, "/"))
        session.request(ORIGIN + path, method=method, kind=kind, json=body)
    if http2:
        return [(name, value) for name, value in h2_fields(transports.made[0])
                if not name.startswith(":")]
    head = transports.sent().decode("latin-1").split("\r\n\r\n", 1)[0]
    return [tuple(line.split(": ", 1)) for line in head.split("\r\n")[1:]]


def placement(fields):
    """The cookie values, and the header right after them (None if last)."""
    names = [name.lower() for name, _ in fields]
    first, count = names.index("cookie"), names.count("cookie")
    if names[first:first + count] != ["cookie"] * count:
        return "not adjacent"
    after = names[first + count] if first + count < len(names) else None
    return [value for name, value in fields if name.lower() == "cookie"], after


class TestEveryCookieCapture(unittest.TestCase):
    def test_cookies_sit_where_each_capture_has_them(self):
        for name, profile, http2, method, path, kind, body in CASES:
            with self.subTest(capture=name):
                self.assertEqual(placement(sent(profile, http2, method, path, kind, body)),
                                 placement(captured(name)))

    def test_firefox_http2_fetch_post_equals_its_capture(self):
        # Field for field, values included: the capture's own fetch POST.
        self.assertEqual(sent(firefox157, True, "POST", "/submit", "xhr",
                              {"field": "value"}),
                         captured("reference-firefox-157-h2-post.txt"))


if __name__ == "__main__":
    unittest.main()
