"""The `{cookie}` slot in a header set: the cookie goes where the capture
put it, or the header is left out. Never sent as written."""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from unittest import mock

from hpack import Decoder, Encoder

from pybrws import client
from pybrws.cookies import Cookie
from pybrws.http1 import Http1Connection
from pybrws.http2 import (FLAG_END_HEADERS, FLAG_END_STREAM, FLAG_PRIORITY,
                          HEADERS, PREFACE, Http2Connection, frame)
from pybrws.profiles import chrome155, firefox157
from pybrws.session import Session
from tests import hostile
from tests.test_session_proxy_hostile import OK_H1, Transports, h2_ok

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
HOST = "pybrws.127.0.0.1.nip.io"
ORIGIN = "https://" + HOST + ":4443"
SETS = ("H1_HEADERS", "H2_NAVIGATION_HEADERS",
        "H1_POST_XHR_HEADERS", "H2_POST_XHR_HEADERS",
        "H1_POST_FORM_HEADERS", "H2_POST_FORM_HEADERS",
        "H1_POST_FORM_SCRIPT_HEADERS", "H2_POST_FORM_SCRIPT_HEADERS",
        "H1_IMAGE_HEADERS", "H2_IMAGE_HEADERS")
# What client.request fills a set with, here with no referer; nothing
# passes a cookie.
CONTEXT = {"origin": "https://example.com", "referer": "",
           "content_type": "application/x-www-form-urlencoded"}
PLACEHOLDER = re.compile(r"\{\w+\}")


def h2_fields(tls) -> list[tuple[str, str]]:
    """The fields of the first HEADERS frame the client sent."""
    for kind, flags, _stream, payload in hostile.frames_in(
            bytes(tls.sent)[len(PREFACE):]):
        if kind == HEADERS:
            return Decoder().decode(payload[5:] if flags & FLAG_PRIORITY else payload)
    raise AssertionError("no HEADERS frame was sent")


def sent_headers(profile, name: str) -> list[tuple[str, str]]:
    """A set as the connection writes it, filled with CONTEXT."""
    headers = getattr(profile, name)
    if name.startswith("H1_"):
        raw = Http1Connection(hostile.ScriptedTls([], alpn="http/1.1")).build_request(
            "POST", "/", "example.com", headers, b"a=1", CONTEXT)
        lines = raw.decode("latin-1").split("\r\n\r\n")[0].split("\r\n")[1:]
        return [tuple(line.split(": ", 1)) for line in lines]
    tls = hostile.ScriptedTls([])
    Http2Connection(tls, profile=profile).send_request(
        "POST", "/", "example.com", headers=headers, body=b"a=1", context=CONTEXT)
    return h2_fields(tls)


class TestNoPlaceholderIsSent(unittest.TestCase):
    def test_every_set_of_every_profile(self):
        for profile in (firefox157, chrome155):
            for name in SETS:
                if getattr(profile, name, None) is None:
                    continue   # unmeasured: refused before anything is sent
                with self.subTest(profile=profile.NAME, set=name):
                    for header, value in sent_headers(profile, name):
                        self.assertIsNone(PLACEHOLDER.search(value),
                                          "%s: %s" % (header, value))

    def test_a_client_image_request_without_cookies_sends_none(self):
        tls = hostile.ScriptedTls([OK_H1], alpn="http/1.1")
        with mock.patch.object(client, "connect", return_value=tls):
            client.get("https://example.com/favicon.ico", kind="image", proxy=False)
        self.assertNotIn(b"\r\nCookie:", bytes(tls.sent))
        tls = hostile.ScriptedTls([h2_ok()])
        with mock.patch.object(client, "connect", return_value=tls):
            client.get("https://example.com/favicon.ico", kind="image", proxy=False)
        self.assertNotIn("cookie", [name for name, _ in h2_fields(tls)])


class TestTheSlotTakesTheCookie(unittest.TestCase):
    def jar(self, session):
        session.cookies.set(Cookie("pybrws_probe", "1", HOST, "/"))
        session.cookies.set(Cookie("pybrws_second", "2", HOST, "/"))

    def test_http1_image_request_equals_the_capture(self):
        # The capture carries Cookie right after Referer.
        with Transports([OK_H1]) as transports:
            with Session(proxy=False) as session:
                self.jar(session)
                session.get(ORIGIN + "/favicon.ico", kind="image")
        self.assertEqual(transports.sent(),
                         (FIXTURES / "reference-firefox-157-image.txt").read_bytes())

    def test_http2_image_request_puts_one_field_per_cookie_there(self):
        with Transports([h2_ok()], alpn="h2") as transports:
            with Session(proxy=False) as session:
                self.jar(session)
                session.get(ORIGIN + "/favicon.ico", kind="image")
        fields = h2_fields(transports.made[0])
        names = [name for name, _ in fields]
        at = names.index("referer")
        self.assertEqual(fields[at + 1:at + 3], [("cookie", "pybrws_probe=1"),
                                                 ("cookie", "pybrws_second=2")])
        self.assertEqual(names[at + 3], "sec-fetch-dest")

    def test_a_set_without_a_slot_keeps_its_anchor(self):
        # chrome155's image set has no slot; its cookies go before priority,
        # as its capture shows.
        ok = frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM,
                   chrome155.H2_FIRST_STREAM_ID, Encoder().encode([(b":status", b"200")]))
        with Transports([ok], alpn="h2") as transports:
            with Session(profile=chrome155, proxy=False) as session:
                self.jar(session)
                session.get(ORIGIN + "/favicon.png", kind="image")
        names = [name for name, _ in h2_fields(transports.made[0])]
        self.assertEqual(names[-3:], ["cookie", "cookie", "priority"])


if __name__ == "__main__":
    unittest.main()
