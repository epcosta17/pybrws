"""Tests for pybrws.http1 and pybrws.client that need no network."""

import unittest
import zlib
from pathlib import Path

from pybrws.client import UnsupportedUrl, get
from pybrws.http1 import Http1Connection, Http1Error
from pybrws.profiles import firefox157


class FakeTls:
    """Stands in for an established TLS connection, replaying canned bytes."""

    def __init__(self, inbound=b"", alpn="http/1.1"):
        self.alpn = alpn
        self.sent = bytearray()
        self._inbound = [inbound] if inbound else []

    def send(self, data):
        self.sent += data

    def recv(self):
        if not self._inbound:
            raise EOFError("no more data")
        return self._inbound.pop(0)


def response_bytes(status_line, headers, body=b""):
    head = status_line + "\r\n" + "".join(n + ": " + v + "\r\n" for n, v in headers)
    return head.encode() + b"\r\n" + body


class TestRequestFormat(unittest.TestCase):
    def setUp(self):
        self.tls = FakeTls()
        self.conn = Http1Connection(self.tls, profile=firefox157)
        self.raw = self.conn.build_request("GET", "/path", "example.com")
        self.lines = self.raw.decode().split("\r\n")

    def test_request_line(self):
        self.assertEqual(self.lines[0], "GET /path HTTP/1.1")

    def test_terminated_by_a_blank_line(self):
        self.assertTrue(self.raw.endswith(b"\r\n\r\n"))
        self.assertEqual(self.lines[-2:], ["", ""])

    def test_header_order_and_capitalisation_come_from_the_profile(self):
        sent = [line.split(":", 1)[0] for line in self.lines[1:] if line]
        self.assertEqual(sent, [name for name, _ in firefox157.H1_HEADERS])

    def test_host_is_first_and_filled_from_the_authority(self):
        self.assertEqual(self.lines[1], "Host: example.com")

    def test_authority_placeholder_handles_a_port(self):
        raw = self.conn.build_request("GET", "/", "example.com:8443")
        self.assertIn("Host: example.com:8443", raw.decode())

    def test_rejects_a_connection_that_negotiated_h2(self):
        with self.assertRaises(Http1Error):
            Http1Connection(FakeTls(alpn="h2"))


class TestResponseParsing(unittest.TestCase):
    def fetch(self, inbound):
        tls = FakeTls(inbound)
        return Http1Connection(tls).get("/", "example.com")

    def test_content_length_body(self):
        raw = response_bytes("HTTP/1.1 200 OK", [("Content-Length", "5")], b"hello")
        response = self.fetch(raw)
        self.assertEqual((response.status, response.body), (200, b"hello"))
        self.assertEqual(response.http_version, "HTTP/1.1")

    def test_header_lookup(self):
        raw = response_bytes(
            "HTTP/1.1 200 OK",
            [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", "0")],
        )
        self.assertEqual(
            self.fetch(raw).header("content-type"), "text/html; charset=utf-8"
        )

    def test_chunked_body(self):
        body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        raw = response_bytes(
            "HTTP/1.1 200 OK", [("Transfer-Encoding", "chunked")], body
        )
        self.assertEqual(self.fetch(raw).body, b"hello world")

    def test_chunked_body_with_trailers(self):
        body = b"4\r\ndata\r\n0\r\nX-Checksum: abc\r\n\r\n"
        raw = response_bytes(
            "HTTP/1.1 200 OK", [("Transfer-Encoding", "chunked")], body
        )
        self.assertEqual(self.fetch(raw).body, b"data")

    def test_chunk_extensions_are_ignored(self):
        body = b"4;ext=1\r\ndata\r\n0\r\n\r\n"
        raw = response_bytes(
            "HTTP/1.1 200 OK", [("Transfer-Encoding", "chunked")], body
        )
        self.assertEqual(self.fetch(raw).body, b"data")

    def test_gzip_body_is_decompressed(self):
        compressor = zlib.compressobj(wbits=31)
        blob = compressor.compress(b"payload") + compressor.flush()
        raw = response_bytes(
            "HTTP/1.1 200 OK",
            [("Content-Encoding", "gzip"), ("Content-Length", str(len(blob)))],
            blob,
        )
        self.assertEqual(self.fetch(raw).body, b"payload")

    def test_204_has_no_body(self):
        raw = response_bytes("HTTP/1.1 204 No Content", [])
        self.assertEqual(self.fetch(raw).body, b"")

    def test_continue_is_skipped(self):
        raw = (
            b"HTTP/1.1 100 Continue\r\n\r\n"
            + response_bytes("HTTP/1.1 200 OK", [("Content-Length", "2")], b"ok")
        )
        response = self.fetch(raw)
        self.assertEqual((response.status, response.body), (200, b"ok"))

    def test_malformed_status_line(self):
        with self.assertRaises(Http1Error):
            self.fetch(b"NOT-HTTP\r\n\r\n")

    def test_truncated_body(self):
        raw = response_bytes("HTTP/1.1 200 OK", [("Content-Length", "99")], b"short")
        with self.assertRaises(Http1Error):
            self.fetch(raw)


class TestMatchesTheReferenceCapture(unittest.TestCase):
    """The built request must equal a real Firefox navigation, byte for byte."""

    REFERENCE = (
        Path(__file__).resolve().parent.parent
        / "fixtures"
        / "reference-firefox-157-h1.txt"
    )
    AUTHORITY = "pybrws.127.0.0.1.nip.io:4443"

    def test_byte_identical(self):
        expected = self.REFERENCE.read_bytes()
        built = Http1Connection(FakeTls()).build_request("GET", "/", self.AUTHORITY)
        self.assertEqual(built, expected)

    def test_reference_is_a_tls_capture(self):
        # br and zstd only appear when the origin is trustworthy, so their
        # presence proves the reference was not captured over cleartext.
        text = self.REFERENCE.read_text()
        self.assertIn("br, zstd", text)
        self.assertIn("Sec-Fetch-Dest", text)


class TestClientUrlHandling(unittest.TestCase):
    def test_rejects_plain_http(self):
        with self.assertRaises(UnsupportedUrl):
            get("http://example.com/")

    def test_rejects_a_url_without_a_host(self):
        with self.assertRaises(UnsupportedUrl):
            get("https:///path")


if __name__ == "__main__":
    unittest.main()
