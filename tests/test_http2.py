"""Tests for pybrws.http2 that need no network."""

import json
import unittest
import zlib

from pybrws.message import ContentEncodingError
from pybrws.http2 import (
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    FLAG_PRIORITY,
    HEADERS,
    PREFACE,
    SETTINGS,
    WINDOW_UPDATE,
    Http2Connection,
    Http2Error,
    Response,
    decompress,
    frame,
)
from pybrws.profiles import firefox157


class FakeTls:
    """Stands in for an established TLS connection."""

    def __init__(self, alpn="h2"):
        self.alpn = alpn
        self.sent = bytearray()

    def send(self, data):
        self.sent += data

    def recv(self):
        raise AssertionError("the test should not read from the connection")


def frames_in(data: bytes):
    out = []
    i = 0
    while i + 9 <= len(data):
        length = int.from_bytes(data[i : i + 3], "big")
        out.append((data[i + 3], data[i + 4],
                    int.from_bytes(data[i + 5 : i + 9], "big"),
                    data[i + 9 : i + 9 + length]))
        i += 9 + length
    return out


class TestFraming(unittest.TestCase):
    def test_header_layout(self):
        raw = frame(HEADERS, 0x05, 3, b"abc")
        self.assertEqual(int.from_bytes(raw[:3], "big"), 3)
        self.assertEqual(raw[3], HEADERS)
        self.assertEqual(raw[4], 0x05)
        self.assertEqual(int.from_bytes(raw[5:9], "big"), 3)
        self.assertEqual(raw[9:], b"abc")

    def test_empty_payload(self):
        self.assertEqual(len(frame(SETTINGS, 0x01, 0)), 9)


class TestPreamble(unittest.TestCase):
    def setUp(self):
        self.tls = FakeTls()
        self.conn = Http2Connection(self.tls, profile=firefox157)

    def test_starts_with_the_connection_preface(self):
        self.assertTrue(bytes(self.tls.sent).startswith(PREFACE))

    def test_settings_then_window_update(self):
        sent = frames_in(bytes(self.tls.sent)[len(PREFACE):])
        self.assertEqual([f[0] for f in sent], [SETTINGS, WINDOW_UPDATE])

    def test_settings_carry_the_profile_values_in_order(self):
        payload = frames_in(bytes(self.tls.sent)[len(PREFACE):])[0][3]
        decoded = [
            (
                int.from_bytes(payload[i : i + 2], "big"),
                int.from_bytes(payload[i + 2 : i + 6], "big"),
            )
            for i in range(0, len(payload), 6)
        ]
        self.assertEqual(decoded, firefox157.H2_SETTINGS)

    def test_window_update_increment(self):
        payload = frames_in(bytes(self.tls.sent)[len(PREFACE):])[1][3]
        self.assertEqual(
            int.from_bytes(payload, "big"), firefox157.H2_CONNECTION_WINDOW_UPDATE
        )

    def test_rejects_a_connection_that_did_not_negotiate_h2(self):
        with self.assertRaises(Http2Error):
            Http2Connection(FakeTls(alpn="http/1.1"))


class TestRequestFraming(unittest.TestCase):
    def setUp(self):
        self.tls = FakeTls()
        self.conn = Http2Connection(self.tls, profile=firefox157)
        self.tls.sent.clear()
        try:
            self.conn.get("/api/all", "tls.peet.ws")
        except AssertionError:
            pass  # FakeTls refuses to read; the request frame is already sent
        self.headers_frame = frames_in(bytes(self.tls.sent))[0]

    def test_first_stream_id_comes_from_the_profile(self):
        self.assertEqual(self.headers_frame[2], firefox157.H2_FIRST_STREAM_ID)

    def test_stream_ids_advance_by_two(self):
        self.assertEqual(
            self.conn.next_stream_id, firefox157.H2_FIRST_STREAM_ID + 2
        )

    def test_flags(self):
        self.assertEqual(
            self.headers_frame[1],
            FLAG_END_STREAM | FLAG_END_HEADERS | FLAG_PRIORITY,
        )

    def test_priority_field_carries_weight_minus_one(self):
        payload = self.headers_frame[3]
        self.assertEqual(int.from_bytes(payload[:4], "big"), 0)
        self.assertEqual(payload[4], firefox157.H2_HEADERS_PRIORITY["weight"] - 1)

    def test_pseudo_headers_precede_the_rest_in_profile_order(self):
        from hpack import Decoder

        payload = self.headers_frame[3][5:]
        decoded = [(n, v) for n, v in Decoder().decode(payload)]
        names = [n for n, _ in decoded]
        self.assertEqual(tuple(names[:4]), firefox157.H2_PSEUDO_ORDER)
        self.assertEqual(
            names[4:], [name for name, _ in firefox157.H2_NAVIGATION_HEADERS]
        )

    def test_header_values(self):
        from hpack import Decoder

        decoded = dict(Decoder().decode(self.headers_frame[3][5:]))
        self.assertEqual(decoded[":method"], "GET")
        self.assertEqual(decoded[":path"], "/api/all")
        self.assertEqual(decoded[":authority"], "tls.peet.ws")
        self.assertEqual(decoded[":scheme"], "https")
        self.assertEqual(decoded["user-agent"], firefox157.USER_AGENT)


class TestDecompress(unittest.TestCase):
    def test_identity(self):
        self.assertEqual(decompress(b"plain", ""), b"plain")
        self.assertEqual(decompress(b"plain", "identity"), b"plain")

    def test_gzip(self):
        compressor = zlib.compressobj(wbits=31)
        blob = compressor.compress(b"payload") + compressor.flush()
        self.assertEqual(decompress(blob, "gzip"), b"payload")

    def test_deflate(self):
        compressor = zlib.compressobj(wbits=-15)
        blob = compressor.compress(b"payload") + compressor.flush()
        self.assertEqual(decompress(blob, "deflate"), b"payload")

    def test_brotli(self):
        import brotli

        self.assertEqual(decompress(brotli.compress(b"payload"), "br"), b"payload")

    def test_zstd(self):
        from compression import zstd

        self.assertEqual(decompress(zstd.compress(b"payload"), "zstd"), b"payload")

    def test_unknown_encoding(self):
        with self.assertRaises(ContentEncodingError):
            decompress(b"x", "exotic")


class TestResponse(unittest.TestCase):
    def test_header_lookup_is_case_insensitive(self):
        response = Response(200, [("Content-Type", "application/json")])
        self.assertEqual(response.header("content-type"), "application/json")
        self.assertIsNone(response.header("missing"))

    def test_text_decodes_the_body(self):
        response = Response(200, [], json.dumps({"a": 1}).encode())
        self.assertEqual(json.loads(response.text()), {"a": 1})


if __name__ == "__main__":
    unittest.main()
