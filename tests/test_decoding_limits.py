"""Response decoding against hostile bodies.

D-1, D-2 and D3 of the 2026-11-11 review. A body is capped while it is
decoded, not after; streaming hands out bounded pieces; and a stream made of
several gzip members or zstd frames is decoded whole. No network: scripted
transports and loopback servers from `tests/hostile.py`.
"""

from __future__ import annotations

import tracemalloc
import unittest
import zlib
from unittest import mock

from hpack import Encoder

from pybrws.http1 import Http1Connection
from pybrws.http2 import (DATA, FLAG_END_HEADERS, FLAG_END_STREAM, HEADERS,
                          Http2Connection, frame)
from pybrws.message import (BodyTooLarge, ContentEncodingError, IncrementalDecoder,
                            decompress)
from pybrws.profiles import firefox157

from tests import hostile

MiB = 1 << 20
BOMB_SIZE = 64 * MiB
SID = firefox157.H2_FIRST_STREAM_ID


def gzip_compress(data: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=31)
    return compressor.compress(data) + compressor.flush()


BOMBS: dict[str, bytes] = {}


def setUpModule():
    import brotli

    zeros = bytes(BOMB_SIZE)
    BOMBS["br"] = brotli.compress(zeros, quality=5)   # the review's 102 bytes
    BOMBS["gzip"] = gzip_compress(zeros)
    deflate = zlib.compressobj(wbits=-15)
    BOMBS["deflate"] = deflate.compress(zeros) + deflate.flush()
    try:
        BOMBS["zstd"] = hostile.zstd_compress(zeros)
    except unittest.SkipTest:
        pass


def head_frame(fields) -> bytes:
    return frame(HEADERS, FLAG_END_HEADERS, SID, Encoder().encode(fields))


class TestCaps(unittest.TestCase):
    """D-1, D3: 102 bytes of brotli became 64 MiB from one call."""

    def test_brotli_bomb_raises_body_too_large(self):
        bomb = BOMBS["br"]
        self.assertLess(len(bomb), 128)
        tracemalloc.start()
        try:
            with self.assertRaises(BodyTooLarge):
                decompress(bomb, "br", max_size=MiB)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 16 * MiB)

    def test_every_encoding_is_capped_while_decoding(self):
        for encoding, bomb in BOMBS.items():
            with self.subTest(encoding=encoding):
                with self.assertRaises(BodyTooLarge):
                    decompress(bomb, encoding, max_size=MiB)
                with self.assertRaises(BodyTooLarge):
                    IncrementalDecoder(encoding, max_size=MiB).feed(bomb)

    def test_streaming_pieces_are_bounded(self):
        for encoding, bomb in BOMBS.items():
            with self.subTest(encoding=encoding):
                decoder = IncrementalDecoder(encoding)
                total = 0
                for piece in decoder.pieces(bomb):
                    self.assertLessEqual(len(piece), MiB)
                    total += len(piece)
                total += len(decoder.finish())
                self.assertEqual(total, BOMB_SIZE)

    def test_cap_none_disables(self):
        blob = gzip_compress(bytes(4 * MiB))
        with self.assertRaises(BodyTooLarge):
            decompress(blob, "gzip", max_size=MiB)
        self.assertEqual(len(decompress(blob, "gzip", max_size=None)), 4 * MiB)
        self.assertEqual(len(IncrementalDecoder("gzip", max_size=None).feed(blob)), 4 * MiB)

    def test_identity_body_is_capped_and_not_copied(self):
        body = bytes(2000)
        with self.assertRaises(BodyTooLarge):
            decompress(body, "identity", max_size=1000)
        self.assertIs(decompress(body, ""), body)

    def test_identity_body_over_cap_raises_http1(self):
        # Review Focus 1: refused before it is buffered whole. Each script
        # ends where reading on would cross the cap, so a client that read
        # on would run past it.
        head = b"HTTP/1.1 200 OK\r\n"
        framings = {
            "content-length": [head + b"Content-Length: 5000\r\n\r\n"],
            "chunked": [head + b"Transfer-Encoding: chunked\r\n\r\n"
                        + b"400\r\n" + b"a" * 0x400 + b"\r\n400\r\n"],
            "close-delimited": [head + b"Connection: close\r\n\r\n",
                                b"a" * 1000, b"a" * 1000],
        }
        for framing, script in framings.items():
            with self.subTest(framing=framing):
                tls = hostile.ScriptedTls(script, alpn="http/1.1")
                connection = Http1Connection(tls, max_body_size=1500)
                with self.assertRaises(BodyTooLarge):
                    connection.request("GET", "/", "example.com")
                self.assertTrue(connection.broken)

    def test_identity_body_over_cap_raises_http2(self):
        # Review Focus 1, over HTTP/2: the stream fails once its DATA passes
        # the cap; nothing can stop the peer sending (D10), so the
        # connection is dropped too.
        tls = hostile.ScriptedTls([
            head_frame([(b":status", b"200")]),
            frame(DATA, 0, SID, b"a" * 1000),
            frame(DATA, 0, SID, b"a" * 1000),
        ])
        connection = Http2Connection(tls, max_body_size=1500)
        with self.assertRaises(BodyTooLarge):
            connection.read_response(connection.send_request("GET", "/", "example.com"))
        self.assertTrue(connection.broken)
        self.assertEqual(connection._open, {})

    def test_stream_response_yields_bounded_pieces(self):
        # Streaming has no total cap -- the total is the caller's business --
        # but no single piece is unbounded.
        tls = hostile.ScriptedTls([
            head_frame([(b":status", b"200"), (b"content-encoding", b"br")]),
            frame(DATA, FLAG_END_STREAM, SID, BOMBS["br"]),
        ])
        connection = Http2Connection(tls)
        _response, chunks = connection.stream_response(
            connection.send_request("GET", "/", "example.com"))
        sizes = [len(chunk) for chunk in chunks]
        self.assertLessEqual(max(sizes), MiB)
        self.assertEqual(sum(sizes), BOMB_SIZE)


def drain(encoding: str, blob: bytes, size: int) -> bytes:
    """`blob` through a fresh decoder in `size`-byte chunks, then finish."""
    decoder = IncrementalDecoder(encoding)
    out = bytearray()
    for start in range(0, len(blob), size):
        out += decoder.feed(blob[start:start + size])
    return bytes(out + decoder.finish())


class TestMembersAndFrames(unittest.TestCase):
    """D-2: a gzip body is a series of members (RFC 1952 2.2) and zstd data
    one or more frames (RFC 8878 3.1). All of them are the body."""

    PARTS = (b"first part, ", b"second part, ", b"third.")
    WHOLE = b"".join(PARTS)
    SIZES = (1, 2, 3, 7, 64, 4096)

    def test_multi_member_gzip_buffered(self):
        blob = b"".join(gzip_compress(part) for part in self.PARTS)
        self.assertEqual(decompress(blob, "gzip"), self.WHOLE)

    def test_multi_member_gzip_streaming(self):
        blob = b"".join(gzip_compress(part) for part in self.PARTS)
        for size in self.SIZES:
            with self.subTest(chunk=size):
                self.assertEqual(drain("gzip", blob, size), self.WHOLE)

    def test_bytes_after_gzip_that_are_no_member_are_ignored(self):
        # As browsers do, and as this client did: a stray CRLF after the
        # last member is not part of the body, and not an error either.
        blob = gzip_compress(b"page") + b"\r\n"
        self.assertEqual(decompress(blob, "gzip"), b"page")
        for size in self.SIZES:
            with self.subTest(chunk=size):
                self.assertEqual(drain("gzip", blob, size), b"page")

    def test_multi_frame_zstd_streaming(self):
        blob = b"".join(hostile.zstd_compress(part) for part in self.PARTS)
        self.assertEqual(decompress(blob, "zstd"), self.WHOLE)
        for size in self.SIZES:
            with self.subTest(chunk=size):
                self.assertEqual(drain("zstd", blob, size), self.WHOLE)

    def test_multi_frame_zstd_split_at_boundary(self):
        decoder = IncrementalDecoder("zstd")
        out = decoder.feed(hostile.zstd_compress(b"one"))
        out += decoder.feed(hostile.zstd_compress(b"two"))
        self.assertEqual(out + decoder.finish(), b"onetwo")

    def test_a_truncated_later_member_or_frame_still_raises(self):
        for encoding, compress, cut in (("gzip", gzip_compress, 4),
                                        ("zstd", hostile.zstd_compress, 2)):
            with self.subTest(encoding=encoding):
                blob = compress(b"one") + compress(b"two")[:-cut]
                decoder = IncrementalDecoder(encoding)
                decoder.feed(blob)
                with self.assertRaises(ContentEncodingError):
                    decoder.finish()

    def test_members_count_against_one_cap(self):
        blob = gzip_compress(bytes(600)) + gzip_compress(bytes(600))
        with self.assertRaises(BodyTooLarge):
            decompress(blob, "gzip", max_size=1000)


class TestNoBodyAndDeflate(unittest.TestCase):
    """Two decoding faults found while rebuilding the decoder (not in the
    review): a response with no body could not carry a Content-Encoding,
    and "deflate" was read as raw deflate only."""

    def test_bodiless_responses_with_a_content_encoding(self):
        # HEAD, 204 and 304 carry the header and no body. Nothing arrived,
        # so nothing was truncated and there is nothing to decode.
        for method, status in (("HEAD", 200), ("GET", 304), ("GET", 204)):
            with self.subTest(method=method, status=status):
                tls = hostile.ScriptedTls(
                    [b"HTTP/1.1 %d X\r\nContent-Encoding: gzip\r\n"
                     b"Content-Length: 1234\r\n\r\n" % status], alpn="http/1.1")
                response = Http1Connection(tls).request(method, "/", "example.com")
                self.assertEqual((response.status, response.body), (status, b""))

    def test_http2_head_with_a_content_encoding(self):
        tls = hostile.ScriptedTls([frame(
            HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, SID,
            Encoder().encode([(b":status", b"200"), (b"content-encoding", b"br")]))])
        connection = Http2Connection(tls)
        response = connection.read_response(
            connection.send_request("HEAD", "/", "example.com"))
        self.assertEqual(response.body, b"")

    def test_an_empty_body_decodes_to_nothing_in_every_encoding(self):
        for encoding in ("gzip", "deflate", "br", "zstd"):
            with self.subTest(encoding=encoding):
                self.assertEqual(decompress(b"", encoding), b"")
                decoder = IncrementalDecoder(encoding)
                self.assertEqual(decoder.feed(b"") + decoder.finish(), b"")

    def test_deflate_takes_the_zlib_format_and_raw(self):
        # RFC 9110 8.4.1.2: "deflate" is the zlib format (RFC 1950). Some
        # servers send raw deflate instead; browsers take both.
        payload = b"payload " * 200
        raw = zlib.compressobj(wbits=-15)
        for framing, blob in (("zlib", zlib.compress(payload)),
                              ("raw", raw.compress(payload) + raw.flush())):
            with self.subTest(framing=framing):
                self.assertEqual(decompress(blob, "deflate"), payload)
                for size in (1, 2, 3, 64):
                    self.assertEqual(drain("deflate", blob, size), payload)

    def test_one_byte_of_deflate_is_truncated(self):
        decoder = IncrementalDecoder("deflate")
        decoder.feed(zlib.compress(b"payload")[:1])
        with self.assertRaises(ContentEncodingError):
            decoder.finish()


class TestCapPlumbing(unittest.TestCase):
    """max_body_size reaches the connections every entry point opens."""

    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_client_request_takes_max_body_size(self):
        from pybrws import client

        def big(tls):
            data = b""
            while b"\r\n\r\n" not in data:
                data += tls.recv(4096)
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n" + b"a" * 5000)

        port = hostile.openssl_server(big, ca=self.ca)
        with self.assertRaises(BodyTooLarge):
            client.get("https://localhost:%d/" % port, max_body_size=1000,
                       proxy=False, trust_store=self.store, timeout=5)

    def test_session_drops_the_connection_after_body_too_large(self):
        # The refused body is still on the wire: reusing the connection
        # would read it as the next response.
        from pybrws import session as session_module
        from pybrws.session import Session

        transports = [
            hostile.ScriptedTls([b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n"],
                                alpn="http/1.1"),
            hostile.ScriptedTls([b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"],
                                alpn="http/1.1"),
        ]
        with mock.patch.object(session_module, "connect", side_effect=transports):
            with Session(proxy=False, max_body_size=1000) as session:
                with self.assertRaises(BodyTooLarge):
                    session.get("https://example.com/big")
                self.assertEqual(session.get("https://example.com/small").body, b"ok")

    def test_fetcher_sessions_carry_max_body_size(self):
        from pybrws.pool import Fetcher

        fetcher = Fetcher(max_body_size=1000)
        try:
            self.assertEqual(fetcher._session().max_body_size, 1000)
        finally:
            fetcher.close()


if __name__ == "__main__":
    unittest.main()
