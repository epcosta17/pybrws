"""Tests for streaming responses: pybrws.message.IncrementalDecoder and
pybrws.http2.Http2Connection.stream_response.

The property under test is that chunk boundaries are invisible. gzip,
brotli and zstd all carry state across a boundary, so a decoder fed in
pieces must produce exactly what the whole-body decoder produces -- and
must refuse a stream that stops early rather than return a short body.
"""

import unittest
import zlib

from hpack import Encoder

from pybrws.http2 import (
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    HEADERS,
    Http2Connection,
    Http2Error,
    _Stream,
    frame,
)
from pybrws.message import ContentEncodingError, IncrementalDecoder, decompress
from pybrws.profiles import firefox157

DATA = 0x00

# Compressible but not trivially so, and long enough to span many chunks.
PAYLOAD = b"".join(
    b'{"id": %d, "name": "item-%d", "tags": ["a", "b", "c"]}\n' % (n, n)
    for n in range(4000)
)


def gzipped(body: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=31)
    return compressor.compress(body) + compressor.flush()


def deflated(body: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(body) + compressor.flush()


def brotlied(body: bytes) -> bytes:
    import brotli

    return brotli.compress(body)


def zstded(body: bytes) -> bytes:
    from compression import zstd

    return zstd.compress(body)


ENCODINGS = [
    ("identity", lambda body: body),
    ("gzip", gzipped),
    ("deflate", deflated),
    ("br", brotlied),
    ("zstd", zstded),
]


def drain(encoding: str, blob: bytes, size: int) -> bytes:
    """Feed `blob` through a fresh decoder in `size`-byte pieces."""
    decoder = IncrementalDecoder(encoding)
    out = bytearray()
    for start in range(0, len(blob), size):
        out += decoder.feed(blob[start : start + size])
    out += decoder.finish()
    return bytes(out)


class TestIncrementalDecoder(unittest.TestCase):
    def test_matches_the_whole_body_decoder_at_every_chunk_size(self):
        # 1 byte is the pathological case: no chunk is a valid stream, and
        # for gzip the 10-byte header alone spans ten calls.
        for encoding, compress in ENCODINGS:
            blob = compress(PAYLOAD)
            self.assertEqual(decompress(blob, encoding), PAYLOAD,
                             encoding + ": the fixture itself is wrong")
            for size in (1, 2, 7, 64, 1024, len(blob), len(blob) * 2):
                with self.subTest(encoding=encoding, chunk=size):
                    self.assertEqual(drain(encoding, blob, size), PAYLOAD)

    def test_empty_encoding_is_identity(self):
        self.assertEqual(drain("", PAYLOAD, 128), PAYLOAD)

    def test_casing_and_spacing_are_ignored(self):
        self.assertEqual(drain("  GZip ", gzipped(PAYLOAD), 128), PAYLOAD)

    def test_an_empty_body_decodes_to_nothing(self):
        for encoding, compress in ENCODINGS:
            with self.subTest(encoding=encoding):
                self.assertEqual(drain(encoding, compress(b""), 64), b"")

    def test_feeding_nothing_at_all_is_not_an_error(self):
        # A 204 or a HEAD carries the header but no body.
        decoder = IncrementalDecoder("identity")
        self.assertEqual(decoder.feed(b"") + decoder.finish(), b"")

    def test_unsupported_encoding_is_refused_up_front(self):
        with self.assertRaises(ContentEncodingError):
            IncrementalDecoder("exotic")

    def test_a_truncated_stream_raises_rather_than_returning_a_short_body(self):
        # The whole-body decoder gets this for free: zlib will not hand back
        # a partial result. Chunk by chunk there is nothing stopping us from
        # yielding what arrived and calling it a response, so finish() has
        # to check. A silently short document is the worst outcome here --
        # it looks like a page that changed, not like a failed download.
        for encoding, compress in ENCODINGS:
            if encoding == "identity":
                continue
            blob = compress(PAYLOAD)
            with self.subTest(encoding=encoding):
                decoder = IncrementalDecoder(encoding)
                partial = decoder.feed(blob[: len(blob) // 2])
                self.assertLess(len(partial), len(PAYLOAD))
                with self.assertRaises(ContentEncodingError):
                    decoder.finish()

    def test_a_complete_stream_needs_no_flush_to_be_accepted(self):
        decoder = IncrementalDecoder("gzip")
        self.assertEqual(decoder.feed(gzipped(PAYLOAD)), PAYLOAD)
        self.assertEqual(decoder.finish(), b"")


class ScriptedTls:
    """Replays canned frames so a response can be read without a server."""

    def __init__(self, frames):
        self.alpn = "h2"
        self.sent = bytearray()
        self._inbound = list(frames)

    def send(self, data):
        self.sent += data

    def recv(self):
        if not self._inbound:
            raise AssertionError("client read past the scripted frames")
        return self._inbound.pop(0)


def scripted(body_frames, *, headers=((":status", "200"),), stream=None):
    """A connection with one open stream and a scripted response on it."""
    stream = firefox157.H2_FIRST_STREAM_ID if stream is None else stream
    frames = [frame(HEADERS, FLAG_END_HEADERS, stream,
                    Encoder().encode(list(headers)))]
    frames.extend(body_frames(stream))
    conn = Http2Connection(ScriptedTls(frames), profile=firefox157)
    conn._open[stream] = _Stream()
    conn._stream_windows[stream] = 1 << 20
    return conn, stream


def data_frames(chunks):
    def build(stream):
        out = []
        for index, chunk in enumerate(chunks):
            last = index == len(chunks) - 1
            out.append(frame(DATA, FLAG_END_STREAM if last else 0, stream, chunk))
        return out

    return build


def pieces(blob: bytes, size: int) -> list[bytes]:
    return [blob[start : start + size] for start in range(0, len(blob), size)] or [b""]


class TestStreamResponse(unittest.TestCase):
    def test_headers_arrive_before_the_body_is_read(self):
        conn, stream = scripted(
            data_frames(pieces(gzipped(PAYLOAD), 4096)),
            headers=((":status", "200"), ("content-encoding", "gzip")),
        )
        response, chunks = conn.stream_response(stream)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.header("content-encoding"), "gzip")
        self.assertEqual(response.body, b"", "the body must not be buffered")
        self.assertEqual(b"".join(chunks), PAYLOAD)

    def test_frame_boundaries_do_not_corrupt_a_compressed_body(self):
        # Awkward sizes on purpose: 1 puts every gzip header byte in its own
        # DATA frame, and the primes land boundaries inside deflate blocks.
        for encoding, compress in ENCODINGS:
            blob = compress(PAYLOAD)
            for size in (1, 3, 17, 997, 16384):
                with self.subTest(encoding=encoding, frame=size):
                    conn, stream = scripted(
                        data_frames(pieces(blob, size)),
                        headers=((":status", "200"),
                                 ("content-encoding", encoding)),
                    )
                    _, chunks = conn.stream_response(stream)
                    self.assertEqual(b"".join(chunks), PAYLOAD)

    def test_a_body_split_across_frames_yields_more_than_one_chunk(self):
        # Otherwise the test above would pass just as well on a decoder
        # that buffered everything and handed it over at the end.
        conn, stream = scripted(data_frames([b"a" * 1000] * 5))
        _, chunks = conn.stream_response(stream)
        self.assertGreater(len(list(chunks)), 1)

    def test_an_empty_body_yields_nothing(self):
        conn, stream = scripted(data_frames([b""]))
        response, chunks = conn.stream_response(stream)
        self.assertEqual(response.status, 200)
        self.assertEqual(list(chunks), [])

    def test_a_truncated_compressed_body_raises_while_draining(self):
        # END_STREAM arrives but the gzip member never ended: the server was
        # cut off. Returning the prefix would be a silent short read.
        blob = gzipped(PAYLOAD)
        conn, stream = scripted(
            data_frames(pieces(blob[: len(blob) // 2], 4096)),
            headers=((":status", "200"), ("content-encoding", "gzip")),
        )
        _, chunks = conn.stream_response(stream)
        with self.assertRaises(ContentEncodingError):
            b"".join(chunks)

    def test_draining_releases_the_stream(self):
        conn, stream = scripted(data_frames(pieces(PAYLOAD, 8192)))
        _, chunks = conn.stream_response(stream)
        self.assertIn(stream, conn._open)
        b"".join(chunks)
        self.assertNotIn(stream, conn._open,
                         "a drained stream must be forgotten")
        self.assertNotIn(stream, conn._stream_windows)

    def test_abandoning_the_iterator_still_releases_the_stream(self):
        # The caller breaks out of the loop early; closing the generator has
        # to run the cleanup, or the connection leaks a stream per request.
        conn, stream = scripted(data_frames(pieces(PAYLOAD, 8192)))
        _, chunks = conn.stream_response(stream)
        next(chunks)
        chunks.close()
        self.assertNotIn(stream, conn._open)
        self.assertNotIn(stream, conn._stream_windows)

    def test_a_reset_stream_raises(self):
        from pybrws.http2 import RST_STREAM

        def build(stream):
            return [
                frame(DATA, 0, stream, b"partial"),
                frame(RST_STREAM, 0, stream, (0x02).to_bytes(4, "big")),
            ]

        conn, stream = scripted(build)
        _, chunks = conn.stream_response(stream)
        with self.assertRaises(Http2Error):
            b"".join(chunks)


if __name__ == "__main__":
    unittest.main()
