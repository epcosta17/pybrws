"""Tests for pybrws.http2 that need no network."""

import json
import unittest
import zlib

from pybrws.message import ContentEncodingError
from pybrws.http2 import (
    _Stream,
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


class TestHpackTableSizes(unittest.TestCase):
    """What the profile advertises, the codec has to be able to honour."""

    def test_decoder_accepts_the_size_the_profile_advertises(self):
        conn = Http2Connection(FakeTls(), profile=firefox157)
        advertised = dict(firefox157.H2_SETTINGS)[0x01]
        self.assertEqual(conn.decoder.max_allowed_table_size, advertised)
        self.assertGreater(advertised, 4096, "the default would make this vacuous")

    def test_peer_header_table_size_bounds_our_encoder(self):
        conn = Http2Connection(FakeTls(), profile=firefox157)
        payload = (0x01).to_bytes(2, "big") + (512).to_bytes(4, "big")
        conn._apply_settings(payload)
        self.assertEqual(conn.encoder.header_table_size, 512)

    def test_other_settings_are_ignored(self):
        conn = Http2Connection(FakeTls(), profile=firefox157)
        before = conn.encoder.header_table_size
        conn._apply_settings((0x04).to_bytes(2, "big") + (99).to_bytes(4, "big"))
        self.assertEqual(conn.encoder.header_table_size, before)


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


class ScriptedTls(FakeTls):
    """Replays canned frames so a response can be read without a server."""

    def __init__(self, frames):
        super().__init__()
        self._inbound = list(frames)

    def recv(self):
        if not self._inbound:
            raise AssertionError("client read past the scripted frames")
        return self._inbound.pop(0)


class TestFlowControl(unittest.TestCase):
    """A response larger than the advertised stream window must not stall."""

    def read_response(self, chunks):
        from hpack import Encoder

        stream = firefox157.H2_FIRST_STREAM_ID
        header_block = Encoder().encode([(":status", "200")])
        frames = [frame(HEADERS, FLAG_END_HEADERS, stream, header_block)]
        for index, chunk in enumerate(chunks):
            last = index == len(chunks) - 1
            frames.append(frame(0x00, FLAG_END_STREAM if last else 0, stream, chunk))

        tls = ScriptedTls(frames)
        conn = Http2Connection(tls, profile=firefox157)
        tls.sent.clear()
        # The reader expects the stream to have been opened by send_request.
        conn._open[stream] = _Stream()
        response = conn._read_response(stream)
        return response, frames_in(bytes(tls.sent))

    def test_both_windows_are_replenished(self):
        response, sent = self.read_response([b"a" * 1000, b"b" * 1000])
        self.assertEqual(response.body, b"a" * 1000 + b"b" * 1000)
        updates = [(f[2], int.from_bytes(f[3], "big")) for f in sent if f[0] == WINDOW_UPDATE]
        connection_level = [n for stream, n in updates if stream == 0]
        stream_level = [n for stream, n in updates if stream != 0]
        self.assertEqual(connection_level, [1000, 1000])
        self.assertEqual(stream_level, [1000], "only the non-final frame needs one")

    def test_increments_match_the_bytes_received(self):
        _, sent = self.read_response([b"x" * 4096, b"y" * 17, b"z" * 1])
        totals = sum(
            int.from_bytes(f[3], "big") for f in sent
            if f[0] == WINDOW_UPDATE and f[2] == 0
        )
        self.assertEqual(totals, 4096 + 17 + 1)

    def test_no_stream_update_after_end_stream(self):
        # The stream is closed; an update on it would be a protocol error.
        _, sent = self.read_response([b"only"])
        stream_updates = [f for f in sent if f[0] == WINDOW_UPDATE and f[2] != 0]
        self.assertEqual(stream_updates, [])


class TestSendFlowControl(unittest.TestCase):
    """A body larger than the peer's window must wait for credit, not stall."""

    def connection(self, credits):
        """A connection whose peer grants `credits` one WINDOW_UPDATE at a time."""
        conn = Http2Connection(FakeTls(), profile=firefox157)
        queued = list(credits)

        def grant():
            if not queued:
                raise AssertionError("asked for more credit than the test grants")
            amount = queued.pop(0)
            return (WINDOW_UPDATE, 0, 0, amount.to_bytes(4, "big"))

        conn._frame_from_wire = grant
        conn.tls.sent.clear()
        return conn

    def data_frames(self, conn):
        return [f for f in frames_in(bytes(conn.tls.sent)) if f[0] == 0x00]

    def test_small_body_goes_in_one_frame(self):
        conn = self.connection([])
        conn._stream_windows[3] = 65535
        conn._send_body(3, b"x" * 100)
        sent = self.data_frames(conn)
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0][1], FLAG_END_STREAM)

    def test_body_is_split_at_the_peer_max_frame_size(self):
        conn = self.connection([])
        conn._stream_windows[3] = 1 << 20
        conn.peer_window = 1 << 20
        conn.peer_max_frame_size = 1000
        conn._send_body(3, b"x" * 2500)
        sizes = [len(f[3]) for f in self.data_frames(conn)]
        self.assertEqual(sizes, [1000, 1000, 500])

    def test_only_the_last_frame_ends_the_stream(self):
        conn = self.connection([])
        conn._stream_windows[3] = 1 << 20
        conn.peer_window = 1 << 20
        conn.peer_max_frame_size = 1000
        conn._send_body(3, b"x" * 2500)
        flags = [f[1] for f in self.data_frames(conn)]
        self.assertEqual(flags, [0, 0, FLAG_END_STREAM])

    def test_waits_for_credit_when_the_window_runs_out(self):
        conn = self.connection([500])      # the peer grants 500 more, once
        conn.peer_window = 300
        conn._stream_windows[3] = 10_000
        conn._send_body(3, b"x" * 700)
        sizes = [len(f[3]) for f in self.data_frames(conn)]
        self.assertEqual(sizes, [300, 400], "sends what fits, then what is granted")

    def test_the_stream_window_binds_as_well_as_the_connection(self):
        conn = self.connection([])
        conn.peer_window = 10_000
        conn._stream_windows[3] = 250
        conn._send_body(3, b"x" * 250)
        self.assertEqual([len(f[3]) for f in self.data_frames(conn)], [250])

    def test_settings_resize_open_stream_windows_by_the_delta(self):
        conn = Http2Connection(FakeTls(), profile=firefox157)
        conn._stream_windows[3] = 65535
        payload = (0x04).to_bytes(2, "big") + (100_000).to_bytes(4, "big")
        conn._apply_settings(payload)
        self.assertEqual(conn._stream_windows[3], 65535 + (100_000 - 65535))

    def test_peer_max_frame_size_is_adopted(self):
        conn = Http2Connection(FakeTls(), profile=firefox157)
        conn._apply_settings((0x05).to_bytes(2, "big") + (32768).to_bytes(4, "big"))
        self.assertEqual(conn.peer_max_frame_size, 32768)

    def test_a_deferred_frame_is_not_handed_back_to_the_deferrer(self):
        # Reading its own deferral is what span forever before the split
        # between _next_frame and _frame_from_wire.
        conn = Http2Connection(FakeTls(), profile=firefox157)
        conn._stream_windows[3] = 1000
        conn.peer_window = 0
        script = [(0x06, 0, 0, b"ping1234"),            # deferred, not credit
                  (WINDOW_UPDATE, 0, 0, (50).to_bytes(4, "big"))]
        conn._frame_from_wire = lambda: script.pop(0)
        self.assertEqual(conn._await_window(3), 50)
        self.assertEqual(len(conn._pending), 1, "the ping waits for the reader")
        self.assertEqual(conn._pending[0][0], 0x06)


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


class TestMultiplexing(unittest.TestCase):
    """Several requests in flight on one connection."""

    def scripted(self, frames):
        tls = ScriptedTls(frames)
        conn = Http2Connection(tls, profile=firefox157)
        tls.sent.clear()
        return conn

    def blocks(self):
        """Two header blocks where the second leans on the first's table.

        Encoding the same fields twice makes the second block a set of
        indexed references into the dynamic table the first one filled, so
        decoding them out of order cannot silently appear to work.
        """
        from hpack import Encoder

        encoder = Encoder()
        fields = [(":status", "200"), ("x-custom", "a-fairly-long-value")]
        return encoder.encode(fields), encoder.encode(fields)

    def test_header_blocks_decode_in_arrival_order(self):
        first, second = self.blocks()
        self.assertLess(len(second), len(first), "the second must be indexed")
        # Wire order 3 then 5, completion order 5 then 3.
        conn = self.scripted([
            frame(HEADERS, FLAG_END_HEADERS, 3, first),
            frame(HEADERS, FLAG_END_HEADERS, 5, second),
            frame(0x00, FLAG_END_STREAM, 5, b"five"),
            frame(0x00, FLAG_END_STREAM, 3, b"three"),
        ])
        conn._open[3] = _Stream()
        conn._open[5] = _Stream()
        conn._stream_windows[3] = conn._stream_windows[5] = 1 << 20
        finished = []
        while len(finished) < 2:
            done = conn._pump()
            if done is not None:
                finished.append((done, conn._finish(done)))
        by_stream = dict(finished)
        self.assertEqual([stream for stream, _ in finished], [5, 3])
        for response in by_stream.values():
            self.assertEqual(response.status, 200)
            self.assertEqual(response.header("x-custom"), "a-fairly-long-value")

    def test_a_frame_for_an_unknown_stream_is_ignored(self):
        conn = self.scripted([
            frame(0x00, FLAG_END_STREAM, 99, b"stray"),
            frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3,
                  self.blocks()[0]),
        ])
        conn._open[3] = _Stream()
        self.assertIsNone(conn._pump())
        self.assertEqual(conn._pump(), 3)

    def test_send_request_returns_without_reading(self):
        conn = self.scripted([])
        first = conn.send_request("GET", "/a", "a.test")
        second = conn.send_request("GET", "/b", "a.test")
        self.assertEqual(second, first + 2)
        self.assertEqual(sorted(conn._open), [first, second])

    def test_max_concurrent_streams_is_adopted(self):
        conn = self.scripted([])
        conn._apply_settings((0x03).to_bytes(2, "big") + (7).to_bytes(4, "big"))
        self.assertEqual(conn.peer_max_streams, 7)

    def test_a_reset_stream_fails_only_itself(self):
        conn = self.scripted([
            frame(0x03, 0, 5, (8).to_bytes(4, "big")),
            frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3,
                  self.blocks()[0]),
        ])
        conn._open[3] = _Stream()
        conn._open[5] = _Stream()
        self.assertEqual(conn._pump(), 5)
        with self.assertRaises(Http2Error):
            conn._finish(5)
        self.assertEqual(conn._pump(), 3)
        self.assertEqual(conn._finish(3).status, 200)
