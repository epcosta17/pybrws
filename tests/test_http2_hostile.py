"""HTTP/2 against peers that misbehave on purpose.

H1-H8 of the 2026-11-11 review, plus D6 and X2 (header bytes). The peer is
a scripted transport (`tests/hostile.ScriptedTls`) fed hand-built frames, so
a test controls every byte the client reads. No network.
"""

from __future__ import annotations

import unittest

from hpack import Encoder

from pybrws import headers as header_tools
from pybrws.http2 import (CONTINUATION, DATA, FLAG_END_HEADERS, FLAG_END_STREAM, PREFACE,
                          HEADERS, Http2Connection, frame)
from pybrws.profiles import chrome155, firefox157

from tests import hostile

SID = firefox157.H2_FIRST_STREAM_ID

# Recorded from the code before the D6 change: what a navigation puts on the
# wire, preface to HEADERS. Must not move for ASCII headers.
NAVIGATION_BYTES = {
    "firefox157": bytes.fromhex(
        "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a00001804000000000000"
        "010001000000020000000000040002000000050000400000000408000000000000bf"
        "00010001170125000000030000000029828441882f91d35d055c87a7877abcd07f66"
        "a281b0dae053fae46aa43f8429a77a8102e0fb5391aa71afb53cb8d7da9677b816dd"
        "5c1fda988a4ea76040080010054c26b0b29fcb016dd5c153b0497ca589d34d1f43ae"
        "ba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177febe58f9"
        "fbed00177b518b2d4b70ddf45abefb4005df50929bd9abfa5242cb40d25fa523b3e9"
        "4f684c9f4092b6b9ac1c8558d520a4b6c2ad617b5a54251f810f408a4148b4a54927"
        "5a42a13f8690e4b692d49f408a4148b4a549275a93c85f86a87dcd30d25f408a4148"
        "b4a549275906497f83a8f517408a4148b4a549275ad416cf82ff034086aec31ec327"
        "d785b6007d286f4082497f864d833505b11f"),
    "chrome155": bytes.fromhex(
        "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a00001804000000000000"
        "010001000000020000000000040060000000060004000000000408000000000000ef"
        "00010001cb01250000000180000000ff8241882f91d35d055c87a7878440874148b1"
        "275ad1ffb8fe711cf350552f4f61e92ff3f7de0fe42db7fcfd29fcde9ec3d26b69fe"
        "7efbc1fc85b6ff9fa53f9d274ff50dcbb60ea93f9fbef07f226bf9408b4148b1275a"
        "d1ad49e3350582ff01408d4148b1275ad1ad5d034ca7b29f88fe791aa90fe11fcf40"
        "92b6b9ac1c8558d520a4b6c2ad617b5a54251f810f7ad5d07f66a281b0dae053fae4"
        "6aa43f8429a77a8102e0fb5391aa71afb53cb8d7f6a435d74179163cc64b0db2eaec"
        "b8a7f59b1efd19fe94a0dd4aa62293a9ffb52f4f61e92b016db5c0b817029b8728ec"
        "330db2eaecb953ec497ca589d34d1f43aeba0c41a4c7a98f33a69a3fdf9a68fa1d75"
        "d0620d263d4c79a68fbed00177fe8d48e62b1d3cd1f46a4731581f734bf46a473158"
        "f058ebfa352398ac0ebaa6faf963e7efb4005defa1d75d0620d263d4c20d35459162"
        "f924e3aa62fdf782367efb4005dd408a4148b4a549275906497f83a8f517408a4148"
        "b4a549275a93c85f86a87dcd30d25f408a4148b4a549275ad416cf82ff03408a4148"
        "b4a549275a42a13f8690e4b692d49f50929bd9abfa5242cb40d25fa523b3e94f684c"
        "9f518b2d4b70ddf45abefb4005df4086aec31ec327d785b6007d286f"),
}


def headers_frame(fields, *, stream_id=SID, flags=FLAG_END_HEADERS | FLAG_END_STREAM,
                  encoder=None):
    return frame(HEADERS, flags, stream_id, (encoder or Encoder()).encode(fields))


def response(frames, *, profile=firefox157):
    """Send one GET on a scripted connection and read what `frames` answer."""
    tls = hostile.ScriptedTls([b"".join(frames)])
    connection = Http2Connection(tls, profile=profile)
    stream_id = connection.send_request("GET", "/", "example.test")
    return connection.read_response(stream_id)


class TestHeaderBytes(unittest.TestCase):
    """D6, H8, X2: a header value is the bytes on the wire. Decoding them as
    UTF-8 crashed on a latin-1 byte and, through the sidecar, turned UTF-8
    into different bytes or dropped the response."""

    def test_latin1_byte_in_h2_header_round_trips(self):
        got = response([headers_frame([(b":status", b"200"),
                                       (b"x-test", b"caf\xe9")])])
        self.assertEqual(header_tools.to_wire(got.header("x-test")), b"caf\xe9")

    def test_utf8_header_survives_sidecar_serialise(self):
        from pybrws.proxy import serialise

        for raw in (b'attachment; filename="\xc3\xa9t\xc3\xa9.pdf"',
                    b'attachment; filename="\xe2\x82\xac.pdf"'):
            with self.subTest(raw=raw):
                got = response([headers_frame([(b":status", b"200"),
                                               (b"content-disposition", raw)])])
                self.assertIn(b"content-disposition: " + raw, serialise(got))

    def test_ascii_navigation_bytes_unchanged(self):
        for profile in (firefox157, chrome155):
            with self.subTest(profile=profile.NAME):
                tls = hostile.ScriptedTls([])
                Http2Connection(tls, profile=profile).send_request(
                    "GET", "/", "example.com")
                self.assertEqual(bytes(tls.sent), NAVIGATION_BYTES[profile.NAME])


FLAG_PADDED = 0x08
FLAG_PRIORITY = 0x20


def padded(body: bytes, pad: int) -> bytes:
    return bytes([pad]) + body + bytes(pad)


class TestPadding(unittest.TestCase):
    """H1: RFC 9113 6.1 and 6.2. A padded frame starts with a pad length and
    ends with that many bytes of padding; neither is content."""

    def test_padded_data_strips_padding(self):
        got = response([
            headers_frame([(b":status", b"200")], flags=FLAG_END_HEADERS),
            frame(DATA, FLAG_END_STREAM | FLAG_PADDED, SID, padded(b"hello", 9)),
        ])
        self.assertEqual(got.body, b"hello")

    def test_padded_headers_with_priority_decode(self):
        block = Encoder().encode([(b":status", b"200"), (b"x-a", b"1")])
        payload = padded(bytes(5) + block, 7)   # pad length, priority, block, pad
        got = response([frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM
                              | FLAG_PADDED | FLAG_PRIORITY, SID, payload)])
        self.assertEqual((got.status, got.header("x-a")), (200, "1"))

    def test_pad_length_not_below_payload_is_protocol_error(self):
        from pybrws.http2 import Http2Error

        with self.assertRaises(Http2Error) as caught:
            response([
                headers_frame([(b":status", b"200")], flags=FLAG_END_HEADERS),
                frame(DATA, FLAG_END_STREAM | FLAG_PADDED, SID, b"\x0aabc"),
            ])
        self.assertIn("PROTOCOL_ERROR", str(caught.exception))

    def test_window_update_credits_the_whole_padded_frame(self):
        payload = padded(b"x" * 20, 30)
        tls = hostile.ScriptedTls([b"".join([
            headers_frame([(b":status", b"200")], flags=FLAG_END_HEADERS),
            frame(DATA, FLAG_PADDED, SID, payload),
            frame(DATA, FLAG_END_STREAM, SID, b"y"),
        ])])
        connection = Http2Connection(tls)
        connection.read_response(connection.send_request("GET", "/", "example.test"))
        sent = bytes(tls.sent)[len(PREFACE):]   # the preface is not a frame
        increments = [int.from_bytes(p, "big")
                      for kind, _flags, stream, p in hostile.frames_in(sent)
                      if kind == 0x08 and stream == 0]
        # RFC 9113 6.9.1: flow control counts the whole payload, padding too.
        self.assertIn(len(payload), increments)


class TestCompressionFailure(unittest.TestCase):
    """H1, Review Focus 4: an HPACK failure leaves the connection's header
    table unknown, so the connection is finished, and the next request goes
    out on a fresh one."""

    BAD_BLOCK = frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, SID,
                      b"\xff\xff\xff\xff\x0f")   # an index far past the table

    def test_hpack_failure_marks_connection_broken(self):
        from pybrws.http2 import Http2Error

        tls = hostile.ScriptedTls([self.BAD_BLOCK])
        connection = Http2Connection(tls)
        with self.assertRaises(Http2Error) as caught:
            connection.read_response(connection.send_request("GET", "/", "example.test"))
        self.assertIn("COMPRESSION_ERROR", str(caught.exception))
        self.assertTrue(connection.broken)

    def test_session_reopens_after_broken_connection(self):
        from pybrws.http2 import Http2Error
        from pybrws.session import Session

        good = headers_frame([(b":status", b"200")])
        scripts = iter([[self.BAD_BLOCK], [good]])

        def fake_open(host, port, timeout=None):
            tls = hostile.ScriptedTls(next(scripts))
            return tls, Http2Connection(tls)

        with Session(proxy=False) as session:
            session._open = fake_open
            with self.assertRaises(Http2Error):
                session.get("https://example.test/")
            self.assertEqual(session.get("https://example.test/").status, 200)


class TestTrailersAndInformational(unittest.TestCase):
    """H2, H3: a header block after the final response head is trailers, and
    a 1xx head is informational. Neither replaces the real head."""

    def test_trailers_do_not_overwrite_head(self):
        import gzip

        encoder = Encoder()
        body = b"the response body"
        got = response([
            headers_frame([(b":status", b"200"), (b"content-encoding", b"gzip")],
                          flags=FLAG_END_HEADERS, encoder=encoder),
            frame(DATA, 0, SID, gzip.compress(body)),
            headers_frame([(b"grpc-status", b"0")], encoder=encoder),
        ])
        self.assertEqual(got.status, 200)
        self.assertEqual(got.header("content-encoding"), "gzip")
        self.assertEqual(got.trailers, [("grpc-status", "0")])
        self.assertEqual(got.body, body)

    def _early_hints_then_ok(self):
        encoder = Encoder()
        return b"".join([
            headers_frame([(b":status", b"103"), (b"link", b"</s.css>")],
                          flags=FLAG_END_HEADERS, encoder=encoder),
            headers_frame([(b":status", b"200")], flags=FLAG_END_HEADERS,
                          encoder=encoder),
            frame(DATA, FLAG_END_STREAM, SID, b"ok"),
        ])

    def test_read_response_skips_103(self):
        got = response([self._early_hints_then_ok()])
        self.assertEqual((got.status, got.body), (200, b"ok"))

    def test_stream_response_skips_103(self):
        tls = hostile.ScriptedTls([self._early_hints_then_ok()])
        connection = Http2Connection(tls)
        head, chunks = connection.stream_response(
            connection.send_request("GET", "/", "example.test"))
        self.assertEqual((head.status, b"".join(chunks)), (200, b"ok"))


class BudgetTls(hostile.ScriptedTls):
    """A scripted transport that stops a client that writes without end."""

    def __init__(self, chunks, budget=1000):
        super().__init__(chunks)
        self.writes = 0
        self.budget = budget

    def send(self, data):
        self.writes += 1
        if self.writes > self.budget:
            raise AssertionError("the client kept writing without reading")
        super().send(data)


def settings_frame(*pairs, raw=None):
    payload = raw if raw is not None else b"".join(
        k.to_bytes(2, "big") + v.to_bytes(4, "big") for k, v in pairs)
    return frame(0x04, 0, 0, payload)


class TestSettingsValidation(unittest.TestCase):
    """H4: RFC 9113 6.5.2. A SETTINGS value out of range is a connection
    error. SETTINGS_MAX_FRAME_SIZE = 0 used to send empty DATA frames
    forever."""

    def _apply(self, frame_bytes):
        from pybrws.http2 import Http2Error

        tls = BudgetTls([frame_bytes])
        connection = Http2Connection(tls)
        with self.assertRaises(Http2Error) as caught:
            connection._pump()
            connection.send_request("POST", "/", "example.test", body=b"0123456789")
        sent = hostile.frames_in(bytes(tls.sent)[len(PREFACE):])
        self.assertFalse([f for f in sent if f[0] == DATA])
        return str(caught.exception)

    def test_max_frame_size_zero_is_rejected(self):
        self.assertIn("PROTOCOL_ERROR", self._apply(settings_frame((0x5, 0))))

    def test_initial_window_above_limit_is_rejected(self):
        self.assertIn("FLOW_CONTROL_ERROR", self._apply(settings_frame((0x4, 2**31))))

    def test_enable_push_two_is_rejected(self):
        self.assertIn("PROTOCOL_ERROR", self._apply(settings_frame((0x2, 2))))

    def test_settings_length_not_multiple_of_six_is_rejected(self):
        self.assertIn("FRAME_SIZE_ERROR", self._apply(settings_frame(raw=b"\x00\x05\x00\x00\x40")))


def goaway(last_stream_id: int, code: int = 0) -> bytes:
    return frame(0x07, 0, 0, last_stream_id.to_bytes(4, "big") + code.to_bytes(4, "big"))


class ReadBudgetTls(hostile.ScriptedTls):
    """Scripted, and stops a reader that keeps asking after the script ends."""

    def __init__(self, chunks, reads=50):
        super().__init__(chunks, at_end=AssertionError("read past the script"))
        self.reads = 0
        self.limit = reads

    def recv(self):
        self.reads += 1
        if self.reads > self.limit:
            raise AssertionError("the client kept reading")
        return super().recv()


class TestGoaway(unittest.TestCase):
    """H5: RFC 9113 6.8. Streams above GOAWAY's last_stream_id were never
    processed; request_many used to wait for them forever."""

    SPECS = [("GET", "/1", "example.test"), ("GET", "/2", "example.test"),
             ("GET", "/3", "example.test")]

    def test_request_many_yields_completed_then_raises_refused(self):
        from pybrws.http2 import StreamRefused

        encoder = Encoder()
        tls = ReadBudgetTls([b"".join([
            headers_frame([(b":status", b"200")], stream_id=SID,
                          flags=FLAG_END_HEADERS, encoder=encoder),
            frame(DATA, FLAG_END_STREAM, SID, b"one"),
            goaway(SID),
        ])])
        results = Http2Connection(tls).request_many(self.SPECS)
        self.assertEqual(next(results).body, b"one")
        with self.assertRaises(StreamRefused) as caught:
            next(results)
        self.assertEqual(caught.exception.requests, self.SPECS[1:])

    def test_no_new_streams_after_goaway(self):
        from pybrws.http2 import StreamRefused

        tls = ReadBudgetTls([goaway(0)])
        connection = Http2Connection(tls)
        connection._pump()
        before = len(tls.sent)
        with self.assertRaises(StreamRefused):
            connection.send_request("GET", "/", "example.test")
        self.assertEqual(len(tls.sent), before)
        self.assertTrue(connection.broken)

    def test_refused_stream_reset_is_stream_refused(self):
        from pybrws.http2 import StreamRefused

        tls = ReadBudgetTls([frame(0x03, 0, SID, (7).to_bytes(4, "big"))])
        connection = Http2Connection(tls)
        with self.assertRaises(StreamRefused):
            connection.read_response(connection.send_request("GET", "/", "example.test"))


class TestSizeLimits(unittest.TestCase):
    """H6: RFC 9113 4.2 -- a frame larger than the SETTINGS_MAX_FRAME_SIZE
    this client advertised is a FRAME_SIZE_ERROR -- and a cap on a header
    block, which CONTINUATION frames could otherwise grow without end."""

    def test_frame_above_advertised_max_is_rejected(self):
        from pybrws.http2 import Http2Error

        oversized = ((4 << 20).to_bytes(3, "big") + bytes([DATA, 0])
                     + SID.to_bytes(4, "big") + b"x" * 100)
        with self.assertRaises(Http2Error) as caught:
            response([headers_frame([(b":status", b"200")], flags=FLAG_END_HEADERS),
                      oversized])
        self.assertIn("FRAME_SIZE_ERROR", str(caught.exception))

    def test_header_block_over_cap_is_rejected(self):
        from pybrws.http2 import Http2Error

        piece = bytes(16000)
        frames = [frame(HEADERS, 0, SID, piece)]
        frames += [frame(CONTINUATION, 0, SID, piece) for _ in range(17)]
        with self.assertRaises(Http2Error) as caught:
            response(frames)
        self.assertIn("header block", str(caught.exception))


class TestEarlyResponse(unittest.TestCase):
    """H7: RFC 9113 8.1. A server may answer before the request body is
    done, then reset the stream with NO_ERROR to stop the upload. The
    response stands."""

    def test_complete_response_then_reset_no_error_is_kept(self):
        tls = ReadBudgetTls([b"".join([
            headers_frame([(b":status", b"200")], flags=FLAG_END_HEADERS),
            frame(DATA, FLAG_END_STREAM, SID, b"done"),
            frame(0x03, 0, SID, (0).to_bytes(4, "big")),   # RST_STREAM NO_ERROR
        ])])
        connection = Http2Connection(tls)
        # Larger than the 65535-byte initial window, so the upload has to
        # wait for credit and reads the early answer instead.
        got = connection.request("POST", "/upload", "example.test",
                                 body=bytes(100_000))
        self.assertEqual((got.status, got.body), (200, b"done"))


if __name__ == "__main__":
    unittest.main()
