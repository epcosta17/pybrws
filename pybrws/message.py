"""Response representation and content decoding, shared by both HTTP versions."""

from __future__ import annotations

import json as _json
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from urllib.parse import urlencode


class ContentEncodingError(Exception):
    pass


# D3: what a buffered response may decode to, unless the caller says else.
DEFAULT_MAX_BODY = 128 * 2**20


class BodyTooLarge(ContentEncodingError):
    """A response body past `max_body_size`, refused before it is held whole."""


def body_too_large(limit: int) -> BodyTooLarge:
    return BodyTooLarge("response body passed max_body_size (%d bytes); pass "
                        "max_body_size=None to lift the cap" % limit)


def decompress(body: bytes, encoding: str,
               max_size: int | None = DEFAULT_MAX_BODY) -> bytes:
    """Decode a whole body.

    Built on IncrementalDecoder, so the cap is checked while the output
    grows: 102 bytes of brotli that would become 64 MiB raise BodyTooLarge
    at `max_size` (None: no cap). An identity body is returned as it is.
    """
    decoder = IncrementalDecoder(encoding, max_size=max_size)
    if decoder.identity or not body:
        # No body -- a HEAD, a 204, a 304 -- has nothing to decode, whatever
        # its Content-Encoding says.
        if max_size is not None and len(body) > max_size:
            raise body_too_large(max_size)
        return body
    out = bytearray()
    for piece in decoder.pieces(body):
        out += piece
    out += decoder.finish()
    return bytes(out)


def _zlib_header(data: bytes) -> bool:
    """Whether `data` opens with a zlib header (RFC 1950 2.2): deflate, a
    window of at most 32 KiB, and a check making the pair a multiple of 31.
    Raw deflate essentially never does: its first byte is a block header."""
    cmf, flg = data[0], data[1]
    return cmf & 0x0F == 8 and cmf >> 4 <= 7 and (cmf << 8 | flg) % 31 == 0


def encode_body(data=None, json=None) -> tuple[bytes, str | None]:
    """Turn a caller's body into bytes and the content type it implies.

    `data` may be bytes, a string, or a mapping to form-encode. `json` is
    serialised. Returns (body, content_type), content_type None when the
    caller should supply its own.
    """
    if data is not None and json is not None:
        raise ValueError("pass data or json, not both")
    if json is not None:
        return _json.dumps(json, separators=(",", ":")).encode(), "application/json"
    if data is None:
        return b"", None
    if isinstance(data, bytes):
        return data, None
    if isinstance(data, str):
        return data.encode(), None
    return (urlencode(data, doseq=True).encode(),
            "application/x-www-form-urlencoded")


@dataclass
class Response:
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    http_version: str = ""
    url: str = ""
    history: list = field(default_factory=list)
    # HTTP/2 trailers: fields sent after the body, kept apart from the head.
    trailers: list[tuple[str, str]] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None

    def text(self, errors: str = "replace") -> str:
        return self.body.decode(self.charset, errors)

    def json(self):
        """Decode the body as JSON."""
        return _json.loads(self.body)

    @property
    def charset(self) -> str:
        content_type = self.header("content-type") or ""
        for part in content_type.split(";")[1:]:
            key, _, value = part.partition("=")
            if key.strip().lower() == "charset":
                return value.strip().strip('"') or "utf-8"
        return "utf-8"

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400


class IncrementalDecoder:
    """Decompresses a response as it arrives.

    The whole-body `decompress` cannot be used piecewise: gzip and brotli
    both carry state across chunk boundaries, and a chunk is not a valid
    compressed stream on its own.

    Output is bounded per call. `pieces` never makes a piece larger than
    `step`, however small the input behind it -- 102 bytes of brotli are
    64 MiB -- and every call into a decoder is limited the same way, so
    memory stays near `step`. With `max_size` the total is capped as well:
    BodyTooLarge as soon as it is passed.
    """

    # zstandard, the zstd decoder before Python 3.14, takes no output limit,
    # so its input goes in this many bytes at a time. A zstd block yields at
    # most 128 KiB and takes at least 4 bytes, so a call yields at most
    # eight blocks: 1 MiB.
    ZSTANDARD_SLICE = 32

    GZIP_MAGIC = b"\x1f\x8b"

    def __init__(self, encoding: str, max_size: int | None = None) -> None:
        self.encoding = (encoding or "").strip().lower()
        self.max_size = max_size
        self.produced = 0
        self._impl = None
        self._kind = ""
        # A body may hold several gzip members or zstd frames (RFC 1952 2.2,
        # RFC 8878 3.1). Once one is complete, the bytes after it decide.
        self._fed = 0            # input bytes seen
        self._ended = False      # the current member or frame is complete
        self._held = b""         # bytes after it, too few yet to decide on
        self._ignoring = False   # what follows is no member: not body
        if self.encoding in ("", "identity"):
            return
        if self.encoding == "gzip":
            self._impl, self._kind = zlib.decompressobj(wbits=47), "zlib"
        elif self.encoding == "deflate":
            # The zlib format or raw deflate: the first two bytes decide.
            self._kind = "zlib"
        elif self.encoding == "br":
            import brotli

            self._impl, self._kind = brotli.Decompressor(), "brotli"
        elif self.encoding == "zstd":
            # Standard library from Python 3.14; the package covers older ones.
            try:
                from compression.zstd import ZstdDecompressor
            except ImportError:
                try:
                    import zstandard
                except ImportError:
                    raise ContentEncodingError(
                        "zstd response but no decoder: needs Python 3.14 or "
                        "the zstandard package. The profile advertises zstd "
                        "because Firefox does, so servers will use it."
                    )
                self._impl = zstandard.ZstdDecompressor().decompressobj()
                self._kind = "zstandard"
            else:
                self._impl, self._kind = ZstdDecompressor(), "zstd"
        else:
            raise ContentEncodingError("unsupported content-encoding "
                                       + self.encoding)

    @property
    def identity(self) -> bool:
        return not self._kind

    def feed(self, chunk: bytes) -> bytes:
        """Decode `chunk` and return its output whole: `pieces`, joined."""
        return b"".join(self.pieces(chunk))

    def pieces(self, chunk: bytes, step: int = 1 << 20) -> Iterator[bytes]:
        """Decode `chunk`, yielding its output in pieces of at most `step`."""
        self._fed += len(chunk)
        for out in self._decode(chunk, step):
            # Brotli's limit is approximate and zstandard has none; their
            # calls are still bounded, and the pieces are evened out here.
            for at in range(0, len(out), step):
                piece = out[at:at + step]
                self._count(len(piece))
                yield piece

    def _decode(self, data: bytes, step: int) -> Iterator[bytes]:
        if not self._kind:
            yield data
            return
        if self._impl is None:
            # deflate. RFC 9110 8.4.1.2 makes it the zlib format; some
            # servers send raw deflate, and browsers take both.
            data, self._held = self._held + data, b""
            if len(data) < 2:
                self._held = data
                return
            self._impl = zlib.decompressobj(wbits=15 if _zlib_header(data) else -15)
        while True:
            if self._ended:
                data, self._held = self._held + data, b""
                if not data or not self._next(data):
                    return
            data = yield from self._run(data, step)
            if not (self._ended and data):
                return

    def _next(self, data: bytes) -> bool:
        """Start a new member or frame on `data`, which follows a complete
        one. False when there is nothing to decode, or not yet."""
        if self._ignoring:
            return False
        if self._kind == "zlib":
            if self.encoding != "gzip":
                self._ignoring = True   # raw deflate is one stream
                return False
            if len(data) < len(self.GZIP_MAGIC):
                self._held = data
                return False
            if not data.startswith(self.GZIP_MAGIC):
                # Not a member: the stray bytes some servers send after the
                # body, which browsers ignore too.
                self._ignoring = True
                return False
            self._impl = zlib.decompressobj(wbits=31)
        elif self._kind == "zstd":
            from compression.zstd import ZstdDecompressor

            self._impl = ZstdDecompressor()
        elif self._kind == "zstandard":
            import zstandard

            self._impl = zstandard.ZstdDecompressor().decompressobj()
        else:
            return False
        self._ended = False
        return True

    def _run(self, data: bytes, step: int):
        """Decode `data` with the current decoder, each call bounded by
        `step`. Returns the bytes after the member or frame if it ended
        within `data`, else b""."""
        impl = self._impl
        if self._kind == "zlib":
            while True:
                out = impl.decompress(data, step)
                yield out
                data = impl.unconsumed_tail
                if impl.eof:
                    self._ended = True
                    return impl.unused_data
                if not data and len(out) < step:
                    return b""
        if self._kind == "brotli":
            yield impl.process(data, output_buffer_limit=step)
            # Feeding nothing drains what the limit held back; nothing
            # coming out means it wants more input.
            while not impl.is_finished():
                out = impl.process(b"", output_buffer_limit=step)
                if not out:
                    break
                yield out
            return b""
        if self._kind == "zstd":
            yield impl.decompress(data, max_length=step)
            while not impl.needs_input and not impl.eof:
                yield impl.decompress(b"", max_length=step)
            if impl.eof:
                self._ended = True
                return impl.unused_data
            return b""
        for at in range(0, len(data), self.ZSTANDARD_SLICE):
            yield impl.decompress(data[at:at + self.ZSTANDARD_SLICE])
            if impl.eof:
                self._ended = True
                return impl.unused_data + data[at + self.ZSTANDARD_SLICE:]
        return b""

    def _count(self, size: int) -> None:
        self.produced += size
        if self.max_size is not None and self.produced > self.max_size:
            raise body_too_large(self.max_size)

    def finish(self) -> bytes:
        """Flush the decoder, then insist the compressed stream really ended.

        Fed chunk by chunk, a decoder has no other guard: a connection cut
        mid-body would hand the caller a short document and no error at
        all, which reads exactly like a page that changed. `decompress`
        ends here too, so whole bodies get the same check. No body at all
        is not a truncation: a HEAD or a 304 carries the header with
        nothing to decode.
        """
        if not self._kind or not self._fed:
            return b""   # identity, or no body at all: nothing went missing
        tail = b""
        if self._impl is not None and not self._ended and hasattr(self._impl, "flush"):
            tail = self._impl.flush()
        self._count(len(tail))
        if not self._complete():
            raise ContentEncodingError(
                self.encoding + " stream ended early: the body is truncated"
            )
        return tail

    def _complete(self) -> bool:
        """Whether the decoder saw the end-of-stream marker."""
        if self._ended:
            return True   # whatever came after was not a member: not body
        if self._impl is None:
            return False  # deflate that never got as far as its header
        if hasattr(self._impl, "is_finished"):
            return self._impl.is_finished()        # brotli
        return getattr(self._impl, "eof", True)    # zlib, zstd
