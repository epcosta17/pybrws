"""Response representation and content decoding, shared by both HTTP versions."""

from __future__ import annotations

import json as _json
import zlib
from dataclasses import dataclass, field
from urllib.parse import urlencode


class ContentEncodingError(Exception):
    pass


def decompress(body: bytes, encoding: str) -> bytes:
    encoding = encoding.strip().lower()
    if encoding in ("", "identity"):
        return body
    if encoding == "gzip":
        return zlib.decompress(body, wbits=47)
    if encoding == "deflate":
        return zlib.decompress(body, wbits=-15)
    if encoding == "br":
        import brotli

        return brotli.decompress(body)
    if encoding == "zstd":
        # Standard library from Python 3.14; the package covers older ones.
        try:
            from compression import zstd
        except ImportError:
            try:
                import zstandard
            except ImportError:
                raise ContentEncodingError(
                    "zstd response but no decoder: needs Python 3.14 or the "
                    "zstandard package. The profile advertises zstd because "
                    "Firefox does, so servers will use it."
                )
            return zstandard.ZstdDecompressor().decompress(body)
        return zstd.decompress(body)
    raise ContentEncodingError("unsupported content-encoding " + encoding)


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
    """

    def __init__(self, encoding: str) -> None:
        self.encoding = (encoding or "").strip().lower()
        self._impl = None
        if self.encoding in ("", "identity"):
            return
        if self.encoding == "gzip":
            self._impl = zlib.decompressobj(wbits=47)
        elif self.encoding == "deflate":
            self._impl = zlib.decompressobj(wbits=-15)
        elif self.encoding == "br":
            import brotli

            self._impl = brotli.Decompressor()
        elif self.encoding == "zstd":
            try:
                from compression.zstd import ZstdDecompressor
            except ImportError:
                try:
                    from zstandard import ZstdDecompressor
                except ImportError:
                    raise ContentEncodingError(
                        "zstd response but no decoder: needs Python 3.14 or "
                        "the zstandard package"
                    )
            self._impl = ZstdDecompressor()
        else:
            raise ContentEncodingError("unsupported content-encoding "
                                       + self.encoding)

    def feed(self, chunk: bytes) -> bytes:
        if self._impl is None:
            return chunk
        if hasattr(self._impl, "decompress"):
            return self._impl.decompress(chunk)
        return self._impl.process(chunk)

    def finish(self) -> bytes:
        """Flush the decoder, then insist the compressed stream really ended.

        This is the asymmetry worth closing: the whole-body `decompress`
        raises on a truncated stream, because zlib refuses to return a
        partial result. Feeding chunk by chunk has no such guard, so a
        connection cut mid-body would hand the caller a short document and
        no error at all, which reads exactly like a page that changed.
        """
        if self._impl is None:
            return b""
        tail = self._impl.flush() if hasattr(self._impl, "flush") else b""
        if not self._complete():
            raise ContentEncodingError(
                self.encoding + " stream ended early: the body is truncated"
            )
        return tail

    def _complete(self) -> bool:
        """Whether the decoder saw the end-of-stream marker."""
        if hasattr(self._impl, "is_finished"):
            return self._impl.is_finished()        # brotli
        return getattr(self._impl, "eof", True)    # zlib, zstd
