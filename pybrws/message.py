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
