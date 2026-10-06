"""Response representation and content decoding, shared by both HTTP versions."""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field


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
        from compression import zstd

        return zstd.decompress(body)
    raise ContentEncodingError("unsupported content-encoding " + encoding)


@dataclass
class Response:
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    http_version: str = ""

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None

    def text(self, errors: str = "replace") -> str:
        return self.body.decode("utf-8", errors)
