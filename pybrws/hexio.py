"""Hex stream I/O."""

from __future__ import annotations

import re
from pathlib import Path

_NOT_HEX = re.compile(r"[^0-9a-fA-F]")

# One line of `hexdump`: an 8-digit offset, the bytes, then |text|.
_HEXDUMP_LINE = re.compile(r"^[0-9a-fA-F]{8}  (?P<hex>[0-9a-fA-F ]*?)\s*\|.*\|$")


def load_hex(path: str | Path) -> bytes:
    """Read a hex dump, ignoring whitespace, colons, 0x prefixes and comments.

    `hexdump`'s own layout is recognised line by line and only its byte
    column read: the offset and the text column are not data, and the text
    can hold digits, A-F and a '#' that would pass for data or a comment.
    """
    text = Path(path).read_text(encoding="utf-8")
    lines = []
    for line in text.splitlines():
        dumped = _HEXDUMP_LINE.match(line.rstrip("\r"))
        lines.append(dumped.group("hex") if dumped else line.split("#", 1)[0])
    text = "\n".join(lines)
    text = text.replace("0x", "").replace("0X", "")
    cleaned = _NOT_HEX.sub("", text)
    if len(cleaned) % 2:
        raise ValueError(f"{path}: odd number of hex digits ({len(cleaned)})")
    return bytes.fromhex(cleaned)


def save_hex(path: str | Path, data: bytes, width: int = 32) -> None:
    """Write bytes as a wrapped hex dump."""
    body = data.hex()
    lines = [body[i : i + width * 2] for i in range(0, len(body), width * 2)]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def hexdump(data: bytes, width: int = 16, start: int = 0) -> str:
    """Render bytes as an offset / hex / ascii dump."""
    out = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{start + off:08x}  {hexpart}  |{text}|")
    return "\n".join(out)
