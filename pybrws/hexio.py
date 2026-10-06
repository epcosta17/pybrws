"""Load and save hex streams. Plumbing."""

from __future__ import annotations

import re
from pathlib import Path

_NOT_HEX = re.compile(r"[^0-9a-fA-F]")


def load_hex(path: str | Path) -> bytes:
    """Read a hex dump, ignoring whitespace, colons, 0x prefixes and comments."""
    text = Path(path).read_text(encoding="utf-8")
    text = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
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
    """Classic offset / hex / ascii dump, for eyeballing a diff."""
    out = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{start + off:08x}  {hexpart}  |{text}|")
    return "\n".join(out)
