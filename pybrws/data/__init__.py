"""Reference captures that ship with the library."""

from __future__ import annotations

from importlib.resources import files

FILES: tuple[str, ...] = (
    "reference-firefox-157-windows-fresh.hex",
    "chrome-1.hex",
    "reference-firefox-157-peet.json",
)


def read_bytes(name: str) -> bytes:
    """The bytes of one packaged capture."""
    return files("pybrws.data").joinpath(name).read_bytes()


def read_text(name: str) -> str:
    """One packaged capture as UTF-8 text."""
    return files("pybrws.data").joinpath(name).read_text(encoding="utf-8")
