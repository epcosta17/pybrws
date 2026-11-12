"""Helper for tests that need a reader's own profile file on disk."""

from __future__ import annotations

from pathlib import Path

MY_FIREFOX = "from pybrws.profiles.firefox157 import *\nNAME = 'my-firefox'\n"


def write_profile(directory: Path, text: str = MY_FIREFOX,
                  name: str = "my_firefox.py") -> Path:
    path = Path(directory) / name
    path.write_text(text, encoding="utf-8")
    return path
