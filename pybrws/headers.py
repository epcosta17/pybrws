"""Header list handling.

Order is part of the fingerprint, so a caller's headers are merged into the
profile's list rather than appended to it or replacing it. A value given for
a header the profile already sends takes its place and keeps its position; a
header the profile does not send is added at the end, where a browser puts
the ones it was asked to add.
"""

from __future__ import annotations

from typing import Iterable, Mapping, Sequence

Headers = Sequence[tuple[str, str]]
Overrides = Mapping[str, str] | Iterable[tuple[str, str]] | None


def as_pairs(overrides: Overrides) -> list[tuple[str, str]]:
    if overrides is None:
        return []
    if isinstance(overrides, Mapping):
        return list(overrides.items())
    return [(name, value) for name, value in overrides]


def merge(base: Headers, overrides: Overrides) -> list[tuple[str, str]]:
    """Apply `overrides` to `base`, preserving the base order.

    A value of None removes the header, which is how a caller drops one the
    profile would otherwise send.
    """
    pairs = as_pairs(overrides)
    if not pairs:
        return list(base)

    replacements = {name.lower(): value for name, value in pairs}
    merged = []
    for name, value in base:
        key = name.lower()
        if key in replacements:
            new_value = replacements.pop(key)
            if new_value is None:
                continue
            merged.append((name, new_value))
        else:
            merged.append((name, value))

    for name, value in pairs:
        if name.lower() in replacements and value is not None:
            merged.append((name, value))
            replacements.pop(name.lower(), None)
    return merged


def insert_before(headers: Headers, name: str, value: str, anchor: str):
    """Place a header immediately before `anchor`, or at the end if absent."""
    out = []
    placed = False
    for existing, existing_value in headers:
        if not placed and existing.lower() == anchor.lower():
            out.append((name, value))
            placed = True
        if existing.lower() != name.lower():
            out.append((existing, existing_value))
    if not placed:
        out.append((name, value))
    return out


def get(headers: Headers, name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers:
        if key.lower() == wanted:
            return value
    return None


def has(headers: Headers, name: str) -> bool:
    return get(headers, name) is not None
