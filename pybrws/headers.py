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
    return insert_all_before(headers, name, [value], anchor)


def insert_all_before(headers: Headers, name: str, values, anchor: str):
    """Place several headers of the same name at the anchor, in order.

    HTTP/2 lets a browser send one `cookie` field per cookie, and Firefox
    does, so this cannot collapse them into one.
    """
    added = [(name, value) for value in values]
    out = []
    placed = False
    for existing, existing_value in headers:
        if not placed and existing.lower() == anchor.lower():
            out.extend(added)
            placed = True
        if existing.lower() != name.lower():
            out.append((existing, existing_value))
    if not placed:
        out.extend(added)
    return out


def get(headers: Headers, name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers:
        if key.lower() == wanted:
            return value
    return None


def has(headers: Headers, name: str) -> bool:
    return get(headers, name) is not None


def fill(headers: Headers, **context) -> list[tuple[str, str]]:
    """Substitute {placeholders} in header values.

    A placeholder resolving to nothing removes its header, which is how an
    absent Referer disappears rather than being sent empty.
    """
    out = []
    for name, value in headers:
        for key, replacement in context.items():
            token = "{" + key + "}"
            if token not in value:
                continue
            if replacement in (None, ""):
                value = None
                break
            value = value.replace(token, str(replacement))
        if value is not None:
            out.append((name, value))
    return out
