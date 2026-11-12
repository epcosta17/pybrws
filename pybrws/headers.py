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


def to_wire(value: str) -> bytes:
    """A header value as the bytes that go on the wire.

    Header values are bytes, not text. Everywhere in this client a value is
    held as a str whose characters are those bytes one to one (latin-1), so
    whatever arrived -- UTF-8, latin-1, anything -- goes back out unchanged.
    """
    return value.encode("latin-1")


def from_wire(raw: bytes) -> str:
    """The str form of header bytes received from the wire; see `to_wire`."""
    return raw.decode("latin-1") if isinstance(raw, (bytes, bytearray)) else raw


def check_field(name: str, value: str) -> None:
    """Refuse a header that would split the message it is written into.

    CR and LF end a header line in HTTP/1.1, so a value carrying them writes
    a second header -- or a second request -- of the sender's choosing; NUL
    is refused by every HTTP version. Checked for every header sent,
    whatever its source: a caller's, a profile's, or a cookie a server set.
    """
    for part in (name, value):
        if "\r" in part or "\n" in part or "\x00" in part:
            raise ValueError("header %r carries CR, LF or NUL, which would "
                             "split the message" % name)


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


def insert_before(headers: Headers, name: str, value: str, anchor: str | None):
    """Place a header immediately before `anchor`, or at the end if absent.

    `anchor` may be None, which means the end on purpose rather than by
    accident: Chrome puts Cookie last over HTTP/1.1, so there is no header
    for it to precede, and saying so beats naming one that does not exist.
    """
    return insert_all_before(headers, name, [value], anchor)


def insert_all_before(headers: Headers, name: str, values,
                      anchor: str | None):
    """Place several headers of the same name at the anchor, in order.

    HTTP/2 lets a browser send one `cookie` field per cookie, and Firefox
    does, so this cannot collapse them into one.
    """
    added = [(name, value) for value in values]
    out = []
    placed = False
    for existing, existing_value in headers:
        if not placed and anchor is not None and existing.lower() == anchor.lower():
            out.extend(added)
            placed = True
        if existing.lower() != name.lower():
            out.append((existing, existing_value))
    if not placed:
        out.extend(added)
    return out


#: Marks where a header set was captured carrying a cookie.
COOKIE_SLOT = "{cookie}"


def place_cookies(headers: Headers, name: str, values, *anchors: str | None):
    """Put a request's cookie headers where its header set says they go.

    A set with a `{cookie}` slot was captured carrying a cookie there, so the
    values take the slot, under its name, and with no values the slot's
    header is left out. A set without one takes them before the first of
    `anchors` it has, or last if it has none of them, and with no values
    stays as it is.
    """
    headers = list(headers)
    for index, (slot_name, value) in enumerate(headers):
        if COOKIE_SLOT in value:
            return (headers[:index] + [(slot_name, cookie) for cookie in values]
                    + headers[index + 1:])
    if not values:
        return headers
    present = {existing.lower() for existing, _ in headers}
    anchor = next((anchor for anchor in anchors
                   if anchor is not None and anchor.lower() in present), None)
    return insert_all_before(headers, name, values, anchor)


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
