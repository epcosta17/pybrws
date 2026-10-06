"""Structural comparison of two ClientHellos."""

from __future__ import annotations

from dataclasses import dataclass

from .model import ClientHello, extension_name, is_grease

# Extension payloads that carry per-connection material. Their length is
# structural, their content is not.
VOLATILE_EXTENSIONS = frozenset(
    {
        35,     # session_ticket
        41,     # pre_shared_key
        51,     # key_share
        65037,  # encrypted_client_hello, greased: randomised per connection
    }
)

_GREASE = "GREASE"


@dataclass(frozen=True)
class Difference:
    """One divergence between two ClientHellos."""

    field: str
    expected: object
    actual: object
    note: str = ""

    def __str__(self) -> str:
        tail = f"  ({self.note})" if self.note else ""
        return f"{self.field}: expected {self.expected!r}, got {self.actual!r}{tail}"


def _slot(ext_type: int) -> object:
    """Identity of an extension for presence and ordering purposes.

    GREASE values are drawn at random per connection, so every GREASE
    extension collapses to a single identity.
    """
    return _GREASE if is_grease(ext_type) else ext_type


def _label(ext_type: int) -> str:
    return f"{extension_name(ext_type)} ({ext_type})"


def _compare_scalar(field: str, expected: object, actual: object) -> list[Difference]:
    if expected == actual:
        return []
    return [Difference(field, expected, actual)]


def _compare_sequence(field: str, expected: list[int], actual: list[int]) -> list[Difference]:
    found: list[Difference] = []
    if len(expected) != len(actual):
        found.append(
            Difference(field, len(expected), len(actual), "element count")
        )
    for index, (want, got) in enumerate(zip(expected, actual)):
        if want != got:
            found.append(
                Difference(f"{field}[{index}]", f"0x{want:04x}", f"0x{got:04x}")
            )
    return found


def _compare_extensions(target: ClientHello, candidate: ClientHello) -> list[Difference]:
    found: list[Difference] = []

    want_slots = [_slot(e.type) for e in target.extensions]
    got_slots = [_slot(e.type) for e in candidate.extensions]

    missing = [s for s in want_slots if s not in got_slots]
    unexpected = [s for s in got_slots if s not in want_slots]

    for slot in missing:
        label = _GREASE if slot == _GREASE else _label(slot)
        found.append(Difference("extensions", label, None, "missing"))
    for slot in unexpected:
        label = _GREASE if slot == _GREASE else _label(slot)
        found.append(Difference("extensions", None, label, "unexpected"))

    if not missing and not unexpected and want_slots != got_slots:
        found.append(
            Difference("extensions.order", want_slots, got_slots, "same set, different order")
        )

    by_type = {e.type: e for e in candidate.extensions}
    for ext in target.extensions:
        if is_grease(ext.type):
            continue
        other = by_type.get(ext.type)
        if other is None:
            continue
        field = f"extensions.{extension_name(ext.type)}"
        if ext.type in VOLATILE_EXTENSIONS:
            if len(ext.data) != len(other.data):
                found.append(
                    Difference(field, len(ext.data), len(other.data), "payload length")
                )
        elif ext.data != other.data:
            found.append(
                Difference(field, ext.data.hex(), other.data.hex(), "payload")
            )

    return found


def diff(target: ClientHello, candidate: ClientHello) -> list[Difference]:
    """Compare two ClientHellos.

    `random` and the payloads listed in `VOLATILE_EXTENSIONS` vary per
    connection and are compared by length only, or not at all.

    Args:
        target: the reference capture.
        candidate: the ClientHello under test.

    Returns:
        The differences found, empty if the two match.
    """
    found: list[Difference] = []
    found += _compare_scalar(
        "legacy_version", f"0x{target.legacy_version:04x}", f"0x{candidate.legacy_version:04x}"
    )
    # session_id is 32 random bytes in TLS 1.3 compatibility mode.
    found += _compare_scalar(
        "session_id.length", len(target.session_id), len(candidate.session_id)
    )
    found += _compare_sequence("cipher_suites", target.cipher_suites, candidate.cipher_suites)
    found += _compare_scalar(
        "compression_methods", target.compression_methods, candidate.compression_methods
    )
    found += _compare_extensions(target, candidate)
    return found
