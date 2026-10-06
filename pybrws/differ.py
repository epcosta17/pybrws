"""Structural comparison of two ClientHellos."""

from __future__ import annotations

from dataclasses import dataclass

from .model import ClientHello


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


def diff(target: ClientHello, candidate: ClientHello) -> list[Difference]:
    """Compare two ClientHellos.

    `random` and the public key inside `key_share` vary per connection and are
    not reported as differences.

    Args:
        target: the reference capture.
        candidate: the ClientHello under test.

    Returns:
        The differences found, empty if the two match.
    """
    raise NotImplementedError
