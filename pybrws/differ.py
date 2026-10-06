"""Fase 0 - EL DIFFER. Esto lo escribes TU.

Dado el ClientHello objetivo (Firefox) y el tuyo, decir exactamente que
difiere, campo por campo. Sin esto estas ciego en la Fase 2.

Un buen differ te dice:

    cipher_suites    len 17 vs 15        <- cuantos
    cipher_suites[3] 0xc02b vs 0xc030    <- cual, en que posicion
    extensions       falta record_size_limit (28)
    extensions       sobra  session_ticket (35)
    extensions       orden distinto a partir del indice 4
    key_share        48B vs 1216B

Dos campos NUNCA deben contar como diferencia real: `random` y la llave
publica dentro de `key_share`. Por definicion cambian en cada conexion.
Decide como los manejas (ignorar? marcar como "esperado"?) y documentalo:
esa decision define que significa "byte-identico" en tu proyecto.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import ClientHello


@dataclass(frozen=True)
class Difference:
    """One divergence between two ClientHellos."""

    field: str          # "cipher_suites", "extensions", "extensions[3].type"
    expected: object    # what the target has
    actual: object      # what we produced
    note: str = ""

    def __str__(self) -> str:
        tail = f"  ({self.note})" if self.note else ""
        return f"{self.field}: expected {self.expected!r}, got {self.actual!r}{tail}"


def diff(target: ClientHello, candidate: ClientHello) -> list[Difference]:
    """Compare two ClientHellos. Empty list means they match.

    Args:
        target:    the golden file - a real browser.
        candidate: what we emitted.
    """
    raise NotImplementedError("Fase 0: escribelo tu. Ver el docstring del modulo.")
