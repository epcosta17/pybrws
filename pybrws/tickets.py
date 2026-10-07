"""Session tickets, and the keys they stand for.

A server hands these out after a handshake so the next one can skip proving
its identity again. Resuming is faster, but the reason it matters here is
that a browser's second connection to a host does not look like its first,
and a client that always looks like a first visit is distinguishable over
enough connections.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .keyschedule import CipherSuite, resumption_psk
from .parser import _Reader

AGE_MODULUS = 1 << 32


@dataclass
class Ticket:
    """One offer a server will recognise later."""

    identity: bytes
    psk: bytes
    age_add: int
    lifetime: int
    suite_id: int
    received: float = field(default_factory=time.time)

    def expired(self, now: float | None = None) -> bool:
        # RFC 8446 caps a ticket at seven days whatever the server says.
        limit = min(self.lifetime, 7 * 24 * 3600)
        return (now or time.time()) - self.received >= limit

    def obfuscated_age(self, now: float | None = None) -> int:
        """The age the server expects, in milliseconds and masked.

        The mask is the server's own random value, so an observer cannot
        read how long ago the ticket was issued.
        """
        elapsed = int(((now or time.time()) - self.received) * 1000)
        return (elapsed + self.age_add) % AGE_MODULUS


def parse_new_session_ticket(body: bytes, suite: CipherSuite,
                             resumption_secret: bytes) -> Ticket:
    """Turn a NewSessionTicket body into a usable Ticket."""
    reader = _Reader(body, "NewSessionTicket")
    lifetime = reader.uint(4)
    age_add = reader.uint(4)
    nonce = reader.vector(1)
    identity = reader.vector(2)
    reader.vector(2)  # extensions, early_data among them
    return Ticket(
        identity=identity,
        psk=resumption_psk(suite, resumption_secret, nonce),
        age_add=age_add,
        lifetime=lifetime,
        suite_id=suite.id,
    )


class TicketStore:
    """Tickets held per host, used once each."""

    def __init__(self) -> None:
        self._tickets: dict[str, list[Ticket]] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return sum(len(v) for v in self._tickets.values())

    def add(self, host: str, ticket: Ticket) -> None:
        with self._lock:
            self._tickets.setdefault(host, []).append(ticket)

    def take(self, host: str, suite_id: int | None = None) -> Ticket | None:
        """Remove and return a usable ticket for `host`, if there is one.

        Removed rather than kept because reusing one lets an observer link
        the two connections, which is the opposite of the point.
        """
        with self._lock:
            held = self._tickets.get(host)
            if not held:
                return None
            now = time.time()
            while held:
                ticket = held.pop(0)
                if ticket.expired(now):
                    continue
                if suite_id is not None and ticket.suite_id != suite_id:
                    continue
                return ticket
            return None

    def clear(self) -> None:
        with self._lock:
            self._tickets.clear()
