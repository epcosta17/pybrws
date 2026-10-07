"""Fetching many URLs at once.

A Session owns connections and is not safe to share between threads, so
each worker gets its own. What they do share is the state that should be
shared: the cookie jar and the ticket store, both of which take a lock.
Giving every worker its own jar would mean a site that sets a session
cookie hands out one per thread, which is both wrong and conspicuous.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .cookies import CookieJar
from .message import Response
from .profiles import firefox157
from .session import Session
from .tickets import TicketStore


@dataclass
class Result:
    """One finished attempt, successful or not."""

    url: str
    response: Response | None = None
    error: Exception | None = None
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return self.response is not None and self.response.ok

    @property
    def status(self) -> int | None:
        return self.response.status if self.response else None


@dataclass
class Retry:
    """When to try again, and how long to wait."""

    attempts: int = 1
    statuses: frozenset = field(default_factory=lambda: frozenset({429, 500, 502, 503, 504}))
    backoff: float = 1.0

    def should(self, result: Result) -> bool:
        if result.attempts >= self.attempts:
            return False
        if result.error is not None:
            return True
        return result.response is not None and result.response.status in self.statuses

    def wait(self, attempt: int) -> float:
        return self.backoff * (2 ** (attempt - 1))


class Fetcher:
    """Runs requests across several connections at once."""

    def __init__(self, *, concurrency: int = 8, profile=firefox157, proxy=None,
                 timeout: float = 20.0, verify: bool = True,
                 follow_redirects: int = 5, retry: Retry | None = None) -> None:
        self.concurrency = concurrency
        self.profile = profile
        self.proxy = proxy
        self.timeout = timeout
        self.verify = verify
        self.follow_redirects = follow_redirects
        self.retry = retry or Retry()
        self.cookies = CookieJar()
        self.tickets = TicketStore()
        self._local = threading.local()
        self._sessions: list[Session] = []
        self._sessions_lock = threading.Lock()

    # -- per-worker sessions ------------------------------------------------

    def _session(self) -> Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = Session(profile=self.profile, proxy=self.proxy,
                              timeout=self.timeout, verify=self.verify,
                              follow_redirects=self.follow_redirects)
            # Shared on purpose: a cookie earned by one worker belongs to
            # the whole run, and so does a ticket.
            session.cookies = self.cookies
            session.tickets = self.tickets
            self._local.session = session
            with self._sessions_lock:
                self._sessions.append(session)
        return session

    def close(self) -> None:
        with self._sessions_lock:
            sessions, self._sessions = self._sessions, []
        for session in sessions:
            session.close()

    def __enter__(self) -> "Fetcher":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- requests -----------------------------------------------------------

    def fetch(self, url: str, **kwargs) -> Result:
        """One URL, with retries. Errors are returned rather than raised.

        A batch of a thousand should not stop because one host refused a
        connection.
        """
        import time

        result = Result(url=url, attempts=0)
        while True:
            result.attempts += 1
            try:
                result.response = self._session().request(url, **kwargs)
                result.error = None
            except Exception as exc:
                result.response = None
                result.error = exc
            if not self.retry.should(result):
                return result
            time.sleep(self.retry.wait(result.attempts))

    def fetch_all(self, urls, **kwargs) -> list[Result]:
        """Fetch every URL, returning results in the order given."""
        urls = list(urls)
        if not urls:
            return []
        workers = max(1, min(self.concurrency, len(urls)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(lambda url: self.fetch(url, **kwargs), urls))

    def map(self, urls, **kwargs):
        """Yield results as they finish rather than in order."""
        from concurrent.futures import as_completed

        urls = list(urls)
        workers = max(1, min(self.concurrency, len(urls) or 1))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(self.fetch, url, **kwargs) for url in urls]
            for future in as_completed(futures):
                yield future.result()
