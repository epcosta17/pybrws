"""Tests for pybrws.pool."""

import threading
import unittest

from pybrws.cookies import Cookie
from pybrws.message import Response
from pybrws.pool import Fetcher, Result, Retry


class FakeSession:
    """Answers from a script, recording the order it was asked."""

    def __init__(self, answers, seen, lock):
        self.answers = answers
        self.seen = seen
        self.lock = lock
        self.cookies = None
        self.tickets = None

    def request(self, url, **kwargs):
        with self.lock:
            self.seen.append(url)
        answer = self.answers.get(url, Response(200, [], b"ok"))
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, list):
            return answer.pop(0) if len(answer) > 1 else answer[0]
        return answer

    def close(self):
        pass


class ScriptedFetcher(Fetcher):
    def __init__(self, answers=None, **kwargs):
        super().__init__(**kwargs)
        self.answers = answers or {}
        self.seen = []
        self._seen_lock = threading.Lock()

    def _session(self):
        session = getattr(self._local, "session", None)
        if session is None:
            session = FakeSession(self.answers, self.seen, self._seen_lock)
            session.cookies = self.cookies
            session.tickets = self.tickets
            self._local.session = session
        return session


class TestResult(unittest.TestCase):
    def test_ok_follows_the_response(self):
        self.assertTrue(Result("u", Response(200, [])).ok)
        self.assertFalse(Result("u", Response(403, [])).ok)
        self.assertFalse(Result("u", error=OSError("nope")).ok)

    def test_status_is_none_without_a_response(self):
        self.assertIsNone(Result("u", error=OSError("nope")).status)


class TestRetryPolicy(unittest.TestCase):
    def test_a_success_is_not_retried(self):
        policy = Retry(attempts=3)
        self.assertFalse(policy.should(Result("u", Response(200, []))))

    def test_a_rate_limit_is(self):
        policy = Retry(attempts=3)
        self.assertTrue(policy.should(Result("u", Response(429, []))))

    def test_a_block_is_not(self):
        # 403 is an answer, not a failure. Repeating it only burns the
        # address faster.
        policy = Retry(attempts=3)
        self.assertFalse(policy.should(Result("u", Response(403, []))))

    def test_an_exception_is(self):
        policy = Retry(attempts=3)
        self.assertTrue(policy.should(Result("u", error=OSError("reset"))))

    def test_the_budget_is_respected(self):
        policy = Retry(attempts=2)
        self.assertFalse(policy.should(Result("u", Response(429, []), attempts=2)))

    def test_the_wait_doubles(self):
        policy = Retry(backoff=0.5)
        self.assertEqual([policy.wait(n) for n in (1, 2, 3)], [0.5, 1.0, 2.0])


class TestFetching(unittest.TestCase):
    def test_order_is_preserved_whatever_finishes_first(self):
        urls = ["https://a.test/%d" % i for i in range(10)]
        with ScriptedFetcher(concurrency=5) as fetcher:
            results = fetcher.fetch_all(urls)
        self.assertEqual([r.url for r in results], urls)

    def test_an_error_is_returned_rather_than_raised(self):
        # A batch of a thousand should not stop because one host refused.
        answers = {"https://bad.test/": OSError("connection refused")}
        with ScriptedFetcher(answers, retry=Retry(attempts=1)) as fetcher:
            results = fetcher.fetch_all(["https://ok.test/", "https://bad.test/"])
        self.assertTrue(results[0].ok)
        self.assertFalse(results[1].ok)
        self.assertIsInstance(results[1].error, OSError)

    def test_a_retried_request_reports_its_attempts(self):
        answers = {"https://flaky.test/": [Response(503, []), Response(200, [])]}
        with ScriptedFetcher(answers, retry=Retry(attempts=3, backoff=0.0)) as f:
            result = f.fetch("https://flaky.test/")
        self.assertEqual(result.status, 200)
        self.assertEqual(result.attempts, 2)

    def test_retries_stop_at_the_budget(self):
        answers = {"https://down.test/": Response(503, [])}
        with ScriptedFetcher(answers, retry=Retry(attempts=3, backoff=0.0)) as f:
            result = f.fetch("https://down.test/")
        self.assertEqual(result.attempts, 3)
        self.assertEqual(result.status, 503)

    def test_map_yields_everything(self):
        urls = ["https://a.test/%d" % i for i in range(6)]
        with ScriptedFetcher(concurrency=3) as fetcher:
            seen = {r.url for r in fetcher.map(urls)}
        self.assertEqual(seen, set(urls))

    def test_an_empty_batch_is_fine(self):
        with ScriptedFetcher() as fetcher:
            self.assertEqual(fetcher.fetch_all([]), [])


class TestSharedState(unittest.TestCase):
    def test_every_worker_sees_the_same_jar(self):
        # One jar per worker would hand a site a different session cookie
        # per thread, which is both wrong and conspicuous.
        jars = set()
        with ScriptedFetcher(concurrency=4) as fetcher:
            fetcher.cookies.set(Cookie("sid", "1", "a.test", "/"))

            def grab(url):
                return id(fetcher._session().cookies)

            for url in ["https://a.test/%d" % i for i in range(8)]:
                fetcher.fetch(url)
            jars.add(id(fetcher.cookies))
        self.assertEqual(len(jars), 1)

    def test_the_jar_survives_concurrent_writers(self):
        with ScriptedFetcher(concurrency=8) as fetcher:
            def write(index):
                for i in range(50):
                    fetcher.cookies.set(
                        Cookie("c%d" % index, str(i), "a.test", "/")
                    )

            threads = [threading.Thread(target=write, args=(n,)) for n in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(fetcher.cookies), 8)

    def test_workers_get_their_own_session(self):
        # Sessions own connections, which are not shareable.
        seen = set()
        with ScriptedFetcher(concurrency=4) as fetcher:
            def grab(_):
                seen.add(id(fetcher._session()))
                return None

            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(grab, range(16)))
        self.assertGreater(len(seen), 1)


if __name__ == "__main__":
    unittest.main()
