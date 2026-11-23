"""A small, rate-limited, GET-only HTTP client.

Every request the scanner makes goes through this one class. Centralising it
gives us three guarantees in one place:

1. Rate limiting: there is always at least `delay` seconds between requests,
   no matter which module sends them.
2. Read-only: the class only exposes `get()`. There is deliberately no
   post/put/delete method, so Phase 1 code physically cannot submit forms or
   change data on the target.
3. Bounded downloads: bodies are streamed and truncated at `max_body_bytes`.
"""

from __future__ import annotations

import logging
import time

import requests

from scanner.config import ScanConfig

log = logging.getLogger(__name__)


class RateLimitedClient:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.delay = config.delay
        self.request_count = 0
        self._last_request_at = 0.0

        # A Session reuses TCP connections (faster, and kinder to the server)
        # and keeps cookies between requests like a browser would.
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": config.user_agent})
        self._session.verify = config.verify_tls

    def set_min_delay(self, seconds: float) -> None:
        """Raise the delay (e.g. to honour a robots.txt Crawl-delay). Never lowers it."""
        self.delay = max(self.delay, seconds)

    def _wait_for_slot(self) -> None:
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request_at = time.monotonic()

    def get(self, url: str, allow_redirects: bool = False) -> requests.Response | None:
        """Send a GET request. Returns None on network errors instead of raising.

        Redirects are NOT followed by default. The crawler handles redirects
        itself so it can check that the redirect target is still in scope
        before requesting it (a redirect to another domain must not be
        followed).
        """
        self._wait_for_slot()
        self.request_count += 1
        try:
            resp = self._session.get(
                url,
                timeout=self.config.timeout,
                allow_redirects=allow_redirects,
                stream=True,  # don't download the body until we decide how much to read
            )
            # Read at most max_body_bytes. decode_content=True undoes gzip.
            # Assigning to `_content` is how we hand the truncated body back
            # to requests so that resp.text / resp.content keep working.
            body = resp.raw.read(self.config.max_body_bytes, decode_content=True)
            resp._content = body or b""
            resp.close()
            log.debug("GET %s -> %s (%d bytes)", url, resp.status_code, len(resp._content))
            return resp
        except requests.RequestException as exc:
            log.warning("Request to %s failed: %s", url, exc)
            return None
