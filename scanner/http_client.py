"""A small, rate-limited HTTP client.

Every request the scanner makes goes through this one class. Centralising it
gives us three guarantees in one place:

1. Rate limiting: there is always at least `delay` seconds between requests,
   no matter which module sends them.
2. Only safe methods: the client refuses to send anything other than GET and
   POST. There is deliberately no PUT/DELETE/PATCH, so no part of the scanner
   can change or remove data on the target, even by mistake. Passive checks
   use GET only; active checks may POST a form, but only with non-destructive
   detection payloads (see scanner/active/).
3. Bounded downloads: bodies are streamed and truncated at `max_body_bytes`.
"""

from __future__ import annotations

import logging
import time

import requests

from scanner.config import ScanConfig

log = logging.getLogger(__name__)

# The only HTTP methods this scanner is ever allowed to send.
ALLOWED_METHODS = ("GET", "POST")


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

    def request(
        self,
        method: str,
        url: str,
        params: dict | None = None,
        data: dict | None = None,
        allow_redirects: bool = False,
    ) -> requests.Response | None:
        """Send one request after waiting for a rate-limit slot.

        Returns None on network errors instead of raising, so a single dead
        link never crashes a whole scan. Redirects are NOT followed by
        default: callers decide, because following a redirect blindly could
        take us to another host (out of scope) or hide an open-redirect bug
        we are trying to detect.
        """
        method = method.upper()
        if method not in ALLOWED_METHODS:
            # A hard guard: this should be impossible to reach from our own
            # code, but it makes the safety property explicit and testable.
            raise ValueError(f"Refusing to send disallowed HTTP method: {method}")

        self._wait_for_slot()
        self.request_count += 1
        try:
            resp = self._session.request(
                method,
                url,
                params=params,
                data=data,
                timeout=self.config.timeout,
                allow_redirects=allow_redirects,
                stream=True,  # don't download the body until we decide how much to read
            )
            # Read at most max_body_bytes. decode_content=True undoes gzip.
            body = resp.raw.read(self.config.max_body_bytes, decode_content=True)
            resp._content = body or b""
            resp.close()
            log.debug("%s %s -> %s (%d bytes)", method, url, resp.status_code, len(resp._content))
            return resp
        except requests.RequestException as exc:
            log.warning("%s request to %s failed: %s", method, url, exc)
            return None

    def get(self, url: str, params: dict | None = None, allow_redirects: bool = False) -> requests.Response | None:
        """Convenience wrapper for the common GET case."""
        return self.request("GET", url, params=params, allow_redirects=allow_redirects)
