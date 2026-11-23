"""The interface every check follows.

There are two kinds of passive check:

* ResponseCheck: looks at a response the crawler already received
  (headers, cookies). It sends no requests of its own, so it is 100%
  passive.
* SiteCheck: runs once per target and may send its own GET requests
  (e.g. probing for /.git/HEAD). Still non-intrusive: GET only, no payloads.

Keeping a common interface means the scanner core can run "all checks"
without knowing what each one does, and Phase 2 can add new checks by
dropping in a new module.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from urllib.parse import urlsplit

import requests

from scanner.http_client import RateLimitedClient
from scanner.models import Finding


class ResponseCheck(ABC):
    name: str = "unnamed"

    @abstractmethod
    def check_response(self, response: requests.Response) -> list[Finding]:
        """Return findings for a single HTTP response."""


class SiteCheck(ABC):
    name: str = "unnamed"

    @abstractmethod
    def run(self, base_url: str, client: RateLimitedClient, context: dict) -> list[Finding]:
        """Return findings for the whole site.

        `context` carries information gathered during the crawl, such as the
        robots.txt Disallow list, so a SiteCheck can make smarter decisions.
        """


def is_html(response: requests.Response) -> bool:
    return "html" in response.headers.get("Content-Type", "").lower()


def is_https(url: str) -> bool:
    return urlsplit(url).scheme == "https"


def is_localhost(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")
