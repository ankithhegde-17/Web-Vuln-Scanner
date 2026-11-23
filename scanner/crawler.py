"""Same-domain breadth-first crawler.

How it works:

    start URL ──► queue ──► fetch (GET) ──► passive checks run on the response
                    ▲                     │
                    │                     ├─► extract <a href> links ─┐
                    │                     └─► extract <form>s         │
                    └──── in scope? allowed by robots.txt? not seen? ◄┘

Breadth-first search (a FIFO queue) visits pages closest to the start URL
first. That way, if we hit `max_pages`, we've covered the most important,
most linked-to pages rather than going deep down one branch.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup

from scanner.config import ScanConfig
from scanner.http_client import RateLimitedClient
from scanner.models import Form, FormField, Page

log = logging.getLogger(__name__)

# File types that are never HTML, so there is nothing to crawl inside them.
# Skipping them saves requests (and politeness budget).
SKIP_EXTENSIONS = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|webp|bmp|css|js|mjs|map|woff2?|ttf|eot|otf|"
    r"pdf|zip|gz|tar|rar|7z|mp3|mp4|webm|avi|mov|exe|dmg|iso)$",
    re.IGNORECASE,
)

# Link schemes that are not web pages.
NON_HTTP_SCHEMES = ("mailto:", "javascript:", "tel:", "data:", "ftp:")

# Called for every response the crawler receives, so passive checks can
# inspect it without the crawler having to know about checks.
ResponseCallback = Callable[[requests.Response], None]


def normalize_url(url: str) -> str:
    """Canonical form of a URL so we don't crawl the same page twice.

    - drops the #fragment (fragments never reach the server)
    - lowercases scheme and host (they are case-insensitive)
    - removes default ports (:80 for http, :443 for https)
    - uses "/" for an empty path
    """
    url, _fragment = urldefrag(url)
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, host, path, parts.query, ""))


def _origin_key(url: str) -> tuple[str, int]:
    """(hostname, effective port) used for the scope check."""
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return (parts.hostname or "").lower(), port


@dataclass
class CrawlResult:
    pages: list[Page] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    # Paths that robots.txt told us not to visit. Reported as an INFO
    # finding because robots.txt often reveals "hidden" admin areas.
    robots_disallowed: list[str] = field(default_factory=list)
    robots_url: str = ""


class Crawler:
    def __init__(
        self,
        config: ScanConfig,
        client: RateLimitedClient,
        on_response: ResponseCallback | None = None,
    ) -> None:
        self.config = config
        self.client = client
        self.on_response = on_response or (lambda resp: None)
        self.start_url = normalize_url(config.start_url)
        self.scope = _origin_key(self.start_url)
        self.robots: RobotFileParser | None = None
        self.result = CrawlResult()

    # ------------------------------------------------------------------ scope
    def in_scope(self, url: str) -> bool:
        """True if `url` is on the same host and port as the start URL.

        Subdomains count as out of scope: being allowed to test
        app.example.com does NOT mean you're allowed to test
        mail.example.com. Both http and https on the same host are allowed,
        because sites commonly redirect one to the other.
        """
        if urlsplit(url).scheme not in ("http", "https"):
            return False
        return _origin_key(url) == self.scope

    # ----------------------------------------------------------------- robots
    def load_robots(self) -> None:
        """Fetch and parse /robots.txt once, before crawling."""
        parts = urlsplit(self.start_url)
        robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
        self.result.robots_url = robots_url
        parser = RobotFileParser()
        resp = self.client.get(robots_url)
        self.on_response_safe(resp)

        if resp is not None and resp.status_code == 200 and "html" not in resp.headers.get("Content-Type", ""):
            lines = resp.text.splitlines()
            parser.parse(lines)
            # Record Disallow lines for the "robots.txt reveals paths" finding.
            for line in lines:
                key, _, value = line.partition(":")
                if key.strip().lower() == "disallow" and value.strip():
                    self.result.robots_disallowed.append(value.strip())
            crawl_delay = parser.crawl_delay(self.config.user_agent)
            if crawl_delay:
                log.info("robots.txt asks for Crawl-delay %s s; honouring it", crawl_delay)
                self.client.set_min_delay(float(crawl_delay))
        else:
            # No robots.txt (or the SPA returned its HTML index page for it):
            # the convention is that everything is allowed.
            parser.parse([])
        self.robots = parser

    def allowed_by_robots(self, url: str) -> bool:
        if not self.config.respect_robots or self.robots is None:
            return True
        return self.robots.can_fetch(self.config.user_agent, url)

    # -------------------------------------------------------------- extraction
    def extract_links(self, base_url: str, soup: BeautifulSoup) -> list[str]:
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.lower().startswith(NON_HTTP_SCHEMES):
                continue
            links.append(normalize_url(urljoin(base_url, href)))
        return links

    def extract_forms(self, page_url: str, soup: BeautifulSoup) -> list[Form]:
        """Record every <form> and its input fields.

        We only *record* forms in Phase 1. We never submit them: submitting a
        form can create accounts, send emails or change data. Phase 2 will use
        this inventory to decide where active tests are allowed to run.
        """
        forms = []
        for form_tag in soup.find_all("form"):
            # A missing action means "submit to the current page".
            action = urljoin(page_url, form_tag.get("action") or page_url)
            method = (form_tag.get("method") or "GET").upper()
            fields = []
            for inp in form_tag.find_all(["input", "textarea", "select", "button"]):
                name = inp.get("name")
                if not name:
                    continue  # unnamed fields are never sent to the server
                if inp.name == "input":
                    ftype = (inp.get("type") or "text").lower()
                else:
                    ftype = inp.name  # "textarea", "select", "button"
                fields.append(FormField(name=name, field_type=ftype, value=inp.get("value", "")))
            forms.append(Form(page_url=page_url, action=action, method=method, fields=fields))
        return forms

    # ------------------------------------------------------------------- crawl
    def on_response_safe(self, resp: requests.Response | None) -> None:
        """Run the callback, but never let a buggy check crash the crawl."""
        if resp is None:
            return
        try:
            self.on_response(resp)
        except Exception:  # noqa: BLE001 - deliberately broad, we log and continue
            log.exception("A passive check failed on %s", resp.url)

    def crawl(self) -> CrawlResult:
        self.load_robots()

        queue: deque[tuple[str, int]] = deque([(self.start_url, 0)])
        seen: set[str] = {self.start_url}

        while queue and len(self.result.pages) < self.config.max_pages:
            url, depth = queue.popleft()

            if not self.allowed_by_robots(url):
                log.info("Skipping %s (disallowed by robots.txt)", url)
                continue

            resp = self.client.get(url)
            if resp is None:
                continue
            self.on_response_safe(resp)

            content_type = resp.headers.get("Content-Type", "")
            self.result.pages.append(Page(url=url, status_code=resp.status_code, depth=depth, content_type=content_type))
            log.info("[%d/%d] %s %s", len(self.result.pages), self.config.max_pages, resp.status_code, url)

            # Follow redirects manually, and only if they stay in scope.
            if resp.is_redirect and "Location" in resp.headers:
                target = normalize_url(urljoin(url, resp.headers["Location"]))
                if self.in_scope(target) and target not in seen:
                    seen.add(target)
                    queue.append((target, depth))  # a redirect isn't a "deeper" page
                elif not self.in_scope(target):
                    log.info("Not following off-scope redirect %s -> %s", url, target)
                continue

            if "html" not in content_type.lower():
                continue  # JSON, images, etc. have no links/forms to extract

            soup = BeautifulSoup(resp.text, "html.parser")
            self.result.forms.extend(self.extract_forms(url, soup))

            if depth >= self.config.max_depth:
                continue
            for link in self.extract_links(url, soup):
                if link in seen or not self.in_scope(link):
                    continue
                if SKIP_EXTENSIONS.search(urlsplit(link).path):
                    continue
                seen.add(link)
                queue.append((link, depth + 1))

        return self.result
