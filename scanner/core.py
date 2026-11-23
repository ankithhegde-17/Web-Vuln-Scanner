"""Glue that wires the crawler, the checks and the findings together.

Kept separate from cli.py so the scan can be run from code (tests, or a
future web UI / LLM pipeline) without going through argparse.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

from scanner.checks import response_checks, site_checks
from scanner.config import ScanConfig
from scanner.crawler import CrawlResult, Crawler
from scanner.http_client import RateLimitedClient
from scanner.models import Finding, FindingCollector

log = logging.getLogger(__name__)


@dataclass
class ScanResult:
    config: ScanConfig
    crawl: CrawlResult
    findings: list[Finding]
    started_at: str
    finished_at: str
    request_count: int
    errors: list[str] = field(default_factory=list)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_scan(config: ScanConfig) -> ScanResult:
    started = _now()
    client = RateLimitedClient(config)
    collector = FindingCollector()
    per_response = response_checks()

    def on_response(resp: requests.Response) -> None:
        for check in per_response:
            collector.extend(check.check_response(resp))

    crawler = Crawler(config, client, on_response=on_response)
    crawl = crawler.crawl()

    # Information the site-level checks may use.
    context = {
        "robots_disallowed": crawl.robots_disallowed,
        "robots_url": crawl.robots_url,
        "allowed_by_robots": crawler.allowed_by_robots,
    }
    for check in site_checks(config.probe_sensitive_paths):
        log.info("Running site check: %s", check.name)
        try:
            collector.extend(check.run(crawler.start_url, client, context))
        except Exception:  # noqa: BLE001 - one broken check shouldn't lose the whole scan
            log.exception("Site check %s failed", check.name)

    return ScanResult(
        config=config,
        crawl=crawl,
        findings=collector.all(),
        started_at=started,
        finished_at=_now(),
        request_count=client.request_count,
    )
