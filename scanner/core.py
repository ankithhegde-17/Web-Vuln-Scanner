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
    # How many injection points the active phase tested (0 when --active off).
    injection_points_tested: int = 0
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

    # ---- Active phase (only with --active, which the CLI gates behind
    # --i-have-permission). Passive-only scans never reach this block. --------
    injection_points_tested = 0
    errors: list[str] = []
    if config.active_checks:
        injection_points_tested = _run_active_phase(config, crawler, crawl, client, collector, errors)

    return ScanResult(
        config=config,
        crawl=crawl,
        findings=collector.all(),
        started_at=started,
        finished_at=_now(),
        request_count=client.request_count,
        injection_points_tested=injection_points_tested,
        errors=errors,
    )


def _run_active_phase(config, crawler, crawl, client, collector, errors) -> int:
    """Build injection points, then run every active check against each one."""
    # Imported here so a passive-only scan never even loads the active code.
    from scanner.active import active_checks
    from scanner.targets import build_injection_points

    points = build_injection_points(crawl.forms, config.seed_urls, crawler.start_url)
    if not points:
        msg = ("Active checks were enabled but there was nothing to test: no forms were found and no "
               "seeded URLs had query parameters. Use --urls to point at endpoints with parameters.")
        log.warning(msg)
        errors.append(msg)
        return 0

    log.info("Active phase: testing %d injection point(s)", len(points))
    checks = active_checks()
    for point in points:
        for check in checks:
            try:
                collector.extend(check.check_point(point, client))
            except Exception:  # noqa: BLE001 - one bad point/check shouldn't abort the scan
                log.exception("Active check %s failed on %s", check.name, point.source)
    return len(points)
