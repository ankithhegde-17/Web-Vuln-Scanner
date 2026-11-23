"""Structured JSON output.

The JSON file is the scanner's real product: the terminal summary is for
humans, the JSON is for machines (a CI job, a dashboard, or the Phase 3 LLM
triage layer). We include a `schema_version` so later code can detect old
report formats.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from scanner import __version__
from scanner.core import ScanResult
from scanner.models import Severity

SCHEMA_VERSION = 1


def build_report(result: ScanResult) -> dict:
    counts = Counter(f.severity.value for f in result.findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "scanner": {"name": "webvuln-scanner", "version": __version__, "mode": "passive"},
        "target": result.config.start_url,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "settings": {
            "max_pages": result.config.max_pages,
            "max_depth": result.config.max_depth,
            "delay_seconds": result.config.delay,
            "respect_robots": result.config.respect_robots,
            "probe_sensitive_paths": result.config.probe_sensitive_paths,
        },
        "stats": {
            "pages_crawled": len(result.crawl.pages),
            "forms_found": len(result.crawl.forms),
            "requests_made": result.request_count,
            "findings_by_severity": {s.value: counts.get(s.value, 0) for s in reversed(Severity)},
        },
        "findings": [f.to_dict() for f in result.findings],
        "pages": [p.to_dict() for p in result.crawl.pages],
        "forms": [f.to_dict() for f in result.crawl.forms],
    }


def write_json_report(result: ScanResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_report(result), indent=2), encoding="utf-8")
    return path
