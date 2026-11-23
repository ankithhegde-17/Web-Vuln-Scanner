"""Tests for the Phase 4 HTML dashboard.

The most important one is escaping: payloads and evidence come from the
target, so a hostile value must appear as text and never as markup.
"""

from __future__ import annotations

import json
import re

from scanner.report import main as report_main
from scanner.reporting.html_report import build_html, effective_severity, sort_findings


def finding(fid, sev, title="t", **extra):
    base = {"id": fid, "rule_id": "R", "check": "c", "severity": sev, "title": title,
            "url": "http://localhost:3000/", "description": "desc", "remediation": "fix it",
            "evidence": "", "payload": "", "confidence": "confirmed", "affected_urls": []}
    base.update(extra)
    return base


def report(findings, **extra):
    r = {"scanner": {"name": "webvuln-scanner", "version": "0.1.0", "mode": "active+passive"},
         "target": "http://localhost:3000", "started_at": "2026-11-23T17:00:11+00:00",
         "finished_at": "2026-11-23T17:00:18+00:00", "stats": {"pages_crawled": 1}, "findings": findings}
    r.update(extra)
    return r


def card_ids(page):
    return re.findall(r'<h3>([^<]*)</h3>', page)


# ---------------------------------------------------------------- escaping
def test_hostile_payload_and_evidence_are_escaped():
    evil = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    page = build_html(report([finding("X", "high", title=evil, payload=evil, evidence=evil, url=evil,
                                      triage={"adjusted_severity": "high", "explanation": evil,
                                              "example_fix": evil, "severity_reason": "`" + evil + "`"})],
                             target=evil, triage={"enriched": True, "summary": evil}))
    assert "<script>alert(1)" not in page
    assert "<img src=x" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert page.count("<script>") == 1  # only our own inline script


def test_page_is_self_contained():
    page = build_html(report([finding("A", "low")]))
    assert not re.search(r'<(link|img|iframe)\b', page)
    assert not re.search(r'\ssrc=', page)
    assert "@import" not in page and "url(" not in page


# ------------------------------------------------------------ severity/sort
def test_triage_severity_wins_and_falls_back():
    assert effective_severity(finding("A", "high", triage={"adjusted_severity": "critical"})) == "critical"
    assert effective_severity(finding("A", "high", triage={"adjusted_severity": "bogus"})) == "high"
    assert effective_severity(finding("A", "medium")) == "medium"


def test_sorted_critical_to_info_with_flagged_last():
    fs = [finding("I", "info", title="info"),
          finding("FP", "high", title="fp", triage={"adjusted_severity": "critical", "likely_false_positive": True}),
          finding("L", "low", title="low"),
          finding("C", "high", title="crit", triage={"adjusted_severity": "critical"}),
          finding("M", "medium", title="med")]
    assert [f["id"] for f in sort_findings(fs)] == ["C", "M", "L", "I", "FP"]
    page = build_html(report(fs))
    assert card_ids(page) == ["crit", "med", "low", "info", "fp"]
    assert 'class="card s-critical flagged"' in page


def test_original_severity_shown_when_triage_changed_it():
    page = build_html(report([finding("A", "high", triage={"adjusted_severity": "critical"})]))
    assert 'class="badge b-critical">critical<' in page
    assert '<s class="badge-orig"' in page and ">high</s>" in page


# ---------------------------------------------------------- graceful cases
def test_no_triage_shows_scanner_text():
    page = build_html(report([finding("A", "medium", description="scanner desc", remediation="scanner fix")]))
    assert "scanner desc" in page and "scanner fix" in page
    assert "<s class=\"badge-orig\"" not in page and "LLM triage" not in page


def test_no_findings_state():
    page = build_html(report([]))
    assert "No findings" in page and 'class="card' not in page


def test_counts_use_effective_severity():
    page = build_html(report([finding("A", "high", triage={"adjusted_severity": "critical"}),
                              finding("B", "low")]))
    assert re.search(r'data-sev="critical"[^>]*><span class="tile-n">1<', page)
    assert re.search(r'data-sev="high"[^>]*><span class="tile-n">0<', page)


def test_cli_writes_html_next_to_json(tmp_path):
    src = tmp_path / "scan.json"
    src.write_text(json.dumps(report([finding("A", "low")])))
    assert report_main([str(src)]) == 0
    assert (tmp_path / "scan.html").read_text().startswith("<!doctype html>")
    assert report_main([str(tmp_path / "missing.json")]) == 1


def test_scan_html_flag_end_to_end(test_site, tmp_path, monkeypatch):
    # A real (local test server) scan with --html writes the dashboard beside
    # the JSON, without needing triage or an API key.
    from scanner.cli import main as cli_main
    monkeypatch.setattr("sys.stdin", open("/dev/null"))
    base_url, _ = test_site
    out = tmp_path / "r.json"
    rc = cli_main([base_url, "--i-have-permission", "--delay", "0", "--max-pages", "5",
                   "--no-path-probes", "-o", str(out), "--html"])
    assert rc == 0
    page = (tmp_path / "r.html").read_text()
    assert "<!doctype html>" in page and 'class="tile' in page
