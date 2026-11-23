"""Tests for the Phase 2 active checks and the --active safety gate.

All tests run against the in-process test server from conftest.py, never a
real site. delay=0 is only safe because that server is local to the test.
"""

from __future__ import annotations

import io
import json

from scanner.active.base import InjectionPoint
from scanner.active.redirect import OpenRedirectCheck
from scanner.active.sqli import SQLInjectionCheck
from scanner.active.xss import ReflectedXSSCheck
from scanner.cli import main
from scanner.config import ScanConfig
from scanner.core import run_scan
from scanner.http_client import RateLimitedClient
from scanner.targets import build_injection_points, parse_seed_urls, points_from_seed_url
from tests.test_scanner import FakeStdin


def client_for(url: str) -> RateLimitedClient:
    return RateLimitedClient(ScanConfig(start_url=url, delay=0, timeout=5))


def get_point(base: str, path: str, param: str, value: str = "x") -> InjectionPoint:
    return InjectionPoint(method="GET", url=f"{base}{path}", params={param: value}, param=param,
                          source=f"test {param}")


# ------------------------------------------------------------- safety gating
def test_active_requires_permission_flag(test_site):
    url, seen = test_site
    # --active without --i-have-permission must refuse and send nothing.
    assert main([url, "--active", "--urls", f"{url}/search?q=x", "--delay", "0"]) == 2
    assert seen == []


def test_active_off_by_default_sends_no_payloads(test_site):
    url, _ = test_site
    result = run_scan(ScanConfig(start_url=url, delay=0, timeout=5))  # active_checks defaults to False
    assert result.injection_points_tested == 0
    assert not [f for f in result.findings if f.rule_id.startswith("ACTIVE_")]


# -------------------------------------------------------------- the injector
def test_seed_parsing_and_scope(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("# comment\nhttp://host/a?x=1\n\n http://host/b?y=2 \n")
    assert parse_seed_urls(str(f)) == ["http://host/a?x=1", "http://host/b?y=2"]
    assert parse_seed_urls("http://h/a?x=1,http://h/b?y=2") == ["http://h/a?x=1", "http://h/b?y=2"]

    # Out-of-scope seeds are dropped.
    pts = build_injection_points([], ["http://evil.com/x?a=1", "http://host/ok?b=2"], "http://host/")
    assert [p.param for p in pts] == ["b"]


def test_points_from_seed_url_one_per_param():
    pts = points_from_seed_url("http://h/s?q=a&page=2")
    assert {p.param for p in pts} == {"q", "page"}
    assert all(p.params == {"q": "a", "page": "2"} for p in pts)  # others kept at baseline


# ----------------------------------------------------------------- XSS check
def test_xss_detects_unencoded_reflection(test_site):
    url, _ = test_site
    findings = ReflectedXSSCheck().check_point(get_point(url, "/search", "q"), client_for(url))
    assert len(findings) == 1
    assert findings[0].rule_id == "ACTIVE_REFLECTED_XSS"
    assert findings[0].severity.value == "high"
    assert "<>" in findings[0].payload  # payload carried the breakout characters


def test_xss_ignores_encoded_reflection(test_site):
    url, _ = test_site
    # /safe-search HTML-escapes the input, so this must NOT be flagged.
    assert ReflectedXSSCheck().check_point(get_point(url, "/safe-search", "q"), client_for(url)) == []


def test_xss_via_post_form(test_site):
    url, _ = test_site
    point = InjectionPoint(method="POST", url=f"{url}/comment", params={"comment": "hi"}, param="comment",
                           source="post form")
    findings = ReflectedXSSCheck().check_point(point, client_for(url))
    assert len(findings) == 1 and findings[0].rule_id == "ACTIVE_REFLECTED_XSS"


# ---------------------------------------------------------------- SQLi check
def test_sqli_error_based(test_site):
    url, _ = test_site
    findings = SQLInjectionCheck().check_point(get_point(url, "/product", "id", "1"), client_for(url))
    assert len(findings) == 1
    assert findings[0].rule_id == "ACTIVE_SQLI_ERROR"
    assert "SQLite" in findings[0].evidence
    assert findings[0].confidence == "confirmed"


def test_sqli_clean_param_not_flagged(test_site):
    url, _ = test_site
    # /search doesn't emit DB errors, and its content doesn't swing on boolean
    # payloads, so SQLi must stay silent (no false positive).
    assert SQLInjectionCheck().check_point(get_point(url, "/search", "q"), client_for(url)) == []


# ------------------------------------------------------------ redirect check
def test_open_redirect_detected(test_site):
    url, _ = test_site
    findings = OpenRedirectCheck().check_point(get_point(url, "/go", "to", "/home"), client_for(url))
    assert len(findings) == 1
    assert findings[0].rule_id == "ACTIVE_OPEN_REDIRECT"
    assert "vuln-scanner-probe.invalid" in findings[0].payload


def test_open_redirect_skips_non_redirect_param(test_site):
    url, _ = test_site
    # 'q' is neither a redirect-style name nor a URL value, so it's skipped.
    assert OpenRedirectCheck().check_point(get_point(url, "/search", "q"), client_for(url)) == []


# -------------------------------------------------------------- end-to-end
def test_active_scan_end_to_end_and_report(test_site, tmp_path):
    url, _ = test_site
    seeds = ",".join([f"{url}/search?q=a", f"{url}/product?id=1", f"{url}/go?to=/x"])
    out = tmp_path / "r.json"
    code = main([url, "--i-have-permission", "--active", "--urls", seeds, "--delay", "0",
                 "--no-path-probes", "-o", str(out)])
    assert code == 0
    report = json.loads(out.read_text())
    assert report["scanner"]["mode"] == "active+passive"
    rules = {f["rule_id"] for f in report["findings"]}
    assert {"ACTIVE_REFLECTED_XSS", "ACTIVE_SQLI_ERROR", "ACTIVE_OPEN_REDIRECT"} <= rules
    # Every active finding records its payload.
    for f in report["findings"]:
        if f["rule_id"].startswith("ACTIVE_"):
            assert f["payload"]
