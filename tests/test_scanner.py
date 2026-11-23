"""End-to-end and unit tests. Run with:  python -m pytest -q"""

from __future__ import annotations

import io
import json

from scanner.checks.cookies import parse_set_cookie
from scanner.checks.headers import parse_csp
from scanner.cli import confirm_authorization, main
from scanner.config import ScanConfig
from scanner.core import run_scan
from scanner.crawler import normalize_url


def fast_config(url: str, **kw) -> ScanConfig:
    # delay=0 only because the target is our own in-process test server.
    return ScanConfig(start_url=url, delay=0, timeout=5, **kw)


# ----------------------------------------------------------------- safety gate
class FakeStdin(io.StringIO):
    def __init__(self, text: str, tty: bool):
        super().__init__(text)
        self._tty = tty

    def isatty(self):
        return self._tty


def test_refuses_without_permission_when_non_interactive(test_site):
    url, seen = test_site
    assert not confirm_authorization(url, False, stdin=FakeStdin("", tty=False), stderr=io.StringIO())


def test_cli_exits_2_and_sends_no_requests_without_permission(test_site, monkeypatch):
    url, seen = test_site
    monkeypatch.setattr("sys.stdin", FakeStdin("", tty=False))
    assert main([url]) == 2
    assert seen == []  # not a single request reached the target


def test_interactive_confirmation_requires_hostname():
    err = io.StringIO()
    assert confirm_authorization("http://localhost:3000", False, stdin=FakeStdin("localhost\n", True), stderr=err)
    assert not confirm_authorization("http://localhost:3000", False, stdin=FakeStdin("yes\n", True), stderr=err)


# --------------------------------------------------------------------- crawler
def test_crawler_scope_robots_and_forms(test_site):
    url, seen = test_site
    result = run_scan(fast_config(url, probe_sensitive_paths=False))
    crawled = {p.url.replace(url, "") for p in result.crawl.pages}

    assert {"/", "/about", "/about/team", "/login"} <= crawled
    assert "/private/secret" not in crawled          # robots.txt Disallow respected
    assert all("example.org" not in p.url for p in result.crawl.pages)  # stayed in scope
    assert all(method == "GET" for method, _ in seen)  # passive: GET only, forms never submitted

    login_form = next(f for f in result.crawl.forms if f.action.endswith("/session"))
    assert login_form.method == "POST"
    assert {f.name for f in login_form.fields} == {"email", "password", "csrf"}


def test_normalize_url():
    assert normalize_url("HTTP://Example.com:80/a#frag") == "http://example.com/a"
    assert normalize_url("https://example.com") == "https://example.com/"


# ---------------------------------------------------------------------- checks
def test_findings_end_to_end(test_site):
    url, _ = test_site
    result = run_scan(fast_config(url))
    rules = {f.rule_id for f in result.findings}

    assert "HEADER_CSP_MISSING" in rules
    assert "HEADER_XCTO_MISSING" in rules
    assert "HEADER_REFERRER_POLICY_MISSING" in rules
    assert "COOKIE_NO_HTTPONLY" in rules
    assert "DISCLOSURE_SERVER_VERSION" in rules
    assert "DISCLOSURE_TECH_HEADER" in rules
    assert "ROBOTS_DISCLOSES_PATHS" in rules

    exposed = [f for f in result.findings if f.rule_id == "EXPOSED_PATH"]
    # /.git/HEAD is real; the catch-all must NOT make /.env, /backup etc. look exposed.
    assert [f.url.replace(url, "") for f in exposed] == ["/.git/HEAD"]
    assert exposed[0].confidence == "confirmed"

    # Dedup: CSP missing on several pages = one finding with several URLs.
    csp = [f for f in result.findings if f.rule_id == "HEADER_CSP_MISSING"]
    assert len(csp) == 1 and len(csp[0].affected_urls) > 1

    # Only the session cookie lacks HttpOnly; and its value is never reported.
    httponly = [f for f in result.findings if f.rule_id == "COOKIE_NO_HTTPONLY"]
    assert len(httponly) == 1 and "sessionid" in httponly[0].title
    assert "s3cr3t" not in json.dumps([f.to_dict() for f in result.findings])


def test_json_report_shape(test_site, tmp_path):
    url, _ = test_site
    out = tmp_path / "report.json"
    assert main([url, "--i-have-permission", "--delay", "0", "-o", str(out)]) == 0
    report = json.loads(out.read_text())
    assert report["scanner"]["mode"] == "passive"
    for finding in report["findings"]:
        for key in ("id", "severity", "url", "description", "remediation"):
            assert finding[key]


def test_parsers():
    assert parse_csp("default-src 'self'; script-src 'self' 'unsafe-inline'")["script-src"] == ["'self'", "'unsafe-inline'"]
    name, attrs = parse_set_cookie("token=abc; Path=/; Secure; SameSite=None")
    assert name == "token" and "secure" in attrs and attrs["samesite"] == "None"
