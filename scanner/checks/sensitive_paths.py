"""Exposed sensitive paths, plus what robots.txt gives away.

Developers sometimes deploy more than they meant to: the .git folder (which
contains the full source code history), a .env file (database passwords, API
keys), or a backup.zip of the whole site. We check for well-known locations
with plain GET requests. Nothing is modified, and we read at most 64 KB of
any response.

The tricky part is FALSE POSITIVES. Single-page apps (Juice Shop included)
answer *every* unknown path with "200 OK" and their index.html, so
"status 200" alone proves nothing. We use two techniques:

1. Content signatures: a real /.git/HEAD starts with "ref: refs/", a real
   .env has KEY=value lines, a real zip starts with the bytes "PK\\x03\\x04".
   A signature match is reported as "confirmed".
2. Soft-404 baseline: before probing we request a random path that cannot
   exist and remember what the "not found" response looks like. A probe
   response that looks the same is ignored. A 200 that differs from the
   baseline but has no signature is reported as "tentative".
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from urllib.parse import urljoin

import requests

from scanner.checks.base import SiteCheck
from scanner.http_client import RateLimitedClient
from scanner.models import Finding, Severity

PROBE_READ_LIMIT = 64 * 1024

DIRECTORY_LISTING = rb"(?i)<title>\s*(index of|listing directory|directory listing)"


@dataclass(frozen=True)
class Probe:
    path: str
    severity: Severity
    title: str
    description: str
    remediation: str
    # Regex (bytes) that the body must match for a "confirmed" finding.
    # None = no reliable signature; rely on the soft-404 comparison.
    signature: bytes | None = None


PROBES: list[Probe] = [
    Probe("/.git/HEAD", Severity.HIGH, "Git repository exposed",
          "The .git directory is web-accessible. Tools like git-dumper can rebuild the full source code and "
          "commit history, which often contains hard-coded secrets.",
          "Block access to /.git (e.g. nginx: location ~ /\\.git { deny all; }) and don't deploy it.",
          rb"^ref: refs/"),
    Probe("/.git/config", Severity.HIGH, "Git config exposed",
          "The repository config is readable; it reveals remote URLs and confirms the .git folder is exposed.",
          "Block access to /.git and remove it from the web root.", rb"\[core\]"),
    Probe("/.env", Severity.HIGH, "Environment file exposed",
          ".env files typically hold database passwords, API keys and signing secrets.",
          "Remove .env from the web root, block dotfiles at the web server, and rotate any exposed secrets.",
          rb"(?m)^[A-Z][A-Z0-9_]*\s*=\s*\S"),
    Probe("/.svn/entries", Severity.HIGH, "Subversion metadata exposed",
          "SVN metadata can be used to download the source code.",
          "Block access to /.svn and remove it from the web root.", rb"^\d+\s*$|dir\n"),
    Probe("/.DS_Store", Severity.LOW, "macOS .DS_Store file exposed",
          ".DS_Store files list the names of files in a directory, revealing hidden files and folders.",
          "Delete .DS_Store files from the server and block them.", rb"Bud1"),
    Probe("/backup.zip", Severity.HIGH, "Backup archive exposed",
          "A downloadable archive likely contains source code, configuration and possibly database dumps.",
          "Remove backups from the web root; store them somewhere not served over HTTP.", rb"^PK\x03\x04"),
    Probe("/backup.sql", Severity.HIGH, "Database dump exposed",
          "A SQL dump may contain every user record, including password hashes.",
          "Remove the dump from the web root and treat its contents as compromised.",
          rb"(?i)(create table|insert into)"),
    Probe("/dump.sql", Severity.HIGH, "Database dump exposed",
          "A SQL dump may contain every user record, including password hashes.",
          "Remove the dump from the web root and treat its contents as compromised.",
          rb"(?i)(create table|insert into)"),
    Probe("/backup", Severity.MEDIUM, "Backup location accessible",
          "A path named 'backup' returned content different from the site's normal not-found page.",
          "Check what is served here and remove anything that should not be public."),
    Probe("/backup/", Severity.MEDIUM, "Directory listing on backup folder",
          "The server lists the contents of the backup directory.",
          "Disable directory listing and remove backups from the web root.", DIRECTORY_LISTING),
    Probe("/ftp/", Severity.MEDIUM, "Directory listing on /ftp",
          "The server lists files in /ftp, letting anyone browse and download them.",
          "Disable directory listing and restrict access to the files.", DIRECTORY_LISTING),
    Probe("/uploads/", Severity.LOW, "Directory listing on /uploads",
          "User uploads can be enumerated, which may expose other users' files.",
          "Disable directory listing.", DIRECTORY_LISTING),
    Probe("/config.php.bak", Severity.HIGH, "Configuration backup exposed",
          "Backup copies of PHP files are served as plain text, revealing source and credentials.",
          "Delete editor/backup copies from the server.", rb"<\?php"),
    Probe("/phpinfo.php", Severity.MEDIUM, "phpinfo() page exposed",
          "phpinfo() reveals PHP version, modules, file paths and environment variables.",
          "Delete phpinfo pages from production.", rb"(?i)phpinfo\(\)|PHP Version"),
    Probe("/server-status", Severity.MEDIUM, "Apache server-status exposed",
          "mod_status shows live requests, client IPs and internal URLs.",
          "Restrict /server-status to localhost or disable mod_status.", rb"(?i)Apache Server Status"),
]


@dataclass
class Baseline:
    status_code: int
    length: int
    digest: str


def _fingerprint(resp: requests.Response) -> Baseline:
    body = resp.content[:PROBE_READ_LIMIT]
    return Baseline(resp.status_code, len(body), hashlib.sha1(body).hexdigest())


def looks_like_baseline(resp: requests.Response, baseline: Baseline | None) -> bool:
    """True if this response is probably just the site's generic not-found/index page."""
    if baseline is None:
        return False
    fp = _fingerprint(resp)
    if fp.status_code != baseline.status_code:
        return False
    if fp.digest == baseline.digest:
        return True
    # Pages often embed the requested path or a timestamp, so allow a
    # small difference in size rather than requiring identical bodies.
    biggest = max(fp.length, baseline.length, 1)
    return abs(fp.length - baseline.length) / biggest < 0.10


class SensitivePathsCheck(SiteCheck):
    name = "sensitive_paths"

    def run(self, base_url: str, client: RateLimitedClient, context: dict) -> list[Finding]:
        findings: list[Finding] = []
        allowed = context.get("allowed_by_robots", lambda url: True)

        # 1. Learn what "not found" looks like on this site.
        random_path = f"/{secrets.token_hex(12)}"
        baseline_resp = client.get(urljoin(base_url, random_path))
        baseline = _fingerprint(baseline_resp) if baseline_resp is not None else None

        # 2. Probe each well-known path.
        for probe in PROBES:
            url = urljoin(base_url, probe.path)
            if not allowed(url):
                # robots.txt asked us not to go there. RobotsDisclosureCheck
                # still reports that the path is listed.
                continue
            resp = client.get(url)
            if resp is None or resp.status_code != 200:
                continue  # 404/403/redirect-to-login: not exposed
            body = resp.content[:PROBE_READ_LIMIT]

            if probe.signature is not None:
                if re.search(probe.signature, body):
                    confidence = "confirmed"
                else:
                    continue  # status 200 but content doesn't match = SPA fallback page
            else:
                if looks_like_baseline(resp, baseline):
                    continue
                confidence = "tentative"

            findings.append(Finding(
                rule_id="EXPOSED_PATH", check=self.name, severity=probe.severity,
                title=f"{probe.title} ({probe.path})", url=url,
                description=probe.description, remediation=probe.remediation,
                evidence=f"GET {probe.path} -> {resp.status_code}, {len(body)} bytes"
                         + (", content signature matched" if confidence == "confirmed" else ""),
                confidence=confidence, dedup_key=probe.path,
            ))
        return findings


class RobotsDisclosureCheck(SiteCheck):
    """robots.txt is public. Its Disallow lines are a list of places the site
    owner would rather people didn't look, which is useful reconnaissance."""

    name = "robots_disclosure"

    def run(self, base_url: str, client: RateLimitedClient, context: dict) -> list[Finding]:
        disallowed = context.get("robots_disallowed", [])
        if not disallowed:
            return []
        robots_url = context.get("robots_url", urljoin(base_url, "/robots.txt"))
        return [Finding(
            rule_id="ROBOTS_DISCLOSES_PATHS", check=self.name, severity=Severity.INFO,
            title="robots.txt lists disallowed paths", url=robots_url,
            description="robots.txt only asks well-behaved crawlers to stay away; it does not protect anything. "
                        "These paths are worth reviewing manually to make sure they require authentication.",
            remediation="Never rely on robots.txt to hide sensitive content; protect it with access control.",
            evidence="Disallow: " + ", ".join(disallowed[:20]),
            confidence="confirmed",
        )]
