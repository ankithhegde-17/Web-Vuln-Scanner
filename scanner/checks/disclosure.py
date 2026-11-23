"""Server / technology disclosure through response headers.

Headers like "Server: Apache/2.4.29 (Ubuntu)" or "X-Powered-By: PHP/7.2.1"
tell an attacker exactly which software and version to look up in a CVE
database. Hiding them doesn't fix vulnerabilities (that's "security through
obscurity"), but it removes free reconnaissance, which is why scanners
report it at LOW / INFO severity.
"""

from __future__ import annotations

import re

import requests

from scanner.checks.base import ResponseCheck
from scanner.models import Finding, Severity

# Headers that reveal technology. Server is handled separately because a
# bare product name ("nginx") is much less useful to an attacker than a version.
TECH_HEADERS = ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache", "X-Runtime")

VERSION_PATTERN = re.compile(r"\d+\.\d+")


class TechDisclosureCheck(ResponseCheck):
    name = "tech_disclosure"

    def check_response(self, response: requests.Response) -> list[Finding]:
        findings: list[Finding] = []
        url = response.url
        h = response.headers

        server = h.get("Server")
        if server:
            has_version = bool(VERSION_PATTERN.search(server))
            findings.append(Finding(
                rule_id="DISCLOSURE_SERVER_VERSION" if has_version else "DISCLOSURE_SERVER",
                check=self.name,
                severity=Severity.LOW if has_version else Severity.INFO,
                title="Server header reveals software version" if has_version else "Server header reveals software",
                url=url,
                description=f"The Server header announces '{server}'. "
                + ("With a version number an attacker can look up known CVEs directly." if has_version
                   else "Without a version this is minor, but still free reconnaissance."),
                remediation="Configure the web server to omit or genericise the Server header "
                            "(e.g. nginx: server_tokens off; Apache: ServerTokens Prod).",
                evidence=f"Server: {server}",
                dedup_key=server,
            ))

        for header in TECH_HEADERS:
            value = h.get(header)
            if value:
                findings.append(Finding(
                    rule_id="DISCLOSURE_TECH_HEADER",
                    check=self.name,
                    severity=Severity.LOW,
                    title=f"{header} header reveals technology",
                    url=url,
                    description=f"The response includes '{header}: {value}', revealing the framework or "
                                "platform in use and helping an attacker pick targeted exploits.",
                    remediation=f"Remove the {header} header (e.g. Express: app.disable('x-powered-by'); "
                                "PHP: expose_php = Off).",
                    evidence=f"{header}: {value}",
                    dedup_key=f"{header}:{value}",
                ))
        return findings
