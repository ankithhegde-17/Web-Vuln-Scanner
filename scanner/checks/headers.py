"""Missing or weak HTTP security headers.

Security headers are instructions the server gives the browser ("don't let
other sites frame this page", "only ever talk to me over HTTPS"). They cost
nothing to add and block whole classes of attacks, so their absence is one of
the most common findings in real assessments.

We only evaluate *document* responses (HTML, status 2xx). A missing CSP on a
PNG or a 404 page isn't meaningful and would just add noise.
"""

from __future__ import annotations

import re

import requests

from scanner.checks.base import ResponseCheck, is_html, is_https, is_localhost
from scanner.models import Finding, Severity

# HSTS max-age below ~6 months is considered too short to be effective
# (and is below the threshold for browser preload lists, which require 1 year).
MIN_HSTS_MAX_AGE = 15_552_000  # 180 days in seconds

WEAK_REFERRER_POLICIES = {"unsafe-url", "no-referrer-when-downgrade"}


def parse_csp(header: str) -> dict[str, list[str]]:
    """Turn "default-src 'self'; script-src 'self' cdn.com" into a dict."""
    directives: dict[str, list[str]] = {}
    for part in header.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


class SecurityHeadersCheck(ResponseCheck):
    name = "security_headers"

    def check_response(self, response: requests.Response) -> list[Finding]:
        if not (200 <= response.status_code < 300 and is_html(response)):
            return []

        url = response.url
        h = response.headers  # requests' header dict is case-insensitive
        findings: list[Finding] = []

        def add(rule_id, severity, title, description, remediation, evidence="", confidence="confirmed"):
            findings.append(
                Finding(
                    rule_id=rule_id, check=self.name, severity=severity, title=title, url=url,
                    description=description, remediation=remediation, evidence=evidence,
                    confidence=confidence,
                )
            )

        # ---- Transport: is the page even served over HTTPS? ----------------
        if not is_https(url):
            # On localhost (e.g. Juice Shop in Docker) plain HTTP is expected,
            # so we downgrade to INFO instead of crying wolf.
            add(
                "TRANSPORT_PLAIN_HTTP",
                Severity.INFO if is_localhost(url) else Severity.MEDIUM,
                "Page served over plain HTTP",
                "Traffic is unencrypted, so anyone on the network path can read or modify it. "
                "HSTS cannot be applied to plain-HTTP responses.",
                "Serve the site only over HTTPS and redirect HTTP to HTTPS.",
            )

        # ---- Content-Security-Policy ---------------------------------------
        csp = h.get("Content-Security-Policy")
        csp_ro = h.get("Content-Security-Policy-Report-Only")
        directives = parse_csp(csp) if csp else {}
        if not csp:
            if csp_ro:
                add("HEADER_CSP_REPORT_ONLY", Severity.LOW, "CSP is in report-only mode",
                    "A Content-Security-Policy-Report-Only header only reports violations; it does not block anything.",
                    "Once the policy is tuned, send it as Content-Security-Policy to enforce it.",
                    evidence=csp_ro[:200])
            else:
                add("HEADER_CSP_MISSING", Severity.MEDIUM, "Content-Security-Policy header missing",
                    "Without a CSP the browser will run any script that ends up in the page, so a single "
                    "XSS bug gives an attacker full control. CSP is the main defence-in-depth layer against XSS.",
                    "Add a Content-Security-Policy, starting with something like "
                    "\"default-src 'self'; object-src 'none'; frame-ancestors 'self'\" and tightening from there.")
        else:
            # Which directive governs scripts? script-src, falling back to default-src.
            script_src = directives.get("script-src", directives.get("default-src"))
            if script_src is None:
                add("HEADER_CSP_NO_SCRIPT_RESTRICTION", Severity.MEDIUM, "CSP does not restrict scripts",
                    "The policy has neither script-src nor default-src, so scripts from anywhere are allowed.",
                    "Add a default-src or script-src directive.", evidence=csp[:200])
            else:
                weak = [t for t in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:", "https:") if t in script_src]
                # 'unsafe-inline' is ignored by browsers if a nonce or hash is present.
                if "'unsafe-inline'" in weak and any(t.startswith(("'nonce-", "'sha")) for t in script_src):
                    weak.remove("'unsafe-inline'")
                if weak:
                    add("HEADER_CSP_WEAK", Severity.LOW, "CSP allows unsafe script sources",
                        f"The script policy contains {', '.join(weak)}, which lets injected or attacker-hosted "
                        "scripts run and largely defeats the purpose of CSP.",
                        "Remove 'unsafe-inline'/'unsafe-eval' and wildcards; use nonces or hashes for inline scripts.",
                        evidence=csp[:200])

        # ---- Clickjacking: X-Frame-Options or CSP frame-ancestors -------------
        xfo = h.get("X-Frame-Options", "").strip().upper()
        if not xfo and "frame-ancestors" not in directives:
            add("HEADER_XFO_MISSING", Severity.MEDIUM, "Clickjacking protection missing",
                "Neither X-Frame-Options nor CSP frame-ancestors is set, so another site can load this page "
                "in an invisible iframe and trick users into clicking buttons on it (clickjacking).",
                "Send \"X-Frame-Options: DENY\" (or SAMEORIGIN), or the CSP directive \"frame-ancestors 'self'\".")
        elif xfo and xfo not in ("DENY", "SAMEORIGIN"):
            add("HEADER_XFO_INVALID", Severity.LOW, "X-Frame-Options has an ineffective value",
                "Modern browsers only honour DENY and SAMEORIGIN; values like ALLOW-FROM are ignored, "
                "leaving the page frameable.",
                "Use DENY or SAMEORIGIN, or CSP frame-ancestors for allow-lists.", evidence=xfo)

        # ---- HSTS (only meaningful over HTTPS) --------------------------------
        if is_https(url):
            hsts = h.get("Strict-Transport-Security")
            if not hsts:
                add("HEADER_HSTS_MISSING", Severity.MEDIUM, "Strict-Transport-Security header missing",
                    "Without HSTS, a user typing the domain (or clicking an http:// link) makes a first plain-HTTP "
                    "request that an attacker on the network can intercept and downgrade (SSL stripping).",
                    "Send \"Strict-Transport-Security: max-age=31536000; includeSubDomains\".")
            else:
                m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.IGNORECASE)
                max_age = int(m.group(1)) if m else 0
                if max_age < MIN_HSTS_MAX_AGE:
                    add("HEADER_HSTS_WEAK", Severity.LOW, "HSTS max-age is too short",
                        f"max-age is {max_age} seconds. Short values mean browsers forget the HTTPS-only rule "
                        "quickly; max-age=0 disables HSTS entirely.",
                        "Use max-age of at least 31536000 (one year).", evidence=hsts)

        # ---- X-Content-Type-Options --------------------------------------------
        xcto = h.get("X-Content-Type-Options", "").strip().lower()
        if xcto != "nosniff":
            add("HEADER_XCTO_MISSING", Severity.LOW, "X-Content-Type-Options: nosniff missing",
                "Browsers may 'sniff' a response and treat, say, an uploaded text file as HTML or JavaScript, "
                "which can turn a file upload into XSS.",
                "Send \"X-Content-Type-Options: nosniff\" on all responses.", evidence=xcto)

        # ---- Referrer-Policy ---------------------------------------------------
        rp = h.get("Referrer-Policy", "").strip().lower()
        if not rp:
            add("HEADER_REFERRER_POLICY_MISSING", Severity.LOW, "Referrer-Policy header missing",
                "Without an explicit policy the full URL (which may contain tokens, IDs or search terms) can be "
                "sent to third-party sites in the Referer header. Modern browsers default to a safer policy, "
                "which is why this is LOW.",
                "Send \"Referrer-Policy: strict-origin-when-cross-origin\" (or no-referrer).")
        else:
            # The header may list fallbacks; the browser uses the last one it understands.
            effective = rp.split(",")[-1].strip()
            if effective in WEAK_REFERRER_POLICIES:
                add("HEADER_REFERRER_POLICY_WEAK", Severity.LOW, "Referrer-Policy leaks full URLs",
                    f"'{effective}' sends the full URL, including path and query string, to other sites.",
                    "Use strict-origin-when-cross-origin or no-referrer.", evidence=rp)

        return findings
