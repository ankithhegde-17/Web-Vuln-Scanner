"""Insecure cookie flags.

Cookies often hold session tokens: whoever has the cookie *is* the user.
Three flags control how safely the browser handles them:

  Secure    only send the cookie over HTTPS (stops network sniffing)
  HttpOnly  hide the cookie from JavaScript (stops XSS from stealing it)
  SameSite  don't attach the cookie to cross-site requests (mitigates CSRF)

We read the raw Set-Cookie headers rather than `response.cookies`, because
the parsed cookie jar throws away exactly the attributes we want to check.
We never put cookie *values* in the report; the name is enough evidence and
values may be live session tokens.
"""

from __future__ import annotations

import re

import requests

from scanner.checks.base import ResponseCheck, is_https
from scanner.models import Finding, Severity

# Names that usually indicate an authentication/session cookie. Missing
# flags on these are more serious than on, say, a "theme=dark" cookie.
SESSION_NAME_PATTERN = re.compile(r"sess|sid|token|auth|jwt|login|remember", re.IGNORECASE)


def get_set_cookie_headers(response: requests.Response) -> list[str]:
    """Every Set-Cookie header, unmerged.

    `response.headers["Set-Cookie"]` joins multiple cookies with commas, which
    is ambiguous because cookie Expires dates contain commas too. The
    underlying urllib3 header object keeps them separate.
    """
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        return raw_headers.getlist("Set-Cookie")
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def parse_set_cookie(header: str) -> tuple[str, dict[str, str]]:
    """Return (cookie_name, {attribute_lowercase: value})."""
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return name, attrs


class CookieFlagsCheck(ResponseCheck):
    name = "cookie_flags"

    def check_response(self, response: requests.Response) -> list[Finding]:
        findings: list[Finding] = []
        url = response.url
        https = is_https(url)

        for header in get_set_cookie_headers(response):
            name, attrs = parse_set_cookie(header)
            if not name:
                continue
            looks_like_session = bool(SESSION_NAME_PATTERN.search(name))
            flags_present = sorted(k for k in attrs if k in ("secure", "httponly", "samesite"))
            evidence = f"cookie '{name}' flags: {', '.join(flags_present) or 'none'}"

            def add(rule_id, severity, title, description, remediation):
                findings.append(Finding(
                    rule_id=rule_id, check=self.name, severity=severity, title=f"{title}: {name}",
                    url=url, description=description, remediation=remediation, evidence=evidence,
                    dedup_key=name,  # one finding per cookie name, not per page
                ))

            if "secure" not in attrs:
                # Over plain HTTP the Secure flag can't be used at all, so
                # this is a lower-severity note; the real fix is HTTPS.
                add("COOKIE_NO_SECURE",
                    Severity.MEDIUM if (https and looks_like_session) else Severity.LOW,
                    "Cookie missing Secure flag",
                    "The browser will also send this cookie over unencrypted HTTP, where it can be sniffed.",
                    "Add the Secure attribute (and serve the site over HTTPS).")

            if "httponly" not in attrs:
                add("COOKIE_NO_HTTPONLY",
                    Severity.MEDIUM if looks_like_session else Severity.LOW,
                    "Cookie missing HttpOnly flag",
                    "JavaScript can read this cookie via document.cookie, so any XSS bug can steal it. "
                    "Cookies that the front-end genuinely needs to read are an exception.",
                    "Add the HttpOnly attribute unless client-side code must read the cookie.")

            samesite = attrs.get("samesite", "").lower()
            if "samesite" not in attrs:
                add("COOKIE_NO_SAMESITE", Severity.LOW, "Cookie missing SameSite attribute",
                    "Without SameSite the behaviour depends on the browser's default; older browsers send the "
                    "cookie on cross-site requests, enabling CSRF.",
                    "Set SameSite=Lax (good default) or SameSite=Strict for sensitive cookies.")
            elif samesite == "none" and "secure" not in attrs:
                add("COOKIE_SAMESITE_NONE_INSECURE", Severity.MEDIUM, "SameSite=None without Secure",
                    "Browsers reject SameSite=None cookies that are not also Secure, and when accepted they "
                    "are sent on every cross-site request.",
                    "Add Secure, or use SameSite=Lax if cross-site use isn't needed.")

        return findings
