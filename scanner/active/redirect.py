"""Open-redirect detection.

An open redirect is a parameter that controls where the server sends the
browser next (e.g. `/login?returnUrl=/account`). If the app doesn't check the
value, an attacker can craft `?returnUrl=http://evil.example` and use your
trusted domain to bounce victims to a phishing page.

Detection: put a harmless MARKER host into redirect-style parameters and see
whether the server tries to send us there (via a 3xx Location header or an
HTML meta-refresh). The marker is a non-routable `.invalid` host
(RFC 2606/6761 reserves `.invalid` so it can never resolve to a real server),
so even if a browser followed the redirect it would go nowhere. We also never
follow the redirect ourselves.

We test a parameter when either its NAME looks redirect-related, or its
baseline VALUE already looks like a URL or path.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import requests

from scanner.active.base import ActiveCheck, InjectionPoint, send_with
from scanner.http_client import RateLimitedClient
from scanner.models import Finding, Severity

# Non-routable marker. If a redirect lands here, the parameter is an open
# redirect. Using .invalid guarantees it points at nothing real.
MARKER_HOST = "vuln-scanner-probe.invalid"
# Try an absolute URL and a protocol-relative one (//host), since some apps
# block "http://" but not "//".
PAYLOADS = [f"http://{MARKER_HOST}/", f"https://{MARKER_HOST}/", f"//{MARKER_HOST}/"]

REDIRECT_PARAM_NAMES = re.compile(
    r"^(redirect|redir|redirect_?uri|url|uri|next|return|returnurl|return_?url|dest|"
    r"destination|continue|goto|go|to|out|link|target|forward|r|u)$",
    re.IGNORECASE,
)

META_REFRESH = re.compile(
    r"""<meta[^>]+http-equiv=['"]?refresh['"]?[^>]+url=([^'">\s]+)""", re.IGNORECASE
)


def _looks_like_url_value(value: str) -> bool:
    return value.startswith(("http://", "https://", "//", "/")) if value else False


def _redirects_to_marker(resp: requests.Response) -> tuple[str, str] | None:
    """Return (mechanism, location) if the response sends us to the marker host."""
    # 1. HTTP redirect via the Location header.
    if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("Location", "")
        if urlsplit(location).hostname == MARKER_HOST:
            return "Location header", location

    # 2. HTML meta refresh redirect.
    if "html" in resp.headers.get("Content-Type", "").lower():
        m = META_REFRESH.search(resp.text)
        if m and urlsplit(m.group(1).strip()).hostname == MARKER_HOST:
            return "meta refresh", m.group(1).strip()
    return None


class OpenRedirectCheck(ActiveCheck):
    name = "open_redirect"

    def check_point(self, point: InjectionPoint, client: RateLimitedClient) -> list[Finding]:
        name_matches = bool(REDIRECT_PARAM_NAMES.match(point.param))
        value_matches = _looks_like_url_value(point.params.get(point.param, ""))
        if not (name_matches or value_matches):
            return []  # not a redirect-style parameter; skip to avoid noise

        for payload in PAYLOADS:
            # allow_redirects stays False: we inspect the redirect, never follow it.
            resp = send_with(client, point, payload, allow_redirects=False)
            if resp is None:
                continue
            hit = _redirects_to_marker(resp)
            if hit:
                mechanism, location = hit
                return [Finding(
                    rule_id="ACTIVE_OPEN_REDIRECT", check=self.name, severity=Severity.MEDIUM,
                    title=f"Open redirect via {point.param}",
                    url=resp.url,
                    description=(
                        f"The '{point.param}' parameter redirects the browser to an attacker-controlled host "
                        f"({mechanism}). Attackers abuse this to make phishing links look like they point at "
                        "your trusted domain."
                    ),
                    remediation=(
                        "Don't redirect to raw user-supplied URLs. Allow only relative paths, or validate the "
                        "destination against an allow-list of known hosts."
                    ),
                    evidence=f"Redirected to {location} via {mechanism}",
                    payload=payload, confidence="confirmed",
                    dedup_key=f"{point.method}:{point.url}:{point.param}",
                )]
        return []
