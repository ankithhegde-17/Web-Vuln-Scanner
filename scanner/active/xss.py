"""Reflected cross-site scripting (XSS) detection.

Idea: send a unique, harmless marker that contains the characters an attacker
would need for XSS (`<`, `>`, `"`, `'`), then look at whether those characters
come back **unencoded** in the HTML response.

  * If the marker comes back exactly as sent, the application copied our input
    into the page without escaping it. An attacker could replace the marker
    with a real <script> and it would run. -> reported (HIGH).
  * If the marker comes back HTML-escaped (`&lt;...&gt;`), the app is doing the
    right thing. -> NOT reported. This is the key to avoiding false positives:
    many sites reflect your input, but safely.

Why this is safe to run:
  * The payload contains NO script, event handler or tag name a browser would
    act on. It is a random token wrapped in angle brackets and quotes. Even if
    it executes nothing, its unencoded reflection is enough to prove the flaw.
  * It only reads the response; it changes nothing on the server.
"""

from __future__ import annotations

import html
import secrets

import requests

from scanner.active.base import ActiveCheck, InjectionPoint, send_with
from scanner.http_client import RateLimitedClient
from scanner.models import Finding, Severity

# The characters that matter for breaking out of HTML text, tags and
# attributes. If all of these survive unencoded, the parameter is injectable.
BREAKOUT_CHARS = "<>\"'"


def make_marker() -> str:
    """A unique token so we can be sure we're seeing OUR input reflected back,
    not some unrelated text that happened to be on the page."""
    return "xss" + secrets.token_hex(5)


class ReflectedXSSCheck(ActiveCheck):
    name = "reflected_xss"

    def check_point(self, point: InjectionPoint, client: RateLimitedClient) -> list[Finding]:
        marker = make_marker()
        # e.g.  xssa1b2c3d4e5"'<>  -- unique token + the breakout characters.
        payload = f"{marker}{BREAKOUT_CHARS}"

        resp = send_with(client, point, payload)
        if resp is None:
            return []

        # Only HTML responses can execute reflected markup. A marker echoed in
        # a JSON API response isn't XSS (the browser won't parse it as HTML),
        # so we don't flag it here.
        content_type = resp.headers.get("Content-Type", "").lower()
        if "html" not in content_type:
            return []

        body = resp.text
        if payload not in body:
            # Either not reflected at all, or reflected but encoded. Check for
            # the encoded form so we can tell the two apart (useful for the
            # log, but neither case is a finding).
            if marker in body and html.escape(payload) in body:
                # Reflected but correctly escaped: the safe, common case.
                return []
            return []

        # The exact payload, breakout characters and all, is in the page
        # unencoded. That's a genuine reflected-XSS sink.
        snippet = self._context_snippet(body, payload)
        return [Finding(
            rule_id="ACTIVE_REFLECTED_XSS",
            check=self.name,
            severity=Severity.HIGH,
            title=f"Reflected XSS via {point.param}",
            url=resp.url,
            description=(
                f"Input sent in '{point.param}' is reflected into the HTML response without encoding the "
                "characters < > \" '. An attacker can inject script that runs in the victim's browser "
                "(session theft, actions on the user's behalf, defacement)."
            ),
            remediation=(
                "Context-aware output encoding: HTML-encode untrusted data before putting it in the page "
                "(and use a templating engine that does this by default). Add a Content-Security-Policy as "
                "defence in depth."
            ),
            evidence=f"Reflected unencoded near: ...{snippet}...",
            payload=payload,
            confidence="confirmed",
            dedup_key=f"{point.method}:{point.url}:{point.param}",
        )]

    @staticmethod
    def _context_snippet(body: str, payload: str, width: int = 40) -> str:
        """A short excerpt around the reflection, for the evidence field."""
        idx = body.find(payload)
        start = max(0, idx - width)
        end = min(len(body), idx + len(payload) + width)
        return body[start:end].replace("\n", " ").strip()
