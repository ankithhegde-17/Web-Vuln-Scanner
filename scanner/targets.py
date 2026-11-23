"""Turning the crawler's results and --urls seeds into injection points.

The Phase 1 crawler only sees one page on JavaScript-rendered apps (Juice
Shop included), so on those sites it finds almost no forms or parameters to
test. The --urls seed solves that: you hand the scanner a list of endpoints
(including ones with query parameters) that you know exist, and the active
checks probe them directly.

This module has no network code. It just builds the list of InjectionPoints
that the active checks will work through.
"""

from __future__ import annotations

import json as jsonlib
import logging
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from scanner.active.base import BENIGN_VALUE, BODY_FORM, BODY_JSON, BODY_QUERY, InjectionPoint
from scanner.crawler import _origin_key
from scanner.models import Form

log = logging.getLogger(__name__)

# Field types we don't inject into: buttons submit nothing useful, and
# fuzzing a hidden anti-CSRF token or a file input just breaks the request.
# Hidden fields are still sent at their baseline value so the form stays valid.
NON_INJECTABLE_TYPES = {"submit", "button", "image", "reset", "file"}
SKIP_VALUE_ONLY = {"hidden"}


def parse_seed_urls(spec: str) -> list[str]:
    """Read --urls, which is either a path to a file or a comma-separated list.

    In a file, blank lines and lines starting with '#' are ignored, so you can
    comment your targets file.
    """
    path = Path(spec)
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
    else:
        lines = spec.split(",")
    urls = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def points_from_seed_url(url: str) -> list[InjectionPoint]:
    """Build one injection point per query parameter in a seeded URL.

    A seeded URL with no query string (e.g. a REST path) produces no points
    here on its own, because there is nothing to inject into. Seed it with a
    sample parameter, e.g. `/rest/products/search?q=apple`, to make `q`
    testable.
    """
    parts = urlsplit(url)
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not query_pairs:
        return []
    params = {k: v for k, v in query_pairs}
    base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    points = []
    for name in params:
        points.append(InjectionPoint(
            method="GET", url=base, params=dict(params), param=name, body_type=BODY_QUERY,
            source=f"query parameter '{name}' of {base}",
        ))
    return points


def points_from_json_body(url: str, body: dict) -> list[InjectionPoint]:
    """Build one injection point per string field of a JSON POST body.

    Used for JSON APIs (e.g. Juice Shop's `/rest/user/login`, which only
    accepts application/json). We inject into string fields only, because a
    text payload in a numeric or boolean JSON field would just be rejected as
    malformed before it reaches any query. Non-string fields are still sent at
    their baseline value so the request stays valid.
    """
    baseline = {k: ("" if v is None else str(v)) for k, v in body.items()}
    points = []
    for name, value in body.items():
        if isinstance(value, str):
            points.append(InjectionPoint(
                method="POST", url=url, params=dict(baseline), param=name, body_type=BODY_JSON,
                source=f"JSON field '{name}' on {url}",
            ))
    return points


def points_from_seed_line(line: str) -> list[InjectionPoint]:
    """Interpret one line of a --urls seed.

    Three forms are accepted:
      * `http://host/path?x=1`            -> GET, each query parameter is a point
      * `GET http://host/path?x=1`        -> same, explicit method
      * `POST http://host/login {"email":"a","password":"b"}`
                                          -> JSON POST, each string field is a point

    The JSON form is what lets the scanner reach APIs that only accept a JSON
    body. The placeholder values ("a"/"b") are benign; the scanner swaps each
    in turn for its detection payloads.
    """
    tokens = line.split(None, 2)
    method = tokens[0].upper() if tokens and tokens[0].upper() in ("GET", "POST") else None

    if method is None:
        return points_from_seed_url(line)  # bare URL -> GET query params

    if len(tokens) < 2:
        log.warning("Seed line names a method but no URL: %s", line)
        return []
    url = tokens[1]
    body_text = tokens[2] if len(tokens) > 2 else ""

    if method == "POST" and body_text:
        try:
            body = jsonlib.loads(body_text)
        except jsonlib.JSONDecodeError as exc:
            log.warning("Seed line has an invalid JSON body (%s): %s", exc, line)
            return []
        if not isinstance(body, dict):
            log.warning("Seed line JSON body must be an object: %s", line)
            return []
        return points_from_json_body(url, body)

    # GET with explicit method, or POST with no body: treat query params as the
    # injection points (POST-with-no-body falls back to GET-style query here).
    return points_from_seed_url(url)


def points_from_form(form: Form) -> list[InjectionPoint]:
    """Build one injection point per injectable field of a form."""
    baseline: dict[str, str] = {}
    injectable: list[str] = []
    for fld in form.fields:
        if fld.field_type in NON_INJECTABLE_TYPES:
            continue
        baseline[fld.name] = fld.value or BENIGN_VALUE
        if fld.field_type not in SKIP_VALUE_ONLY:
            injectable.append(fld.name)

    method = form.method if form.method in ("GET", "POST") else "POST"
    body_type = BODY_QUERY if method == "GET" else BODY_FORM
    points = []
    for name in injectable:
        points.append(InjectionPoint(
            method=method, url=form.action, params=dict(baseline), param=name, body_type=body_type,
            source=f"form field '{name}' on {form.page_url} (submits to {form.action})",
        ))
    return points


def build_injection_points(forms: list[Form], seed_urls: list[str], scope_url: str) -> list[InjectionPoint]:
    """Combine crawler forms and seeded URLs into one de-duplicated list.

    Everything is scope-checked against `scope_url`: an injection point whose
    host or port differs from the authorized target is dropped, so active
    probes can never leave the host you said you were allowed to test.
    """
    scope = _origin_key(scope_url)
    points: list[InjectionPoint] = []
    skipped_out_of_scope: list[str] = []

    def in_scope(u: str) -> bool:
        return _origin_key(u) == scope

    for form in forms:
        if in_scope(form.action):
            points.extend(points_from_form(form))
        else:
            skipped_out_of_scope.append(form.action)

    for line in seed_urls:
        new_points = points_from_seed_line(line)
        if not new_points:
            log.info("Seed line produced no injection points: %s", line)
            continue
        # Scope-check each point by its actual target URL (a line may be
        # method-prefixed, e.g. "POST http://host/login {...}").
        for p in new_points:
            if in_scope(p.url):
                points.append(p)
            else:
                skipped_out_of_scope.append(p.url)

    if skipped_out_of_scope:
        for u in skipped_out_of_scope:
            log.warning("Skipping out-of-scope target (not on the authorized host): %s", u)

    # De-duplicate: the same (method, url, param, body_type) only needs testing once.
    seen = set()
    unique = []
    for p in points:
        key = (p.method, urlsplit(p.url)._replace(query="").geturl(), p.param, p.body_type, tuple(sorted(p.params)))
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique
