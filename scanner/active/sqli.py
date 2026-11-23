"""SQL injection detection — safe, non-destructive only.

Two independent techniques, neither of which changes any data:

1. ERROR-BASED
   Send a single breaking character (an unbalanced quote). If the parameter is
   concatenated straight into a SQL query, the database throws a syntax error,
   and that error text often leaks into the HTTP response. We match the
   response against a library of well-known DB error signatures (MySQL,
   PostgreSQL, SQLite, MS SQL Server, Oracle). To avoid flagging an error that
   was already on the page, we only report a signature that appears after the
   quote but NOT in the clean baseline response.

2. BOOLEAN-BASED (behavioural)
   Send two payloads that are syntactically valid but logically opposite:
       ' AND '1'='1   (always true)
       ' AND '1'='2   (always false)
   If the parameter reaches a SQL WHERE clause, the TRUE version returns the
   normal page while the FALSE version returns a different one (e.g. no
   results). A consistent, significant difference between the two — where the
   TRUE response also matches the original page — is the tell-tale sign.

What we deliberately DON'T do (because the brief forbids destructive or noisy
payloads, and they can harm a target):
   * No DROP / DELETE / UPDATE / INSERT — nothing that writes.
   * No stacked queries (`; DROP ...`).
   * No time-based payloads (`SLEEP(5)`) — those deliberately load the DB.
Detection only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher

import requests

from scanner.active.base import ActiveCheck, InjectionPoint, send_with
from scanner.http_client import RateLimitedClient
from scanner.models import Finding, Severity

# Signatures of database error messages. Kept as (engine, compiled regex) so
# the evidence can name which database leaked.
_RAW_SIGNATURES = {
    "MySQL": r"SQL syntax.*MySQL|valid MySQL result|MySqlClient\.|com\.mysql\.jdbc|Unknown column '[^']+' in 'field list'",
    "PostgreSQL": r"PostgreSQL.*ERROR|pg_query\(\)|PG::SyntaxError|unterminated quoted string at or near",
    "SQLite": r"SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|SQLITE_ERROR|sqlite3\.OperationalError|unrecognized token:",
    "MSSQL": r"Microsoft SQL Server|ODBC SQL Server Driver|Unclosed quotation mark after the character string|SQLServerException",
    "Oracle": r"ORA-[0-9]{5}|Oracle error|quoted string not properly terminated",
    "Generic": r"SQL syntax.*error|syntax error at or near|Warning.*\Wmysqli?_|Dynamic SQL Error",
}
SIGNATURES = {engine: re.compile(pattern, re.IGNORECASE) for engine, pattern in _RAW_SIGNATURES.items()}

# A payload that breaks SQL syntax if unescaped, but is harmless otherwise.
ERROR_PAYLOAD = "'\""

# Boolean pairs. We try a quote-based and a numeric-based variant, because we
# don't know whether the parameter sits inside quotes in the query.
BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    (" AND 1=1", " AND 1=2"),
]

# How similar two pages must be to count as "the same" / "different".
SAME_THRESHOLD = 0.98
DIFF_THRESHOLD = 0.95


@dataclass
class _Resp:
    status: int
    text: str


def _similarity(a: str, b: str) -> float:
    """Ratio in [0,1] of how alike two response bodies are. 1.0 = identical."""
    # Comparing a capped prefix keeps this fast on large pages.
    return SequenceMatcher(None, a[:4000], b[:4000]).ratio()


def _find_signature(text: str) -> tuple[str, str] | None:
    for engine, pattern in SIGNATURES.items():
        m = pattern.search(text)
        if m:
            return engine, m.group(0)
    return None


class SQLInjectionCheck(ActiveCheck):
    name = "sql_injection"

    def check_point(self, point: InjectionPoint, client: RateLimitedClient) -> list[Finding]:
        # Baseline: the response to an ordinary, benign value.
        base_resp = send_with(client, point, "1")
        if base_resp is None:
            return []
        baseline = _Resp(base_resp.status_code, base_resp.text)
        baseline_sig = _find_signature(baseline.text)

        finding = self._error_based(point, client, baseline, baseline_sig)
        if finding is None:
            finding = self._boolean_based(point, client, baseline)
        return [finding] if finding else []

    # ----------------------------------------------------------- error-based
    def _error_based(self, point, client, baseline, baseline_sig) -> Finding | None:
        resp = send_with(client, point, ERROR_PAYLOAD)
        if resp is None:
            return None
        hit = _find_signature(resp.text)
        # Must be a signature that wasn't already present on the clean page.
        if hit and (baseline_sig is None or baseline_sig[0] != hit[0]):
            engine, matched = hit
            return Finding(
                rule_id="ACTIVE_SQLI_ERROR", check=self.name, severity=Severity.HIGH,
                title=f"SQL injection (error-based) via {point.param}",
                url=resp.url,
                description=(
                    f"Sending a quote in '{point.param}' produced a {engine} database error in the response, "
                    "which means the input is being placed into a SQL query unsafely. This can allow reading "
                    "or altering database contents."
                ),
                remediation=(
                    "Use parameterised queries / prepared statements (never build SQL by string concatenation), "
                    "and don't return raw database errors to the client."
                ),
                evidence=f"{engine} error signature in response: {matched[:160]}",
                payload=ERROR_PAYLOAD, confidence="confirmed",
                dedup_key=f"{point.method}:{point.url}:{point.param}",
            )
        return None

    # --------------------------------------------------------- boolean-based
    def _boolean_based(self, point, client, baseline) -> Finding | None:
        for true_payload, false_payload in BOOLEAN_PAIRS:
            true_resp = send_with(client, point, f"1{true_payload}")
            false_resp = send_with(client, point, f"1{false_payload}")
            if true_resp is None or false_resp is None:
                continue

            # Classic signal: TRUE looks like the normal page, FALSE differs.
            true_vs_false = _similarity(true_resp.text, false_resp.text)
            true_vs_base = _similarity(true_resp.text, baseline.text)

            if true_vs_base >= SAME_THRESHOLD and true_vs_false < DIFF_THRESHOLD:
                return Finding(
                    rule_id="ACTIVE_SQLI_BOOLEAN", check=self.name, severity=Severity.HIGH,
                    title=f"Possible SQL injection (boolean-based) via {point.param}",
                    url=true_resp.url,
                    description=(
                        f"A true condition ({true_payload!r}) and a false condition ({false_payload!r}) in "
                        f"'{point.param}' produced noticeably different responses, while the true condition "
                        "matched the normal page. That behaviour indicates the input is being evaluated inside "
                        "a SQL query. Confirm manually before reporting."
                    ),
                    remediation=(
                        "Use parameterised queries / prepared statements so user input is treated as data, "
                        "never as part of the SQL statement."
                    ),
                    evidence=(
                        f"similarity true-vs-false={true_vs_false:.2f}, true-vs-baseline={true_vs_base:.2f} "
                        f"(payloads 1{true_payload} / 1{false_payload})"
                    ),
                    payload=f"1{true_payload} | 1{false_payload}",
                    # Behavioural, so a human should confirm: marked tentative.
                    confidence="tentative",
                    dedup_key=f"{point.method}:{point.url}:{point.param}",
                )
        return None
