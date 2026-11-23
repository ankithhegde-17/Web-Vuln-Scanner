"""Human-readable summary printed to the terminal.

Uses plain ANSI escape codes for colour instead of a library such as
`rich` or `colorama`, to keep dependencies minimal. Colour is switched off
automatically when output isn't a terminal (e.g. piped to a file) or when
the NO_COLOR environment variable is set (a common convention, no-color.org).
"""

from __future__ import annotations

import os
import sys
from collections import Counter
from typing import TextIO

from scanner.core import ScanResult
from scanner.models import Severity

COLORS = {
    Severity.HIGH: "\033[1;31m",    # bold red
    Severity.MEDIUM: "\033[33m",    # yellow
    Severity.LOW: "\033[36m",       # cyan
    Severity.INFO: "\033[37m",      # grey
}
BOLD = "\033[1m"
RESET = "\033[0m"


def _use_color(stream: TextIO) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ


def print_summary(result: ScanResult, report_path: str | None = None, stream: TextIO = sys.stdout) -> None:
    color = _use_color(stream)

    def c(text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    out = lambda s="": print(s, file=stream)  # noqa: E731

    out()
    out(c("=" * 70, BOLD))
    out(c(f" Scan summary for {result.config.start_url}", BOLD))
    out(c("=" * 70, BOLD))
    out(f" Mode          : {'active + passive' if result.config.active_checks else 'passive only'}")
    out(f" Pages crawled : {len(result.crawl.pages)}")
    out(f" Forms found   : {len(result.crawl.forms)}")
    if result.config.active_checks:
        out(f" Points tested : {result.injection_points_tested}  (injection points probed by active checks)")
    out(f" Requests made : {result.request_count}")

    counts = Counter(f.severity for f in result.findings)
    sev_line = "  ".join(c(f"{s.value.upper()}: {counts.get(s, 0)}", COLORS[s]) for s in reversed(Severity))
    out(f" Findings      : {len(result.findings)}   ({sev_line})")
    out()

    if not result.findings:
        out(" No findings. (Passive checks only, so this does not mean the site is secure.)")
    for f in result.findings:
        tag = c(f"[{f.severity.value.upper():6}]", COLORS[f.severity])
        tentative = " (tentative)" if f.confidence == "tentative" else ""
        out(f" {tag} {f.title}{tentative}")
        extra = len(f.affected_urls) - 1
        out(f"          url: {f.url}" + (f"  (+{extra} more)" if extra > 0 else ""))
        if f.payload:
            out(f"          payload: {f.payload}")
        if f.evidence:
            out(f"          evidence: {f.evidence}")
        out(f"          fix: {f.remediation}")
        out()

    if result.errors:
        for warning in result.errors:
            out(c(f" ! {warning}", COLORS[Severity.MEDIUM]))
        out()

    if result.crawl.forms:
        out(c(" Forms discovered (recorded only, never submitted):", BOLD))
        for form in result.crawl.forms:
            names = ", ".join(f"{fld.name}<{fld.field_type}>" for fld in form.fields) or "(no named fields)"
            out(f"   {form.method:4} {form.action}  <- {form.page_url}")
            out(f"        fields: {names}")
        out()

    if report_path:
        out(f" Full JSON report written to: {report_path}")
    out()
