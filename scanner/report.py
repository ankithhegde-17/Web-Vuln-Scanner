"""Turn a saved scan report into a self-contained HTML dashboard (Phase 4).

    python -m scanner.report scan-results.json            # -> scan-results.html
    python -m scanner.report scan-results.triaged.json    # uses the triage fields
    python -m scanner.report scan-results.json -o report.html

This only reads a JSON file and writes an HTML file: it never contacts the
target or any LLM, so it needs no permission flag and no API key.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scanner.reporting.html_report import write_html_from_json


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="scanner.report",
        description="Render a webvuln-scanner JSON report (plain or .triaged.json) as a single, "
                    "self-contained HTML file that works offline.",
    )
    p.add_argument("report", help="Path to a scan JSON report")
    p.add_argument("-o", "--output", default=None,
                   help="Where to write the HTML (default: the input path with .html)")
    args = p.parse_args(argv)

    src = Path(args.report)
    if not src.is_file():
        print(f"error: report not found: {src}", file=sys.stderr)
        return 1
    try:
        out = write_html_from_json(src, args.output)
    except json.JSONDecodeError as exc:
        print(f"error: {src} is not valid JSON: {exc}", file=sys.stderr)
        return 1
    print(f"HTML report written to: {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
