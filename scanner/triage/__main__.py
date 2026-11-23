"""Run triage on a saved scan report:

    python -m scanner.triage scan-results.json
    python -m scanner.triage scan-results.json --llm-provider openai --llm-model gpt-4o

This reads a Phase 2 JSON report and writes <report>.triaged.json and
<report>.triaged.md. It sends the findings to the configured LLM only; if no
API key is set it prints how to set one and exits cleanly.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scanner.triage.runner import run_triage


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="scanner.triage",
        description="LLM triage for a webvuln-scanner JSON report (opt-in; needs an API key).",
    )
    p.add_argument("report", help="Path to a scan JSON report (from `python -m scanner ... -o report.json`)")
    p.add_argument("--llm-provider", default="anthropic", help="LLM provider (default: anthropic)")
    p.add_argument("--llm-model", default=None, help="Model id (default: the provider's default)")
    p.add_argument("-o", "--output", default=None,
                   help="Base path for output (default: alongside the input report)")
    p.add_argument("--env-file", default=".env", help="Path to a .env file to load (default: ./.env)")
    args = p.parse_args(argv)

    report_path = Path(args.report)
    if not report_path.is_file():
        print(f"error: report not found: {report_path}", file=sys.stderr)
        return 1
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"error: {report_path} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    output_base = args.output or str(report_path)
    ran = run_triage(
        report, output_base,
        provider_name=args.llm_provider, model=args.llm_model, dotenv_path=args.env_file,
    )
    return 0 if ran else 0  # a clean skip is still a success for scripting


if __name__ == "__main__":
    sys.exit(main())
