"""Shared triage driver used by both `python -m scanner.triage` and the
`--triage` flag on a scan, so the behaviour (and the graceful skip) is
identical no matter how triage is invoked.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from scanner.triage.engine import triage_report
from scanner.triage.providers import MissingAPIKey, TriageError, build_provider, load_dotenv
from scanner.triage.report import write_json, write_markdown

log = logging.getLogger(__name__)


def run_triage(
    report: dict,
    output_base: str | Path,
    provider_name: str = "anthropic",
    model: str | None = None,
    dotenv_path: str | Path = ".env",
    stderr=None,
) -> bool:
    """Triage `report` and write <base>.triaged.json / .triaged.md.

    Returns True if triage ran, False if it was skipped (no key). Never raises
    for the normal 'no key' case -- that's the graceful-skip requirement.
    """
    # Resolve stderr at call time (not as a default) so callers and tests that
    # replace sys.stderr still capture our messages.
    stderr = stderr if stderr is not None else sys.stderr
    load_dotenv(dotenv_path)  # fill os.environ from .env (never overwriting real env vars)

    try:
        provider = build_provider(provider_name, model)
    except MissingAPIKey as exc:
        print(f"\nSkipping triage: {exc}\n"
              f"  Set {exc.env_var} in your environment or a .env file to enable it. "
              f"The scan report is unchanged.", file=stderr)
        return False
    except TriageError as exc:
        print(f"\nSkipping triage: {exc}", file=stderr)
        return False

    print(f"Triaging {len(report.get('findings', []))} finding(s) with "
          f"{provider.name}/{provider.model}...", file=stderr)
    try:
        enriched = triage_report(report, provider)
    except TriageError as exc:
        # SDK missing, auth rejected, network, etc. Don't lose the scan.
        print(f"\nTriage could not complete: {exc}\n  The scan report is unchanged.", file=stderr)
        return False

    base = Path(output_base)
    stem = base.with_suffix("")  # drop .json if present
    json_path = write_json(enriched, f"{stem}.triaged.json")
    md_path = write_markdown(enriched, f"{stem}.triaged.md")
    print(f"Triage report written to:\n  {json_path}\n  {md_path}", file=stderr)
    return True
