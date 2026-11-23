"""Write the enriched triage report: JSON for machines, Markdown for people."""

from __future__ import annotations

import json
from pathlib import Path

SEVERITY_EMOJI = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]", "info": "[INFO]"}


def write_json(report: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def _finding_md(f: dict) -> str:
    t = f.get("triage") or {}
    scanner_sev = f.get("severity", "info")
    adjusted = t.get("adjusted_severity", scanner_sev)
    tag = SEVERITY_EMOJI.get(adjusted, "[    ]")

    lines = [f"### {tag} {f.get('title', f.get('rule_id', 'Finding'))}"]
    # Show the re-rank explicitly when triage changed it.
    if adjusted != scanner_sev:
        lines.append(f"**Severity:** {adjusted}  (scanner said *{scanner_sev}*)")
    else:
        lines.append(f"**Severity:** {adjusted}")
    if t.get("severity_reason"):
        lines.append(f"*{t['severity_reason']}*")
    lines.append("")
    lines.append(f"- **URL:** {f.get('url', '')}")
    if f.get("payload"):
        lines.append(f"- **Payload:** `{f['payload']}`")
    if f.get("evidence"):
        lines.append(f"- **Evidence:** {f['evidence']}")
    if t.get("likely_false_positive"):
        lines.append(f"- **⚠ Likely false positive:** {t.get('false_positive_reason', '')}")
    if t.get("duplicate_of"):
        lines.append(f"- **Duplicate of:** `{t['duplicate_of']}`")
    lines.append("")
    if t.get("explanation"):
        lines.append(t["explanation"])
        lines.append("")
    if t.get("example_fix"):
        lines.append(f"**Example fix:** {t['example_fix']}")
        lines.append("")
    if not t:
        lines.append(f"_(not triaged)_ {f.get('description', '')}")
        lines.append("")
    return "\n".join(lines)


def build_markdown(report: dict) -> str:
    triage = report.get("triage", {})
    findings = report.get("findings", [])

    lines = [
        f"# Triage report — {report.get('target', 'unknown target')}",
        "",
        f"- **Scanner:** {report.get('scanner', {}).get('name', 'webvuln-scanner')} "
        f"({report.get('scanner', {}).get('mode', '')} mode)",
    ]
    if triage.get("enriched"):
        lines.append(f"- **Triage model:** {triage.get('provider', '')} / {triage.get('model', '')}")
    lines.append(f"- **Findings:** {len(findings)}")
    lines.append("")

    if triage.get("summary"):
        lines += ["## Summary", "", triage["summary"], ""]
    if triage.get("error"):
        lines += ["> **Note:** triage enrichment was skipped — " + triage["error"], ""]

    # Count false positives / duplicates flagged.
    fps = sum(1 for f in findings if (f.get("triage") or {}).get("likely_false_positive"))
    dups = sum(1 for f in findings if (f.get("triage") or {}).get("duplicate_of"))
    if triage.get("enriched"):
        lines += [f"Triage flagged **{fps}** likely false positive(s) and **{dups}** duplicate(s). "
                  "Findings are ordered by real-world severity; flagged items are sorted to the end.", ""]

    lines += ["## Findings", ""]
    for f in findings:
        lines.append(_finding_md(f))
    return "\n".join(lines)


def write_markdown(report: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_markdown(report), encoding="utf-8")
    return path
