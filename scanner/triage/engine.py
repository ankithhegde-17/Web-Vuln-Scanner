"""The triage engine: turn raw findings into an LLM-enriched report.

Flow:
    findings --> compact prompt --> LLM --> JSON --> merged back into findings

Design notes:
  * We send the model only the finding fields it needs to reason (id, rule,
    severity, url, evidence, payload, confidence). We do NOT send raw response
    bodies -- the evidence snippets are already short.
  * The model must answer with strict JSON keyed by finding id. We parse it
    defensively (models sometimes wrap JSON in ``` fences or add a sentence),
    retry once, and if it still won't parse we fall back to the original
    findings with a recorded note. Triage never crashes a report.
  * Enrichment is additive: every original field is preserved; triage output
    goes in a new `triage` block per finding, so the Phase 2 schema still holds.
"""

from __future__ import annotations

import json
import logging
import re

from scanner.triage.providers import LLMProvider

log = logging.getLogger(__name__)

# Rank used to sort the enriched report. Mirrors models.Severity ordering but
# is defined here so triage can rank the LLM's *adjusted* severity without
# importing scan internals.
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SYSTEM_PROMPT = """You are a senior application security engineer triaging the \
output of an automated, PASSIVE-and-light-active web vulnerability scanner. \
The scanner only observes responses and sends non-destructive detection \
probes; treat its findings as leads to assess, not ground truth.

For the findings you are given, do three things:
1. Rank each by REAL-WORLD severity (critical/high/medium/low/info), which may \
differ from the scanner's raw label. Consider exploitability, impact, and \
context (e.g. a missing header on a static page is lower risk than a confirmed \
SQL injection). Give a one-sentence reason.
2. Reduce noise: mark findings that are likely FALSE POSITIVES (with a reason), \
and identify duplicates (point a finding at the id it duplicates).
3. Write a short, plain-language remediation note: what the bug is, why it \
matters, and a concrete example fix.

Respond with ONLY a JSON object, no prose and no markdown fences, of this shape:
{
  "summary": "2-3 sentence overview of the overall security posture",
  "findings": {
    "<finding id>": {
      "adjusted_severity": "critical|high|medium|low|info",
      "severity_reason": "one sentence",
      "likely_false_positive": true|false,
      "false_positive_reason": "one sentence, or empty string",
      "duplicate_of": "<another finding id>, or empty string",
      "explanation": "what the bug is and why it matters, plain language",
      "example_fix": "a concrete example fix"
    }
  }
}
Include every finding id exactly once in "findings"."""


def _finding_for_prompt(f: dict) -> dict:
    """The subset of a finding we send to the model (keeps the prompt small)."""
    return {
        "id": f.get("id"),
        "rule_id": f.get("rule_id"),
        "check": f.get("check"),
        "scanner_severity": f.get("severity"),
        "title": f.get("title"),
        "url": f.get("url"),
        "description": f.get("description"),
        "evidence": f.get("evidence", ""),
        "payload": f.get("payload", ""),
        "confidence": f.get("confidence", ""),
        "seen_on_n_urls": len(f.get("affected_urls", []) or [f.get("url")]),
    }


def build_user_prompt(report: dict) -> str:
    findings = [_finding_for_prompt(f) for f in report.get("findings", [])]
    context = {
        "target": report.get("target"),
        "scan_mode": report.get("scanner", {}).get("mode"),
        "findings": findings,
    }
    return "Triage these scanner findings:\n\n" + json.dumps(context, indent=2)


def _extract_json(text: str) -> dict:
    """Parse the model's reply into a dict, tolerating common wrapping.

    Handles a ```json fence or a stray sentence around the object by falling
    back to the outermost {...} span. Raises ValueError if nothing parses.
    """
    text = text.strip()
    # Strip a leading/trailing code fence if present.
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Last resort: the substring from the first { to the last }.
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        return json.loads(text[start : end + 1])
    raise ValueError("No JSON object found in model response")


def _merge(report: dict, triage: dict) -> dict:
    """Attach triage output to each finding and re-rank, additively."""
    per_finding = triage.get("findings", {}) if isinstance(triage, dict) else {}
    enriched = []
    for f in report.get("findings", []):
        t = per_finding.get(f.get("id"))
        f = dict(f)  # don't mutate the input
        if isinstance(t, dict):
            adjusted = str(t.get("adjusted_severity", f.get("severity"))).lower()
            if adjusted not in SEVERITY_RANK:
                adjusted = f.get("severity", "info")
            f["triage"] = {
                "adjusted_severity": adjusted,
                "severity_reason": t.get("severity_reason", ""),
                "likely_false_positive": bool(t.get("likely_false_positive", False)),
                "false_positive_reason": t.get("false_positive_reason", ""),
                "duplicate_of": t.get("duplicate_of", ""),
                "explanation": t.get("explanation", ""),
                "example_fix": t.get("example_fix", ""),
            }
        else:
            # The model didn't return anything for this id: keep it, unenriched.
            f["triage"] = None
        enriched.append(f)

    # Rank by adjusted severity (falling back to the scanner label), most
    # serious first; genuine duplicates and false positives sink to the bottom.
    def sort_key(f: dict):
        t = f.get("triage") or {}
        sev = t.get("adjusted_severity") or f.get("severity", "info")
        penalty = 1 if (t.get("likely_false_positive") or t.get("duplicate_of")) else 0
        return (penalty, -SEVERITY_RANK.get(sev, 0), f.get("rule_id", ""))

    enriched.sort(key=sort_key)

    out = dict(report)
    out["findings"] = enriched
    out["triage"] = {
        "provider": triage.get("_provider", ""),
        "model": triage.get("_model", ""),
        "summary": triage.get("summary", ""),
        "enriched": True,
    }
    return out


def triage_report(report: dict, provider: LLMProvider, retries: int = 1) -> dict:
    """Return an enriched copy of `report`. Never raises on a bad LLM reply.

    If the model's response can't be parsed after `retries`, the report is
    returned with findings unchanged and a `triage.error` note, so a flaky
    response degrades gracefully instead of losing the scan.
    """
    if not report.get("findings"):
        out = dict(report)
        out["triage"] = {"provider": provider.name, "model": provider.model,
                         "summary": "No findings to triage.", "enriched": False}
        return out

    system = SYSTEM_PROMPT
    user = build_user_prompt(report)

    last_error = ""
    for attempt in range(retries + 1):
        try:
            raw = provider.complete(system, user)
            parsed = _extract_json(raw)
            parsed["_provider"] = provider.name
            parsed["_model"] = provider.model
            return _merge(report, parsed)
        except (ValueError, json.JSONDecodeError) as exc:
            last_error = str(exc)
            log.warning("Triage response did not parse (attempt %d): %s", attempt + 1, last_error)

    # Graceful degradation: keep the scan, note that enrichment failed.
    out = dict(report)
    out["triage"] = {
        "provider": provider.name, "model": provider.model, "enriched": False,
        "error": f"LLM response could not be parsed as JSON after {retries + 1} attempts: {last_error}",
    }
    return out
