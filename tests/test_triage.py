"""Tests for the Phase 3 LLM triage layer.

No real network calls: a FakeProvider stands in for the LLM so we test the
prompt, parsing, merging, ranking, graceful-skip and report writing
deterministically. These tests don't need the anthropic/openai packages.
"""

from __future__ import annotations

import json

import pytest

from scanner.triage.engine import _extract_json, triage_report
from scanner.triage.providers import LLMProvider, MissingAPIKey, TriageError, build_provider, load_dotenv
from scanner.triage.report import build_markdown
from scanner.triage.runner import run_triage


class FakeProvider(LLMProvider):
    """Returns a canned reply (or raises) without touching the network."""
    name = "fake"

    def __init__(self, reply="", model="fake-model", error=None):
        super().__init__(model=model)
        self._reply = reply
        self._error = error

    def complete(self, system, user):
        if self._error:
            raise self._error
        return self._reply


def sample_report():
    return {
        "scanner": {"name": "webvuln-scanner", "mode": "active+passive"},
        "target": "http://localhost:3000",
        "findings": [
            {"id": "SQLI-1", "rule_id": "ACTIVE_SQLI_ERROR", "check": "sql_injection",
             "severity": "high", "title": "SQLi via q", "url": "http://localhost:3000/search?q=",
             "description": "...", "evidence": "SQLITE_ERROR", "payload": "'\"",
             "confidence": "confirmed", "affected_urls": ["http://localhost:3000/search?q="]},
            {"id": "CSP-1", "rule_id": "HEADER_CSP_MISSING", "check": "security_headers",
             "severity": "medium", "title": "CSP missing", "url": "http://localhost:3000/",
             "description": "...", "evidence": "", "payload": "", "confidence": "confirmed",
             "affected_urls": ["http://localhost:3000/"]},
        ],
    }


def llm_reply():
    return json.dumps({
        "summary": "One confirmed SQLi dominates risk; the header issue is minor.",
        "findings": {
            "SQLI-1": {"adjusted_severity": "critical", "severity_reason": "Confirmed DB error, full data exposure.",
                       "likely_false_positive": False, "false_positive_reason": "",
                       "duplicate_of": "", "explanation": "Attacker-controlled SQL.",
                       "example_fix": "Use parameterised queries."},
            "CSP-1": {"adjusted_severity": "low", "severity_reason": "Defence-in-depth only.",
                      "likely_false_positive": False, "false_positive_reason": "",
                      "duplicate_of": "", "explanation": "No CSP header.",
                      "example_fix": "Add Content-Security-Policy."},
        },
    })


# ----------------------------------------------------------- JSON extraction
def test_extract_json_plain():
    assert _extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_with_fence_and_prose():
    assert _extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert _extract_json('Here you go:\n{"a": 1}\nHope that helps') == {"a": 1}


def test_extract_json_raises_when_absent():
    with pytest.raises(ValueError):
        _extract_json("no json here")


# ------------------------------------------------------------- enrichment
def test_triage_merges_and_reranks():
    enriched = triage_report(sample_report(), FakeProvider(reply=llm_reply()))
    assert enriched["triage"]["enriched"] is True
    # SQLi re-ranked up to critical, CSP down to low; order reflects that.
    assert [f["id"] for f in enriched["findings"]] == ["SQLI-1", "CSP-1"]
    sqli = enriched["findings"][0]
    assert sqli["triage"]["adjusted_severity"] == "critical"
    assert sqli["severity"] == "high"  # original label preserved (additive)
    assert "parameterised" in sqli["triage"]["example_fix"]


def test_false_positives_sink_to_bottom():
    reply = json.loads(llm_reply())
    reply["findings"]["SQLI-1"]["likely_false_positive"] = True
    enriched = triage_report(sample_report(), FakeProvider(reply=json.dumps(reply)))
    # Even though SQLi is "critical", being a likely FP sorts it last.
    assert enriched["findings"][-1]["id"] == "SQLI-1"


def test_bad_llm_reply_degrades_gracefully():
    enriched = triage_report(sample_report(), FakeProvider(reply="not json"), retries=1)
    assert enriched["triage"]["enriched"] is False
    assert "error" in enriched["triage"]
    # Findings are preserved unchanged, not lost.
    assert {f["id"] for f in enriched["findings"]} == {"SQLI-1", "CSP-1"}


def test_provider_api_error_becomes_triage_error():
    # A vendor SDK failure (e.g. Gemini's 503 "high demand") must surface as a
    # clean TriageError the runner can report -- not an unhandled traceback.
    with pytest.raises(TriageError, match="API call failed"):
        triage_report(sample_report(), FakeProvider(error=RuntimeError("503 UNAVAILABLE")))


def test_markdown_renders_rerank_and_summary():
    enriched = triage_report(sample_report(), FakeProvider(reply=llm_reply()))
    md = build_markdown(enriched)
    assert "# Triage report" in md
    assert "scanner said *high*" in md   # shows the re-rank
    assert "parameterised queries" in md


# ------------------------------------------------------------- key handling
def test_build_provider_missing_key_raises(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(MissingAPIKey) as exc:
        build_provider("anthropic")
    assert exc.value.env_var == "ANTHROPIC_API_KEY"


def test_build_provider_unknown_provider(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    with pytest.raises(TriageError):
        build_provider("not-a-provider")


def test_build_provider_gemini_missing_key_raises(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(MissingAPIKey) as exc:
        build_provider("gemini")
    assert exc.value.env_var == "GEMINI_API_KEY"


def test_build_provider_gemini_with_key(monkeypatch):
    # With the key present, build_provider returns a Gemini provider using the
    # current stable Flash model by default -- and never imports the SDK or hits
    # the network (that only happens inside complete()).
    monkeypatch.setenv("GEMINI_API_KEY", "x")
    provider = build_provider("gemini")
    assert provider.name == "gemini"
    assert provider.model == "gemini-3.8-flash"
    assert build_provider("gemini", model="gemini-3.6-flash").model == "gemini-3.6-flash"


def test_run_triage_skips_without_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    ran = run_triage(sample_report(), tmp_path / "r.json", dotenv_path=tmp_path / "nope.env")
    assert ran is False
    assert "Skipping triage" in capsys.readouterr().err
    assert not (tmp_path / "r.triaged.json").exists()  # nothing written, nothing sent


def test_load_dotenv_does_not_override(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text('ANTHROPIC_API_KEY="from-file"\n# comment\nOTHER=value\n')
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-real-env")
    loaded = load_dotenv(env)
    import os
    assert os.environ["ANTHROPIC_API_KEY"] == "from-real-env"  # real env wins
    assert os.environ["OTHER"] == "value"
    assert "OTHER" in loaded
