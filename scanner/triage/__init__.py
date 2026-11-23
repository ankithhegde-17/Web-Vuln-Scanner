"""Phase 3: an optional LLM triage layer.

This package takes the JSON findings from a scan and asks a large language
model to (1) re-rank them by real-world severity, (2) flag likely false
positives and duplicates, and (3) write a plain-language remediation note.

It is strictly opt-in. A normal scan never imports or calls anything here;
triage runs only when the user asks for it (the `--triage` flag or
`python -m scanner.triage`). Nothing is sent to an LLM unless triage is
explicitly invoked AND an API key is configured.
"""

from scanner.triage.providers import (
    MissingAPIKey,
    TriageError,
    build_provider,
    load_dotenv,
)

__all__ = ["MissingAPIKey", "TriageError", "build_provider", "load_dotenv"]
