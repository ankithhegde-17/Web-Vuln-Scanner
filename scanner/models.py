"""Data models shared by the crawler, the checks and the reporters.

Using dataclasses (instead of loose dicts) gives us one place that defines
the shape of the JSON output. A later phase that feeds findings to an LLM
can rely on these exact field names.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Severity levels, ordered from least to most serious.

    Inheriting from `str` makes the enum serialise to JSON as a plain string
    ("high") without a custom encoder.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        """Numeric rank used for sorting (higher = more serious)."""
        return ["info", "low", "medium", "high"].index(self.value)


@dataclass
class Finding:
    """One security issue discovered by a check.

    rule_id     Stable identifier for the *type* of issue, e.g.
                "HEADER_CSP_MISSING". Same issue type = same rule_id.
    id          Unique identifier for *this* finding. Derived from rule_id and
                a dedup key, so re-running a scan produces the same ids, which
                makes it easy to diff two scans.
    url         The first URL where the issue was seen.
    affected_urls  Every URL where the same issue was seen (filled in when
                findings are de-duplicated, see FindingCollector).
    evidence    The raw observation that triggered the finding (a header
                value, a status code). Never contains secret values such as
                cookie contents.
    confidence  "confirmed" when the evidence is unambiguous, "tentative" when
                a human (or the LLM phase) should double-check it.
    """

    rule_id: str
    check: str
    severity: Severity
    title: str
    url: str
    description: str
    remediation: str
    evidence: str = ""
    confidence: str = "confirmed"
    # Extra key used for de-duplication, e.g. the cookie name for cookie
    # findings, so two different insecure cookies are two separate findings.
    dedup_key: str = ""
    affected_urls: list[str] = field(default_factory=list)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.affected_urls:
            self.affected_urls = [self.url]
        if not self.id:
            digest = hashlib.sha1(f"{self.rule_id}|{self.dedup_key}".encode()).hexdigest()
            self.id = f"{self.rule_id}-{digest[:8]}"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.value
        data.pop("dedup_key")  # internal detail, not useful in the report
        return data


@dataclass
class FormField:
    name: str
    field_type: str  # "text", "password", "hidden", "select", "textarea", ...
    value: str = ""  # default value present in the HTML, if any


@dataclass
class Form:
    page_url: str  # page on which the form was found
    action: str    # absolute URL the form submits to
    method: str    # "GET" or "POST"
    fields: list[FormField] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Page:
    url: str
    status_code: int
    depth: int
    content_type: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class FindingCollector:
    """Gathers findings and merges duplicates.

    Without this, a site with 50 pages that is missing a CSP header would
    produce 50 identical findings. Instead we keep one finding per
    (rule_id, dedup_key) and record every affected URL on it.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, Finding] = {}

    def add(self, finding: Finding) -> None:
        existing = self._by_id.get(finding.id)
        if existing is None:
            self._by_id[finding.id] = finding
        elif finding.url not in existing.affected_urls:
            existing.affected_urls.append(finding.url)

    def extend(self, findings: list[Finding]) -> None:
        for f in findings:
            self.add(f)

    def all(self) -> list[Finding]:
        """Findings sorted most severe first, then by rule id."""
        return sorted(self._by_id.values(), key=lambda f: (-f.severity.rank, f.rule_id))
