"""Core types shared by every detector and the API.

A scan produces Findings; Findings aggregate into a ScanResult with a
verdict. Detectors never decide the overall verdict themselves — they only
report what they saw and how confident they are. Aggregation lives in one
place (scanner.py) so the risk policy is auditable and tunable rather than
smeared across detectors.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 25,
    Severity.HIGH: 45,
    Severity.CRITICAL: 70,
}


class Verdict(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Category(StrEnum):
    """What kind of problem this is — drives the UI grouping and the
    remediation text. Kept coarse on purpose; the detector name carries
    the specifics.
    """

    HIDDEN_TEXT = "hidden_text"          # visually concealed from a human reader
    UNICODE_TRICK = "unicode_trick"      # zero-width, bidi, homoglyphs
    METADATA = "metadata"                # payload outside the visible body
    SEMANTIC_INJECTION = "semantic_injection"  # instructions aimed at an AI reader


@dataclass
class Finding:
    """One thing a detector noticed.

    `evidence` is the offending text itself — it's what makes the report
    convincing ("here is the sentence that was hidden from you"), and what
    the sanitizer strips. `page`/`bbox` are optional because non-visual
    detectors (metadata, unicode) have no location on the page; when
    present they let the UI draw a box over the rendered page.
    """

    detector: str
    category: Category
    severity: Severity
    message: str
    evidence: str = ""
    page: int | None = None
    bbox: tuple[float, float, float, float] | None = None
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["category"] = str(self.category)
        data["severity"] = str(self.severity)
        return data


@dataclass
class ScanResult:
    filename: str
    verdict: Verdict = Verdict.CLEAN
    risk_score: int = 0
    findings: list[Finding] = field(default_factory=list)
    visible_text: str = ""
    hidden_text: str = ""
    sanitized_text: str = ""
    pages: int = 0
    errors: list[str] = field(default_factory=list)
    rendered_pages: list[dict] = field(default_factory=list)
    # Per-library extraction, so a report can show which tool saw what.
    extractor_texts: dict[str, str] = field(default_factory=dict)
    differential: dict = field(default_factory=dict)

    @property
    def is_clean(self) -> bool:
        return self.verdict is Verdict.CLEAN

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "verdict": str(self.verdict),
            "risk_score": self.risk_score,
            "pages": self.pages,
            "findings": [f.to_dict() for f in self.findings],
            "visible_text": self.visible_text,
            "hidden_text": self.hidden_text,
            "sanitized_text": self.sanitized_text,
            "errors": self.errors,
            "rendered_pages": self.rendered_pages,
            "extractor_texts": self.extractor_texts,
            "differential": self.differential,
        }
