"""Document context shared across all detection stages."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import pymupdf

    from resumeshield.models import Finding


@dataclass
class DocumentContext:
    """Carries the state and extracted streams of a document during a scan."""

    data: bytes
    filename: str = "resume.pdf"
    doc: pymupdf.Document | None = None
    visible_text: str = ""
    hidden_text: str = ""
    metadata_text: str = ""
    divergent_text: str = ""
    extractor_texts: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def concealed_text(self) -> str:
        """Superset of all text concealed from human view."""
        return "\n".join(
            filter(None, [self.hidden_text, self.metadata_text, self.divergent_text])
        )

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_findings(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)
