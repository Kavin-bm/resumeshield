"""LangChain document loader integration for safely ingesting resumes."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from resumeshield.models import ScanResult, Verdict
from resumeshield.shield import Shield


class PromptInjectionDetectedError(ValueError):
    """Raised when a malicious prompt injection payload is found in a loaded document."""

    def __init__(self, message: str, result: ScanResult) -> None:
        super().__init__(message)
        self.result = result


@dataclass
class Document:
    """Document representation compatible with LangChain and LlamaIndex."""

    page_content: str
    metadata: dict[str, Any] = field(default_factory=dict)


class ResumeShieldPDFLoader:
    """Safe document loader that validates and sanitizes resume PDFs before feeding LLM chains."""

    def __init__(
        self,
        file_path: str | Path,
        shield: Shield | None = None,
        reject_malicious: bool = True,
    ) -> None:
        self.file_path = Path(file_path)
        self.shield = shield or Shield.default()
        self.reject_malicious = reject_malicious

    def load(self) -> list[Document]:
        """Load and sanitize document into a Document object."""
        return list(self.lazy_load())

    def lazy_load(self) -> Iterator[Document]:
        """Lazy load and screen the document."""
        data = self.file_path.read_bytes()
        result = self.shield.scan(data, filename=self.file_path.name)

        if self.reject_malicious and result.verdict == Verdict.MALICIOUS:
            raise PromptInjectionDetectedError(
                f"Malicious prompt injection detected in {self.file_path.name} (Risk Score: {result.risk_score}).",
                result=result,
            )

        metadata = {
            "source": str(self.file_path),
            "filename": self.file_path.name,
            "resumeshield_verdict": str(result.verdict),
            "resumeshield_risk_score": result.risk_score,
            "resumeshield_findings_count": len(result.findings),
            "pages": result.pages,
        }

        yield Document(
            page_content=result.sanitized_text,
            metadata=metadata,
        )
