"""ResumeShield: Detects and neutralizes prompt-injection payloads in resumes."""
from resumeshield.config import ShieldConfig
from resumeshield.context import DocumentContext
from resumeshield.detectors.base import (
    BaseDetector,
    FunctionalDetector,
    PatternDetector,
    SemanticModelDetector,
    Stage,
)
from resumeshield.integrations.fastapi import ResumeShieldGuard
from resumeshield.integrations.langchain import ResumeShieldPDFLoader
from resumeshield.models import (
    Category,
    Finding,
    ScanResult,
    Severity,
    Verdict,
)
from resumeshield.registry import DetectorRegistry, default_registry
from resumeshield.scanner import scan_file, scan_pdf
from resumeshield.shield import Shield

__version__ = "0.2.0"

__all__ = [
    "BaseDetector",
    "Category",
    "DetectorRegistry",
    "DocumentContext",
    "Finding",
    "FunctionalDetector",
    "PatternDetector",
    "ResumeShieldGuard",
    "ResumeShieldPDFLoader",
    "ScanResult",
    "SemanticModelDetector",
    "Severity",
    "Shield",
    "ShieldConfig",
    "Stage",
    "Verdict",
    "default_registry",
    "scan_file",
    "scan_pdf",
]
