"""Main SDK facade: Shield class for embedding ResumeShield in any Python application."""
from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, Callable

from resumeshield.config import ShieldConfig
from resumeshield.context import DocumentContext
from resumeshield.detectors.base import (
    BaseDetector,
    FunctionalDetector,
    PatternDetector,
    SemanticModelDetector,
    Stage,
)
from resumeshield.models import Category, Finding, ScanResult, Severity
from resumeshield.registry import DetectorRegistry, default_registry
from resumeshield.scanner import scan_pdf


class Shield:
    """Primary developer interface for scanning and sanitizing resumes."""

    def __init__(
        self,
        config: ShieldConfig | None = None,
        registry: DetectorRegistry | None = None,
    ) -> None:
        self.config = config or ShieldConfig.from_env()
        self.registry = registry if registry is not None else default_registry.clone()
        self.registry.apply_config(self.config)

    @classmethod
    def default(cls) -> Shield:
        """Create a Shield instance with default configuration and detectors."""
        return cls()

    @classmethod
    def from_config_file(cls, path: str | Path) -> Shield:
        """Create a Shield instance initialized from a YAML or JSON configuration file."""
        config = ShieldConfig.from_file(path)
        return cls(config=config)

    def _read_target(self, target: bytes | str | Path | BinaryIO, filename: str | None) -> tuple[bytes, str]:
        if isinstance(target, bytes):
            return target, filename or "resume.pdf"
        if isinstance(target, (str, Path)):
            path = Path(target)
            return path.read_bytes(), filename or path.name
        if hasattr(target, "read"):
            data = target.read()
            if isinstance(data, str):
                data = data.encode("utf-8")
            name = filename or getattr(target, "name", "resume.pdf")
            return data, Path(name).name
        raise TypeError(f"Unsupported target type: {type(target)}. Expected bytes, str, Path, or file-like object.")

    def scan(
        self,
        target: bytes | str | Path | BinaryIO,
        filename: str | None = None,
        render: bool = False,
        differential_screening: bool = False,
    ) -> ScanResult:
        """Scan a resume document for prompt-injection payloads."""
        data, name = self._read_target(target, filename)
        return scan_pdf(
            data=data,
            filename=name,
            render=render,
            differential_screening=differential_screening or self.config.enable_differential,
            config=self.config,
            registry=self.registry,
        )

    def sanitize(
        self,
        target: bytes | str | Path | BinaryIO,
        filename: str | None = None,
    ) -> str:
        """Scan a resume and return only the screening-safe sanitized text."""
        result = self.scan(target, filename=filename, render=False)
        return result.sanitized_text

    def add_detector(self, detector: BaseDetector) -> None:
        """Register a custom detector instance."""
        self.registry.register(detector)

    def add_pattern(
        self,
        pattern: str,
        severity: Severity = Severity.HIGH,
        message: str = "Suspicious prompt-injection pattern detected.",
        name: str | None = None,
        category: Category = Category.SEMANTIC_INJECTION,
    ) -> PatternDetector:
        """Add a single custom regex pattern detector."""
        det_name = name or f"custom_pattern_{abs(hash(pattern)) % 10000}"
        detector = PatternDetector(
            name=det_name,
            rules=[(pattern, severity, message)],
            category=category,
        )
        self.registry.register(detector)
        return detector

    def add_rule(
        self,
        name: str,
        func: Callable[[DocumentContext], list[Finding]],
        category: Category = Category.SEMANTIC_INJECTION,
        stage: Stage = Stage.CUSTOM,
    ) -> FunctionalDetector:
        """Add an arbitrary Python function rule."""
        return self.registry.add_custom_rule(name=name, func=func, category=category, stage=stage)

    def add_model_classifier(
        self,
        name: str,
        classifier: Callable[[str], list[tuple[str, float]]],
        threshold: float = 0.7,
        category: Category = Category.SEMANTIC_INJECTION,
    ) -> SemanticModelDetector:
        """Attach a custom ML or LLM classifier."""
        detector = SemanticModelDetector(
            name=name,
            classifier=classifier,
            threshold=threshold,
            category=category,
        )
        self.registry.register(detector)
        return detector

    def disable_detector(self, name: str) -> None:
        """Disable a specific detector by name."""
        det = self.registry.get(name)
        if det:
            det.enabled = False
