"""Base contracts and helper classes for pluggable detectors."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Callable

from resumeshield.context import DocumentContext
from resumeshield.models import Category, Finding, Severity


class Stage(StrEnum):
    """Execution stages in the scanning pipeline."""

    STRUCTURE = "structure"
    METADATA = "metadata"
    DIVERGENCE = "divergence"
    ENCODING = "encoding"
    INSTRUCTION = "instruction"
    CUSTOM = "custom"
    POST = "post"


@dataclass
class PatternRule:
    """A single regex pattern rule."""

    pattern: str
    severity: Severity = Severity.HIGH
    message: str = "Suspicious prompt-injection pattern detected."
    regex: re.Pattern = field(init=False)

    def __post_init__(self) -> None:
        self.regex = re.compile(self.pattern, re.IGNORECASE)


class BaseDetector(ABC):
    """Abstract base class for all detection modules."""

    name: str
    category: Category = Category.SEMANTIC_INJECTION
    stage: Stage = Stage.CUSTOM
    enabled: bool = True

    @abstractmethod
    def analyze(self, ctx: DocumentContext) -> list[Finding]:
        """Inspect the document context and return findings."""
        raise NotImplementedError


class PatternDetector(BaseDetector):
    """Configurable regex-based pattern detector for instructions or keywords."""

    def __init__(
        self,
        name: str,
        rules: list[tuple[str, Severity, str] | PatternRule | str],
        category: Category = Category.SEMANTIC_INJECTION,
        stage: Stage = Stage.INSTRUCTION,
        scan_visible: bool = True,
        scan_concealed: bool = True,
    ) -> None:
        self.name = name
        self.category = category
        self.stage = stage
        self.scan_visible = scan_visible
        self.scan_concealed = scan_concealed

        self.rules: list[PatternRule] = []
        for rule in rules:
            if isinstance(rule, PatternRule):
                self.rules.append(rule)
            elif isinstance(rule, tuple):
                self.rules.append(PatternRule(pattern=rule[0], severity=rule[1], message=rule[2]))
            elif isinstance(rule, str):
                self.rules.append(PatternRule(pattern=rule))

    def _scan_stream(self, text: str, source: str) -> list[Finding]:
        if not text or not text.strip():
            return []

        findings: list[Finding] = []
        seen_spans: list[tuple[int, int]] = []

        for rule in self.rules:
            for match in rule.regex.finditer(text):
                start, end = match.span()
                if any(start < s_end and end > s_start for s_start, s_end in seen_spans):
                    continue
                seen_spans.append((start, end))

                lo, hi = max(0, start - 60), min(len(text), end + 60)
                evidence = " ".join(text[lo:hi].split())

                findings.append(
                    Finding(
                        detector=self.name,
                        category=self.category,
                        severity=rule.severity,
                        message=rule.message,
                        evidence=evidence,
                        detail={"matched": match.group(0), "source": source},
                    )
                )
        return findings

    def analyze(self, ctx: DocumentContext) -> list[Finding]:
        findings: list[Finding] = []
        if self.scan_visible and ctx.visible_text:
            findings.extend(self._scan_stream(ctx.visible_text, source="visible"))
        if self.scan_concealed:
            if ctx.hidden_text:
                findings.extend(self._scan_stream(ctx.hidden_text, source="hidden"))
            if ctx.metadata_text:
                findings.extend(self._scan_stream(ctx.metadata_text, source="metadata"))
            if ctx.divergent_text:
                findings.extend(self._scan_stream(ctx.divergent_text, source="hidden"))
        return findings


class FunctionalDetector(BaseDetector):
    """Wraps an arbitrary Python callable into a BaseDetector."""

    def __init__(
        self,
        name: str,
        func: Callable[[DocumentContext], list[Finding]],
        category: Category = Category.SEMANTIC_INJECTION,
        stage: Stage = Stage.CUSTOM,
    ) -> None:
        self.name = name
        self.func = func
        self.category = category
        self.stage = stage

    def analyze(self, ctx: DocumentContext) -> list[Finding]:
        return self.func(ctx)


class SemanticModelDetector(BaseDetector):
    """Detector for user-supplied ML or LLM semantic classifiers."""

    def __init__(
        self,
        name: str,
        classifier: Callable[[str], list[tuple[str, float]]],
        threshold: float = 0.7,
        category: Category = Category.SEMANTIC_INJECTION,
        stage: Stage = Stage.CUSTOM,
    ) -> None:
        self.name = name
        self.classifier = classifier
        self.threshold = threshold
        self.category = category
        self.stage = stage

    def analyze(self, ctx: DocumentContext) -> list[Finding]:
        findings: list[Finding] = []
        targets = [
            (ctx.visible_text, "visible"),
            (ctx.concealed_text, "hidden"),
        ]

        for text, source in targets:
            if not text or not text.strip():
                continue
            try:
                results = self.classifier(text)
                for label, score in results:
                    if score >= self.threshold:
                        findings.append(
                            Finding(
                                detector=self.name,
                                category=self.category,
                                severity=Severity.CRITICAL if source == "hidden" else Severity.HIGH,
                                message=f"Semantic classifier flagged '{label}' (confidence: {score:.2f})",
                                evidence=" ".join(text[:120].split()),
                                detail={"label": label, "score": score, "source": source},
                            )
                        )
            except Exception as exc:  # noqa: BLE001
                # Custom classifier exceptions should not break the whole scan
                findings.append(
                    Finding(
                        detector=self.name,
                        category=self.category,
                        severity=Severity.INFO,
                        message=f"Classifier execution error: {exc}",
                        detail={"error": str(exc)},
                    )
                )
        return findings
