"""Detector registry for dynamically managing built-in and custom detectors."""
from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Callable

from resumeshield.detectors import (
    extractor_divergence,
    injection_patterns,
    normalization,
    pdf_metadata,
    pdf_structure,
    unicode_tricks,
)
from resumeshield.detectors.base import BaseDetector, FunctionalDetector, PatternDetector, Stage
from resumeshield.models import Category, Finding, Severity

if TYPE_CHECKING:
    from resumeshield.config import ShieldConfig
    from resumeshield.context import DocumentContext


class BuiltinStructureDetector(BaseDetector):
    name = "pdf_structure"
    category = Category.HIDDEN_TEXT
    stage = Stage.STRUCTURE

    def analyze(self, ctx: DocumentContext) -> list[Finding]:
        if ctx.doc is None:
            return []
        findings, visible, hidden = pdf_structure.analyze(ctx.doc)
        ctx.visible_text = visible
        ctx.hidden_text = hidden
        return findings


class BuiltinMetadataDetector(BaseDetector):
    name = "pdf_metadata"
    category = Category.METADATA
    stage = Stage.METADATA

    def analyze(self, ctx: DocumentContext) -> list[Finding]:
        if ctx.doc is None:
            return []
        findings, meta_text = pdf_metadata.analyze(ctx.doc)
        ctx.metadata_text = meta_text
        return findings


class BuiltinDivergenceDetector(BaseDetector):
    name = "extractor_divergence"
    category = Category.HIDDEN_TEXT
    stage = Stage.DIVERGENCE

    def analyze(self, ctx: DocumentContext) -> list[Finding]:
        findings, extractor_texts = extractor_divergence.analyze(ctx.data)
        ctx.extractor_texts = extractor_texts
        ctx.divergent_text = " ".join(f.evidence for f in findings)
        return findings


class BuiltinUnicodeDetector(BaseDetector):
    name = "unicode_tricks"
    category = Category.UNICODE_TRICK
    stage = Stage.ENCODING

    def analyze(self, ctx: DocumentContext) -> list[Finding]:
        findings = []
        if ctx.visible_text:
            findings.extend(unicode_tricks.analyze(ctx.visible_text, source="visible"))
        if ctx.concealed_text:
            findings.extend(unicode_tricks.analyze(ctx.concealed_text, source="hidden"))
        return findings


class BuiltinNormalizationDetector(BaseDetector):
    name = "normalization"
    category = Category.UNICODE_TRICK
    stage = Stage.ENCODING

    def analyze(self, ctx: DocumentContext) -> list[Finding]:
        findings = []
        if ctx.visible_text:
            findings.extend(normalization.analyze(ctx.visible_text, source="visible"))
        if ctx.concealed_text:
            findings.extend(normalization.analyze(ctx.concealed_text, source="hidden"))
        return findings


class BuiltinInjectionDetector(BaseDetector):
    name = "injection_patterns"
    category = Category.SEMANTIC_INJECTION
    stage = Stage.INSTRUCTION

    def analyze(self, ctx: DocumentContext) -> list[Finding]:
        findings = []
        if ctx.visible_text:
            findings.extend(injection_patterns.analyze(ctx.visible_text, source="visible"))
        if ctx.hidden_text:
            findings.extend(injection_patterns.analyze(ctx.hidden_text, source="hidden"))
        if ctx.metadata_text:
            findings.extend(injection_patterns.analyze(ctx.metadata_text, source="metadata"))
        if ctx.divergent_text:
            findings.extend(injection_patterns.analyze(ctx.divergent_text, source="hidden"))
        return findings


class DetectorRegistry:
    """Central registry of detectors."""

    def __init__(self, load_defaults: bool = True) -> None:
        self._detectors: dict[str, BaseDetector] = {}
        if load_defaults:
            self._register_defaults()

    def _register_defaults(self) -> None:
        defaults: list[BaseDetector] = [
            BuiltinStructureDetector(),
            BuiltinMetadataDetector(),
            BuiltinDivergenceDetector(),
            BuiltinUnicodeDetector(),
            BuiltinNormalizationDetector(),
            BuiltinInjectionDetector(),
        ]
        for detector in defaults:
            self.register(detector)

    def register(self, detector: BaseDetector, overwrite: bool = True) -> None:
        """Register a detector instance."""
        if not overwrite and detector.name in self._detectors:
            raise ValueError(f"Detector '{detector.name}' already registered.")
        self._detectors[detector.name] = detector

    def unregister(self, name: str) -> BaseDetector | None:
        """Remove a detector by name."""
        return self._detectors.pop(name, None)

    def get(self, name: str) -> BaseDetector | None:
        return self._detectors.get(name)

    def list_detectors(self) -> list[BaseDetector]:
        return list(self._detectors.values())

    def add_custom_rule(
        self,
        name: str,
        func: Callable[[DocumentContext], list[Finding]],
        category: Category = Category.SEMANTIC_INJECTION,
        stage: Stage = Stage.CUSTOM,
    ) -> FunctionalDetector:
        detector = FunctionalDetector(name=name, func=func, category=category, stage=stage)
        self.register(detector)
        return detector

    def add_pattern_detector(
        self,
        name: str,
        rules: list[tuple[str, Severity, str] | str],
        category: Category = Category.SEMANTIC_INJECTION,
    ) -> PatternDetector:
        detector = PatternDetector(name=name, rules=rules, category=category)
        self.register(detector)
        return detector

    def apply_config(self, config: ShieldConfig) -> None:
        """Apply disabled detectors and custom patterns from configuration."""
        for name in config.disabled_detectors:
            if name in self._detectors:
                self._detectors[name].enabled = False

        if config.custom_patterns:
            rules = []
            for item in config.custom_patterns:
                sev = Severity(item.get("severity", "high"))
                rules.append((item["pattern"], sev, item.get("message", "Custom pattern detected.")))
            self.add_pattern_detector(name="config_custom_patterns", rules=rules)

    def clone(self) -> DetectorRegistry:
        """Create an independent copy of this registry."""
        registry = DetectorRegistry(load_defaults=False)
        for name, d in self._detectors.items():
            registry.register(copy.copy(d))
        return registry


# Global default registry instance
default_registry = DetectorRegistry()
