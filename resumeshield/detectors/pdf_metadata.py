"""Payloads hiding outside the page body: document metadata, XMP, annotations.

Division of labour worth noting: this module reports *where* text is
hiding, not whether that text is an attack. Deciding "is this an
instruction aimed at an AI reader" is the semantic layer's job. Keeping
those separate means the structural layers stay deterministic and cheap,
and only one component needs an LLM.
"""
from __future__ import annotations

import pymupdf

from resumeshield.models import Category, Finding, Severity

# Fields that legitimately hold prose vs. ones that should hold tool names.
FREEFORM_FIELDS = ("title", "subject", "keywords", "author")
TOOLING_FIELDS = ("creator", "producer")

# Longer than a real title/author, short enough to catch a one-line payload.
SUSPICIOUS_FIELD_CHARS = 60


def _metadata_findings(doc: pymupdf.Document) -> tuple[list[Finding], list[str]]:
    findings, hidden = [], []
    metadata = doc.metadata or {}

    for field in FREEFORM_FIELDS + TOOLING_FIELDS:
        value = (metadata.get(field) or "").strip()
        if len(value) < SUSPICIOUS_FIELD_CHARS:
            continue
        hidden.append(value)
        findings.append(
            Finding(
                detector=f"pdf_metadata.{field}",
                category=Category.METADATA,
                severity=Severity.MEDIUM,
                message=(
                    f"Document metadata field '{field}' holds {len(value)} characters "
                    "of prose — unusual for a resume, and invisible when the document is read."
                ),
                evidence=value,
                detail={"field": field},
            )
        )
    return findings, hidden


def _xmp_findings(doc: pymupdf.Document) -> tuple[list[Finding], list[str]]:
    try:
        xmp = doc.get_xml_metadata()
    except Exception:  # noqa: BLE001 - malformed XMP shouldn't fail a scan
        return [], []
    if not xmp or len(xmp) < SUSPICIOUS_FIELD_CHARS:
        return [], []

    # XMP is normally tool-generated boilerplate; only surface it as hidden
    # text so the semantic layer can judge, without alarming on its own.
    return [], [xmp]


def _annotation_findings(doc: pymupdf.Document) -> tuple[list[Finding], list[str]]:
    findings, hidden = [], []
    for page_index, page in enumerate(doc):
        for annot in page.annots() or []:
            info = annot.info or {}
            content = (info.get("content") or "").strip()
            if not content:
                continue
            hidden.append(content)
            findings.append(
                Finding(
                    detector="pdf_metadata.annotation",
                    category=Category.METADATA,
                    severity=Severity.MEDIUM,
                    message=(
                        "Annotation text is attached to the page. Annotations are not part "
                        "of the printed resume but are picked up by many text extractors."
                    ),
                    evidence=content,
                    page=page_index,
                    detail={"annot_type": annot.type[1] if annot.type else "unknown"},
                )
            )
    return findings, hidden


def analyze(doc: pymupdf.Document) -> tuple[list[Finding], str]:
    """Returns (findings, hidden_text) for non-body payload locations."""
    findings: list[Finding] = []
    hidden: list[str] = []

    for extractor in (_metadata_findings, _xmp_findings, _annotation_findings):
        part_findings, part_hidden = extractor(doc)
        findings.extend(part_findings)
        hidden.extend(part_hidden)

    return findings, "\n".join(hidden)
