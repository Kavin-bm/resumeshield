"""Runs every detector over a document and aggregates one verdict.

Detectors deliberately don't decide the verdict — they report observations.
Aggregation lives here alone so the risk policy is one auditable function
rather than logic smeared across five modules.

The policy's central rule: **concealment and instruction are much worse
together than apart.** Hidden text on its own is often benign (leftover
template text, a white logo caption). Instruction-like text on its own can
be an unlucky phrasing. Instruction-like text that someone took the
trouble to hide is deliberate, and that combination is what earns a
`malicious` verdict.
"""
from __future__ import annotations

import io
from pathlib import Path

import pymupdf

from resumeshield.detectors import (
    injection_patterns,
    pdf_metadata,
    pdf_structure,
    unicode_tricks,
)
from resumeshield.models import (
    SEVERITY_WEIGHT,
    Category,
    Finding,
    ScanResult,
    Severity,
    Verdict,
)

MALICIOUS_SCORE = 60
SUSPICIOUS_SCORE = 15


def _escalate_hidden_injections(findings: list[Finding]) -> list[Finding]:
    """Instruction text that was also concealed is upgraded to critical."""
    for finding in findings:
        if (
            finding.category is Category.SEMANTIC_INJECTION
            and finding.detail.get("source") in ("hidden", "metadata")
            and finding.severity is not Severity.CRITICAL
        ):
            finding.severity = Severity.CRITICAL
            finding.message += " This text was also concealed from human readers."
    return findings


def _score(findings: list[Finding]) -> int:
    """Severity of the worst finding, nudged up by corroborating ones.

    Deliberately not a sum: summing saturates at the cap the moment a
    document trips two serious checks, which collapses the score into a
    0-or-100 flag and makes it useless for triaging a stack of resumes by
    priority. Anchoring on the worst finding keeps the number meaningful.
    """
    if not findings:
        return 0
    worst = max(SEVERITY_WEIGHT[f.severity] for f in findings)
    return min(100, worst + 5 * (len(findings) - 1))


def _decide(findings: list[Finding]) -> tuple[Verdict, int]:
    score = _score(findings)

    concealed = any(
        f.category in (Category.HIDDEN_TEXT, Category.UNICODE_TRICK, Category.METADATA)
        for f in findings
    )
    instructing = any(f.category is Category.SEMANTIC_INJECTION for f in findings)
    has_critical = any(f.severity is Severity.CRITICAL for f in findings)

    # Unambiguous injection phrasing is an attack whether or not it was
    # hidden — a resume has no legitimate reason to address its reader.
    if has_critical or (concealed and instructing) or score >= MALICIOUS_SCORE:
        return Verdict.MALICIOUS, max(score, MALICIOUS_SCORE)
    if score >= SUSPICIOUS_SCORE or concealed or instructing:
        return Verdict.SUSPICIOUS, max(score, SUSPICIOUS_SCORE)
    return Verdict.CLEAN, score


def _sanitize(visible_text: str, findings: list[Finding]) -> str:
    """Produce text that's safe to hand to a downstream LLM screener.

    Starts from visible text only — anything concealed is dropped wholesale
    rather than filtered, since a human reviewer was never meant to see it.
    Remaining injection phrases found in visible text are redacted in place
    so the screener still gets the genuine resume content around them.
    """
    clean = unicode_tricks.strip_invisible(visible_text)

    for finding in findings:
        if finding.category is not Category.SEMANTIC_INJECTION:
            continue
        matched = finding.detail.get("matched")
        if matched and matched in clean:
            clean = clean.replace(matched, "[REDACTED: suspected prompt injection]")

    return " ".join(clean.split())


def scan_pdf(data: bytes, filename: str = "resume.pdf") -> ScanResult:
    result = ScanResult(filename=filename)

    try:
        doc = pymupdf.open(stream=io.BytesIO(data), filetype="pdf")
    except Exception as exc:  # noqa: BLE001 - a corrupt upload is user input, not a crash
        result.errors.append(f"Could not open PDF: {exc}")
        result.verdict = Verdict.SUSPICIOUS
        return result

    try:
        result.pages = doc.page_count

        structure_findings, visible_text, hidden_text = pdf_structure.analyze(doc)
        metadata_findings, metadata_text = pdf_metadata.analyze(doc)

        findings = [*structure_findings, *metadata_findings]

        # Character-level checks run over everything extracted.
        findings += unicode_tricks.analyze(visible_text, source="visible")
        findings += unicode_tricks.analyze(hidden_text, source="hidden")

        # Instruction checks, tagged by where the text was found so the
        # aggregation step can escalate concealed instructions.
        findings += injection_patterns.analyze(visible_text, source="visible")
        findings += injection_patterns.analyze(hidden_text, source="hidden")
        findings += injection_patterns.analyze(metadata_text, source="metadata")

        findings = _escalate_hidden_injections(findings)

        result.findings = findings
        result.visible_text = " ".join(visible_text.split())
        result.hidden_text = " ".join((hidden_text + "\n" + metadata_text).split())
        result.sanitized_text = _sanitize(visible_text, findings)
        result.verdict, result.risk_score = _decide(findings)
    finally:
        doc.close()

    return result


def scan_file(path: str | Path) -> ScanResult:
    path = Path(path)
    return scan_pdf(path.read_bytes(), filename=path.name)
