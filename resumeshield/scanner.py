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
    extractor_divergence,
    injection_patterns,
    normalization,
    pdf_metadata,
    pdf_structure,
    unicode_tricks,
)
from resumeshield import differential
from resumeshield.models import (
    SEVERITY_WEIGHT,
    Category,
    Finding,
    ScanResult,
    Severity,
    Verdict,
)
from resumeshield.render import render_pages

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


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse the same observation reported by overlapping layers.

    Concealed text reaches the instruction checks by more than one route
    (hidden spans, metadata, extractor divergence), and those streams
    overlap by design. Without this, one payload would be reported three
    times and inflate the score purely for being found thoroughly.
    """
    seen: set[tuple[str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.detector, " ".join(finding.evidence.lower().split())[:160])
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _score(findings: list[Finding]) -> int:
    """Worst finding, raised by *independent* corroboration.

    Two deliberate choices. Not a sum — summing saturates at the cap as
    soon as a document trips two serious checks, collapsing the score into
    a 0-or-100 flag that can't triage a stack of resumes. And the bonus
    counts distinct detection *categories*, not findings, because one
    payload matching six regexes is a single piece of evidence found
    repeatedly, whereas the same payload caught by structural analysis
    *and* parser divergence *and* instruction phrasing is three
    independent confirmations.
    """
    if not findings:
        return 0
    worst = max(SEVERITY_WEIGHT[f.severity] for f in findings)
    independent_categories = len({f.category for f in findings})
    return min(100, worst + 8 * (independent_categories - 1))


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


def scan_pdf(
    data: bytes,
    filename: str = "resume.pdf",
    render: bool = False,
    differential_screening: bool = False,
) -> ScanResult:
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

        # Parser-differential analysis works on the raw bytes, since the
        # whole point is to compare independent PDF implementations.
        divergence_findings, extractor_texts = extractor_divergence.analyze(data)

        findings = [*structure_findings, *metadata_findings, *divergence_findings]

        # Text only some extractors can see counts as concealed for the
        # purposes of instruction analysis below.
        divergent_text = " ".join(f.evidence for f in divergence_findings)
        concealed_text = "\n".join(filter(None, [hidden_text, metadata_text, divergent_text]))

        # Character- and encoding-level checks over everything extracted.
        for text, source in ((visible_text, "visible"), (concealed_text, "hidden")):
            findings += unicode_tricks.analyze(text, source=source)
            findings += normalization.analyze(text, source=source)

        # Instruction checks, tagged by where the text was found so the
        # aggregation step can escalate concealed instructions.
        findings += injection_patterns.analyze(visible_text, source="visible")
        findings += injection_patterns.analyze(hidden_text, source="hidden")
        findings += injection_patterns.analyze(metadata_text, source="metadata")
        findings += injection_patterns.analyze(divergent_text, source="hidden")

        findings = _escalate_hidden_injections(findings)
        findings = _dedupe(findings)
        result.extractor_texts = {
            name: " ".join(text.split())[:4000] for name, text in extractor_texts.items()
        }

        result.findings = findings
        result.visible_text = " ".join(visible_text.split())
        result.hidden_text = " ".join(concealed_text.split())
        result.sanitized_text = _sanitize(visible_text, findings)
        result.verdict, result.risk_score = _decide(findings)

        if render:
            result.rendered_pages = [p.to_dict() for p in render_pages(doc)]

        if differential_screening:
            raw_text = max(extractor_texts.values(), key=len, default="")
            outcome = differential.run(raw_text, result.sanitized_text)
            result.differential = outcome.to_dict()
            if outcome.manipulated:
                result.verdict = Verdict.MALICIOUS
                result.risk_score = max(result.risk_score, MALICIOUS_SCORE)
                result.findings.append(
                    Finding(
                        detector="differential.screening",
                        category=Category.SEMANTIC_INJECTION,
                        severity=Severity.CRITICAL,
                        message=outcome.note,
                        evidence=(
                            f"raw={outcome.raw_score} ({outcome.raw_recommendation}) vs "
                            f"sanitized={outcome.sanitized_score} ({outcome.sanitized_recommendation})"
                        ),
                        detail=outcome.to_dict(),
                    )
                )
    finally:
        doc.close()

    return result


def scan_file(path: str | Path) -> ScanResult:
    path = Path(path)
    return scan_pdf(path.read_bytes(), filename=path.name)
