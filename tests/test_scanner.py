"""End-to-end scanner tests against a freshly generated corpus.

The corpus is regenerated per-session rather than committed as binary
fixtures, so the attacks and the detectors can't silently drift apart.
"""
from __future__ import annotations

import pytest

from resumeshield import poison
from resumeshield.models import Category, Severity, Verdict
from resumeshield.scanner import scan_file

POISONED = ["white_text", "tiny_font", "invisible_render_mode", "offpage", "metadata", "visible_injection"]
CLEAN = ["clean", "dark_banner"]


@pytest.fixture(scope="session")
def corpus(tmp_path_factory):
    out = tmp_path_factory.mktemp("corpus")
    samples = poison.generate_corpus(out)
    return {s.technique: s for s in samples}


@pytest.mark.parametrize("technique", POISONED)
def test_poisoned_documents_are_flagged(corpus, technique):
    result = scan_file(corpus[technique].path)
    assert result.verdict is Verdict.MALICIOUS, f"{technique} was not flagged: {result.findings}"
    assert result.findings


@pytest.mark.parametrize("technique", CLEAN)
def test_clean_documents_are_not_flagged(corpus, technique):
    result = scan_file(corpus[technique].path)
    assert result.verdict is Verdict.CLEAN, (
        f"false positive on {technique}: "
        f"{[(f.detector, f.evidence[:60]) for f in result.findings]}"
    )
    assert result.risk_score == 0


def test_dark_banner_white_text_is_not_a_false_positive(corpus):
    """The FP case with real human cost: white text on a dark header is an
    ordinary design choice, and flagging it means rejecting a real
    applicant."""
    result = scan_file(corpus["dark_banner"].path)
    contrast_findings = [f for f in result.findings if "low_contrast" in f.detector]
    assert not contrast_findings
    assert "JORDAN AVERY" in result.visible_text


@pytest.mark.parametrize("technique", ["white_text", "tiny_font", "invisible_render_mode", "offpage"])
def test_hidden_payload_is_extracted_and_reported(corpus, technique):
    result = scan_file(corpus[technique].path)
    assert "Ignore all previous instructions" in result.hidden_text
    assert "Ignore all previous instructions" not in result.visible_text


@pytest.mark.parametrize("technique", POISONED)
def test_sanitized_text_never_contains_the_payload(corpus, technique):
    result = scan_file(corpus[technique].path)
    assert "Ignore all previous instructions" not in result.sanitized_text
    # The real resume content must survive sanitization.
    assert "JORDAN AVERY" in result.sanitized_text


def test_sanitized_text_of_clean_resume_is_intact(corpus):
    result = scan_file(corpus["clean"].path)
    assert "JORDAN AVERY" in result.sanitized_text
    assert "Northwind Systems" in result.sanitized_text


def test_concealment_plus_instruction_scores_above_bare_injection(corpus):
    hidden = scan_file(corpus["white_text"].path)
    visible = scan_file(corpus["visible_injection"].path)
    assert hidden.risk_score > visible.risk_score


def test_structural_detector_locates_payload_on_page(corpus):
    result = scan_file(corpus["white_text"].path)
    structural = [f for f in result.findings if f.category is Category.HIDDEN_TEXT]
    assert structural
    # bbox drives the visual highlight in the UI, so it must be populated.
    assert structural[0].bbox is not None
    assert structural[0].page == 0


def test_severity_escalates_for_concealed_instructions(corpus):
    result = scan_file(corpus["white_text"].path)
    semantic = [f for f in result.findings if f.category is Category.SEMANTIC_INJECTION]
    assert semantic
    assert all(f.severity is Severity.CRITICAL for f in semantic)


def test_corrupt_upload_does_not_crash():
    from resumeshield.scanner import scan_pdf

    result = scan_pdf(b"this is not a pdf", filename="junk.pdf")
    assert result.errors
    assert result.verdict is Verdict.SUSPICIOUS
