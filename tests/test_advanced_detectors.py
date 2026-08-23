"""Tests for the generalizing layers: parser divergence and normalization.

These are the layers that catch techniques nobody enumerated, so the tests
focus on the *property* each layer claims to detect rather than on the
specific sample that happens to trip it.
"""
from __future__ import annotations

import pytest

from resumeshield import poison
from resumeshield.detectors import extractor_divergence, normalization
from resumeshield.models import Category

CYRILLIC_A = "а"  # U+0430, visually identical to Latin 'a'


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    out = tmp_path_factory.mktemp("adv_corpus")
    return {s.technique: s for s in poison.generate_corpus(out)}


# ------------------------------------------------------- parser divergence


@pytest.mark.parametrize("technique", ["clean", "dark_banner"])
def test_clean_documents_show_no_parser_divergence(corpus, technique):
    findings, _ = extractor_divergence.analyze(corpus[technique].path.read_bytes())
    assert findings == [], [f.evidence[:80] for f in findings]


def test_offpage_payload_is_extractor_dependent(corpus):
    """The core claim: a screener using one library gets poisoned while a
    reviewer using another sees a clean page."""
    data = corpus["offpage"].path.read_bytes()
    texts = extractor_divergence.extract_all(data)
    assert "Ignore all previous" not in texts["pymupdf"]
    assert "Ignore all previous" in texts["pypdf"]

    findings, _ = extractor_divergence.analyze(data)
    assert findings
    assert all(f.category is Category.HIDDEN_TEXT for f in findings)


def test_divergence_findings_name_the_disagreeing_extractors(corpus):
    findings, _ = extractor_divergence.analyze(corpus["offpage"].path.read_bytes())
    assert findings
    assert findings[0].detail["extractor"]
    assert findings[0].detail["divergent_shingles"] > 0


def test_visual_only_tricks_produce_no_parser_divergence(corpus):
    """White-on-white is a rendering trick, not a parser differential —
    every extractor reads it identically. It must be caught by the
    contrast layer instead, and this asserts the layers stay in their
    lanes rather than all firing on everything."""
    findings, texts = extractor_divergence.analyze(corpus["white_text"].path.read_bytes())
    assert findings == []
    assert all("Ignore all previous" in t for k, t in texts.items() if not k.startswith("__"))


def test_extract_all_returns_every_backend(corpus):
    texts = extractor_divergence.extract_all(corpus["clean"].path.read_bytes())
    for backend in ("pymupdf", "pymupdf_unclipped", "pypdf", "pdfminer"):
        assert backend in texts
        assert "JORDAN AVERY" in texts[backend]


def test_corrupt_pdf_does_not_raise():
    texts = extractor_divergence.extract_all(b"not a pdf at all")
    assert any(k.startswith("__error__") for k in texts)
    findings, _ = extractor_divergence.analyze(b"not a pdf at all")
    assert findings == []


# ---------------------------------------------------------- normalization


def test_mixed_script_word_is_detected():
    text = f"Senior Engineer with p{CYRILLIC_A}ssword management experience"
    findings = normalization.analyze(text)
    assert any(f.detector == "normalization.mixed_script" for f in findings)


def test_pure_latin_resume_text_is_clean():
    text = "Senior Engineer with password management and distributed systems experience"
    assert normalization.analyze(text) == []


def test_accented_names_are_not_flagged():
    """Real names carry diacritics; those are still Latin script."""
    text = "Chloé Müller — Sr. Engineer, São Paulo. Delivered resilient services at scale."
    findings = [f for f in normalization.analyze(text) if f.detector == "normalization.mixed_script"]
    assert findings == []


def test_find_mixed_script_words_reports_the_scripts():
    hits = normalization.find_mixed_script_words(f"p{CYRILLIC_A}ssword")
    assert hits
    word, scripts = hits[0]
    assert "latin" in scripts and "cyrillic" in scripts


def test_normalize_for_screening_strips_format_chars():
    text = "Clean​text‮here"
    out = normalization.normalize_for_screening(text)
    assert "​" not in out and "‮" not in out
    assert "Clean" in out and "text" in out


def test_empty_text_is_safe():
    assert normalization.analyze("") == []
