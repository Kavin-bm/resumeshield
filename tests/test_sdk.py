"""Tests for the high-level Shield SDK facade."""
from __future__ import annotations

import io
from pathlib import Path

import pytest

from resumeshield import Shield, ShieldConfig
from resumeshield.models import Verdict


@pytest.fixture(scope="module")
def sample_files(tmp_path_factory):
    from resumeshield import poison

    out = tmp_path_factory.mktemp("sdk_corpus")
    samples = poison.generate_corpus(out)
    return {s.technique: s.path for s in samples}


def test_shield_scan_from_path(sample_files):
    shield = Shield.default()
    result = shield.scan(sample_files["clean"])
    assert result.verdict == Verdict.CLEAN
    assert result.risk_score == 0

    poisoned = shield.scan(sample_files["white_text"])
    assert poisoned.verdict == Verdict.MALICIOUS
    assert poisoned.risk_score >= 60


def test_shield_scan_from_bytes(sample_files):
    shield = Shield.default()
    data = sample_files["clean"].read_bytes()
    result = shield.scan(data, filename="jordan.pdf")
    assert result.filename == "jordan.pdf"
    assert result.verdict == Verdict.CLEAN


def test_shield_scan_from_file_object(sample_files):
    shield = Shield.default()
    with open(sample_files["clean"], "rb") as f:
        result = shield.scan(f)
    assert result.verdict == Verdict.CLEAN


def test_shield_sanitize(sample_files):
    shield = Shield.default()
    safe_text = shield.sanitize(sample_files["white_text"])
    assert "Ignore all previous instructions" not in safe_text
    assert "JORDAN AVERY" in safe_text


def test_shield_disable_detector(sample_files):
    # Without injection_patterns, unhidden injection shouldn't trip instruction patterns
    shield = Shield.default()
    shield.disable_detector("injection_patterns")
    result = shield.scan(sample_files["visible_injection"])
    instruction_findings = [f for f in result.findings if f.detector == "injection_patterns"]
    assert len(instruction_findings) == 0
