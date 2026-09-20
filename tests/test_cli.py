"""Tests for the ResumeShield CLI commands."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from resumeshield import cli


@pytest.fixture(scope="module")
def sample_files(tmp_path_factory):
    from resumeshield import poison

    out = tmp_path_factory.mktemp("cli_corpus")
    samples = poison.generate_corpus(out)
    return {s.technique: s.path for s in samples}


def test_cli_samples_command(capsys):
    ret = cli.main(["samples"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "white_text" in captured.out
    assert "clean" in captured.out


def test_cli_scan_clean(sample_files, capsys):
    ret = cli.main(["scan", str(sample_files["clean"])])
    assert ret == 0
    captured = capsys.readouterr()
    assert "CLEAN" in captured.out
    assert "Risk Score:  0/100" in captured.out


def test_cli_scan_malicious(sample_files, capsys):
    ret = cli.main(["scan", str(sample_files["white_text"])])
    assert ret == 2  # Non-zero exit code for flagged documents
    captured = capsys.readouterr()
    assert "MALICIOUS" in captured.out
    assert "low_contrast" in captured.out


def test_cli_scan_json(sample_files, capsys):
    ret = cli.main(["scan", str(sample_files["white_text"]), "--json"])
    assert ret == 2
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["verdict"] == "malicious"
    assert "findings" in data


def test_cli_sanitize(sample_files, capsys):
    ret = cli.main(["sanitize", str(sample_files["white_text"])])
    assert ret == 0
    captured = capsys.readouterr()
    assert "JORDAN AVERY" in captured.out
    assert "Ignore all previous instructions" not in captured.out
