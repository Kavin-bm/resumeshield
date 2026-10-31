"""Tests for the ResumeShield CLI commands."""
from __future__ import annotations

import json

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


@pytest.mark.parametrize(
    ("technique", "verdict"),
    [
        ("clean", "clean"),
        ("white_text", "malicious"),
        ("tiny_font", "malicious"),
        ("offpage", "malicious"),
        ("metadata", "malicious"),
    ],
)
def test_cli_json_covers_main_techniques(sample_files, capsys, technique, verdict):
    ret = cli.main(["scan", str(sample_files[technique]), "--json"])
    assert ret == (0 if verdict == "clean" else 2)
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["verdict"] == verdict
    assert "risk_score" in data
    assert "findings" in data
    assert "sanitized_text" in data
    assert "hidden_text" in data
    assert "\033" not in captured


def test_cli_json_written_to_file(sample_files, tmp_path, capsys):
    out = tmp_path / "report.json"
    ret = cli.main(["scan", str(sample_files["tiny_font"]), "--json", "-o", str(out)])
    assert ret == 2
    assert capsys.readouterr().out == ""
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["verdict"] == "malicious"
    assert any(f["detector"] == "pdf_structure.tiny_font" for f in data["findings"])


def test_cli_output_flag_requires_json(sample_files, tmp_path, capsys):
    ret = cli.main(["scan", str(sample_files["clean"]), "-o", str(tmp_path / "out.txt")])
    assert ret == 1
    assert "--json" in capsys.readouterr().err


def test_cli_missing_file(capsys):
    ret = cli.main(["scan", "no-such-resume.pdf"])
    assert ret == 1
    assert "File not found" in capsys.readouterr().err


def test_cli_rejects_a_directory(tmp_path, capsys):
    ret = cli.main(["scan", str(tmp_path)])
    assert ret == 1
    assert "Not a file" in capsys.readouterr().err


def test_cli_plain_text_when_stdout_is_not_a_tty(monkeypatch, sample_files, capsys):
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    cli.main(["scan", str(sample_files["white_text"])])
    captured = capsys.readouterr().out
    assert "\033" not in captured
    assert "MALICIOUS" in captured
    assert "pdf_structure.low_contrast" in captured
    assert "Summary:" in captured


def test_cli_sanitize_writes_a_file(sample_files, tmp_path):
    out = tmp_path / "safe.txt"
    ret = cli.main(["sanitize", str(sample_files["metadata"]), "-o", str(out)])
    assert ret == 0
    text = out.read_text(encoding="utf-8")
    assert "JORDAN AVERY" in text
    assert "Ignore all previous instructions" not in text


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "resumeshield" in capsys.readouterr().out


def test_python_module_entrypoint():
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "resumeshield", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "scan" in proc.stdout
