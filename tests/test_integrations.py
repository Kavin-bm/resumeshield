"""Tests for framework integrations (FastAPI guardrail & LangChain loader)."""
from __future__ import annotations

import io
from pathlib import Path

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from resumeshield.integrations.fastapi import ResumeShieldGuard
from resumeshield.integrations.langchain import (
    PromptInjectionDetectedError,
    ResumeShieldPDFLoader,
)
from resumeshield.models import ScanResult, Verdict
from resumeshield.shield import Shield


@pytest.fixture(scope="module")
def sample_files(tmp_path_factory):
    from resumeshield import poison

    out = tmp_path_factory.mktemp("integration_corpus")
    samples = poison.generate_corpus(out)
    return {s.technique: s.path for s in samples}


def test_fastapi_guard_clean_and_malicious(sample_files):
    app = FastAPI()
    guard = ResumeShieldGuard(auto_reject=True)

    @app.post("/submit")
    def submit_resume(scan: ScanResult = Depends(guard)):
        return {
            "status": "accepted",
            "candidate_name": "Jordan Avery",
            "safe_text_preview": scan.sanitized_text[:50],
        }

    client = TestClient(app)

    # 1. Clean file submission succeeds
    clean_bytes = sample_files["clean"].read_bytes()
    resp_clean = client.post(
        "/submit",
        files={"file": ("resume.pdf", clean_bytes, "application/pdf")},
    )
    assert resp_clean.status_code == 200
    assert resp_clean.json()["status"] == "accepted"

    # 2. Poisoned file submission is rejected automatically with 400
    malicious_bytes = sample_files["white_text"].read_bytes()
    resp_malicious = client.post(
        "/submit",
        files={"file": ("malicious.pdf", malicious_bytes, "application/pdf")},
    )
    assert resp_malicious.status_code == 400
    detail = resp_malicious.json()["detail"]
    assert detail["verdict"] == "malicious"
    assert detail["risk_score"] >= 60


def test_langchain_loader(sample_files):
    # 1. Loading clean document returns Document with sanitized text and metadata
    loader = ResumeShieldPDFLoader(sample_files["clean"])
    docs = loader.load()
    assert len(docs) == 1
    doc = docs[0]
    assert "JORDAN AVERY" in doc.page_content
    assert doc.metadata["resumeshield_verdict"] == "clean"
    assert doc.metadata["resumeshield_risk_score"] == 0

    # 2. Loading poisoned document raises PromptInjectionDetectedError
    poisoned_loader = ResumeShieldPDFLoader(sample_files["white_text"], reject_malicious=True)
    with pytest.raises(PromptInjectionDetectedError) as exc_info:
        poisoned_loader.load()
    assert exc_info.value.result.verdict == Verdict.MALICIOUS

    # 3. Loading poisoned document with reject_malicious=False yields sanitized document with security warnings
    tolerant_loader = ResumeShieldPDFLoader(sample_files["white_text"], reject_malicious=False)
    tolerant_docs = tolerant_loader.load()
    assert len(tolerant_docs) == 1
    assert tolerant_docs[0].metadata["resumeshield_verdict"] == "malicious"
    assert "Ignore all previous instructions" not in tolerant_docs[0].page_content
