from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from resumeshield import poison
from resumeshield.api import app


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    out = tmp_path_factory.mktemp("api_corpus")
    return {s.technique: s for s in poison.generate_corpus(out)}


@pytest.fixture
def client():
    return TestClient(app)


def _upload(client, path, **params):
    with open(path, "rb") as fh:
        return client.post("/scan", files={"file": (path.name, fh, "application/pdf")}, params=params)


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_scan_flags_poisoned_resume(client, corpus):
    resp = _upload(client, corpus["white_text"].path)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "malicious"
    assert body["risk_score"] > 0
    assert "Ignore all previous instructions" in body["hidden_text"]
    assert "Ignore all previous instructions" not in body["sanitized_text"]


def test_scan_passes_clean_resume(client, corpus):
    body = _upload(client, corpus["clean"].path).json()
    assert body["verdict"] == "clean"
    assert body["findings"] == []


def test_render_flag_returns_page_images(client, corpus):
    body = _upload(client, corpus["white_text"].path, render="true").json()
    assert body["rendered_pages"]
    page = body["rendered_pages"][0]
    assert page["png_base64"]
    # Needed by the client to scale finding bboxes onto the image.
    assert page["width_pt"] > 0 and page["height_pt"] > 0


def test_render_omitted_by_default(client, corpus):
    body = _upload(client, corpus["clean"].path).json()
    assert body["rendered_pages"] == []


def test_findings_carry_location_for_highlighting(client, corpus):
    body = _upload(client, corpus["white_text"].path, render="true").json()
    hidden = [f for f in body["findings"] if f["category"] == "hidden_text"]
    assert hidden
    assert hidden[0]["bbox"] is not None
    assert hidden[0]["page"] == 0


def test_non_pdf_is_rejected(client):
    resp = client.post("/scan", files={"file": ("resume.docx", b"x", "application/octet-stream")})
    assert resp.status_code == 400


def test_empty_upload_is_rejected(client):
    resp = client.post("/scan", files={"file": ("resume.pdf", b"", "application/pdf")})
    assert resp.status_code == 400


def test_sanitize_endpoint_returns_safe_text(client, corpus):
    path = corpus["white_text"].path
    with open(path, "rb") as fh:
        resp = client.post("/sanitize", files={"file": (path.name, fh, "application/pdf")})
    body = resp.json()
    assert body["verdict"] == "malicious"
    assert "Ignore all previous instructions" not in body["safe_text"]
    assert "JORDAN AVERY" in body["safe_text"]
    assert body["removed_count"] > 0
