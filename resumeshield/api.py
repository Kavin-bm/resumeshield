"""HTTP API for scanning resumes.

Two audiences, one endpoint: the demo UI (which wants rendered pages to
draw highlights on) and an ATS integration (which wants a verdict and
sanitized text, and would rather not pay for image encoding). The
`render` flag is what separates them.

Nothing is persisted. An uploaded resume is personal data; it lives in
memory for the duration of the request and is never written to disk.
"""
from __future__ import annotations

import atexit
import os
import tempfile
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from resumeshield import poison
from resumeshield.scanner import scan_pdf

# Human-readable labels for the built-in demo documents. Most visitors
# won't have a poisoned resume to hand, and asking them to build one would
# end the demo before it starts.
SAMPLE_LABELS = {
    "clean": ("Ordinary resume", "A normal resume with nothing hidden in it."),
    "dark_banner": ("Designed resume", "White header text on a dark banner — legitimate design that naive contrast checks flag."),
    "white_text": ("White-on-white text", "Payload written in white on a white page."),
    "tiny_font": ("Sub-point font", "Payload set at 1pt — present, but unreadable."),
    "invisible_render_mode": ("Invisible render mode", "Painted as nothing, still extracted as text."),
    "offpage": ("Off-page payload", "Positioned past the page edge; some parsers still read it."),
    "metadata": ("Metadata payload", "Hidden in document properties rather than the page."),
    "visible_injection": ("Unhidden injection", "Not concealed at all — relies on nobody reading it."),
}

# Resumes are small; this is a guard against resource-exhaustion uploads,
# not a real product limit.
MAX_UPLOAD_BYTES = 15 * 1024 * 1024

app = FastAPI(
    title="ResumeShield API",
    description="Detects prompt-injection payloads hidden in resume documents.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    # Local dev ports only. A deployment sets RESUMESHIELD_ALLOWED_ORIGINS.
    allow_origins=(
        os.environ["RESUMESHIELD_ALLOWED_ORIGINS"].split(",")
        if os.environ.get("RESUMESHIELD_ALLOWED_ORIGINS")
        else [f"http://localhost:{port}" for port in (3000, 3001, 3002, 3003)]
    ),
    allow_methods=["*"],
    allow_headers=["*"],
)


@lru_cache(maxsize=1)
def _sample_dir() -> Path:
    """Generate the demo corpus once, into a temp dir cleaned up at exit."""
    directory = Path(tempfile.mkdtemp(prefix="resumeshield-samples-"))
    poison.generate_corpus(directory)
    atexit.register(lambda: [p.unlink(missing_ok=True) for p in directory.glob("*.pdf")])
    return directory


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/samples")
def list_samples() -> list[dict]:
    """Built-in demo documents, each isolating one concealment technique."""
    _sample_dir()
    return [
        {
            "id": technique,
            "label": label,
            "description": description,
            "poisoned": technique not in ("clean", "dark_banner"),
        }
        for technique, (label, description) in SAMPLE_LABELS.items()
    ]


@app.get("/samples/{sample_id}")
def get_sample(sample_id: str) -> FileResponse:
    if sample_id not in SAMPLE_LABELS:
        raise HTTPException(status_code=404, detail="Unknown sample.")
    path = _sample_dir() / f"{sample_id}.pdf"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Sample not generated.")
    return FileResponse(path, media_type="application/pdf", filename=f"{sample_id}.pdf")


@app.post("/scan/sample/{sample_id}")
def scan_sample(sample_id: str, render: bool = Query(True)) -> dict:
    """Scan a built-in sample — the one-click path for the demo."""
    if sample_id not in SAMPLE_LABELS:
        raise HTTPException(status_code=404, detail="Unknown sample.")
    path = _sample_dir() / f"{sample_id}.pdf"
    result = scan_pdf(path.read_bytes(), filename=f"{sample_id}.pdf", render=render)
    return result.to_dict()


@app.post("/scan")
async def scan(
    file: UploadFile = File(...),
    render: bool = Query(False, description="Include rendered page images for highlighting."),
) -> dict:
    filename = file.filename or "upload.pdf"
    if not filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF resumes are supported right now.")

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)}MB limit.",
        )

    result = scan_pdf(data, filename=filename, render=render)
    return result.to_dict()


@app.post("/sanitize")
async def sanitize(file: UploadFile = File(...)) -> dict:
    """Return only the text that's safe to hand to a downstream LLM screener.

    The integration-shaped endpoint: an ATS calls this instead of extracting
    text itself, and feeds the result to its model.
    """
    filename = file.filename or "upload.pdf"
    if not filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF resumes are supported right now.")

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    result = scan_pdf(data, filename=filename)
    return {
        "filename": result.filename,
        "verdict": str(result.verdict),
        "risk_score": result.risk_score,
        "safe_text": result.sanitized_text,
        "removed_count": len(result.findings),
    }
