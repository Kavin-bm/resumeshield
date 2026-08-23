"""HTTP API for scanning resumes.

Two audiences, one endpoint: the demo UI (which wants rendered pages to
draw highlights on) and an ATS integration (which wants a verdict and
sanitized text, and would rather not pay for image encoding). The
`render` flag is what separates them.

Nothing is persisted. An uploaded resume is personal data; it lives in
memory for the duration of the request and is never written to disk.
"""
from __future__ import annotations

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from resumeshield.scanner import scan_pdf

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
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


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
