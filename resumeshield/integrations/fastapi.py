"""FastAPI integration: Dependency guardrail for resume upload endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import File, HTTPException, UploadFile, status

from resumeshield.models import ScanResult, Verdict
from resumeshield.shield import Shield

MAX_FILE_SIZE = 15 * 1024 * 1024


class ResumeShieldGuard:
    """FastAPI dependency to automatically inspect resume uploads before route execution.

    Usage:
        guard = ResumeShieldGuard(auto_reject=True)

        @app.post("/apply")
        async def submit_resume(scan: ScanResult = Depends(guard)):
            # Safe to feed scan.sanitized_text to your LLM screening pipeline
            screen_candidate(scan.sanitized_text)
    """

    def __init__(
        self,
        shield: Shield | None = None,
        auto_reject: bool = True,
        max_risk_score: int = 60,
        allow_suspicious: bool = True,
        render: bool = False,
    ) -> None:
        self.shield = shield or Shield.default()
        self.auto_reject = auto_reject
        self.max_risk_score = max_risk_score
        self.allow_suspicious = allow_suspicious
        self.render = render

    async def __call__(self, file: UploadFile = File(...)) -> ScanResult:
        filename = file.filename or "upload.pdf"
        if not filename.lower().endswith(".pdf"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file format. Only PDF files are supported.",
            )

        data = await file.read()
        if not data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty.",
            )

        if len(data) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds maximum allowed size ({MAX_FILE_SIZE // (1024 * 1024)}MB).",
            )

        scan_result = self.shield.scan(data, filename=filename, render=self.render)

        if self.auto_reject:
            is_malicious = scan_result.verdict == Verdict.MALICIOUS
            score_exceeded = scan_result.risk_score >= self.max_risk_score
            suspicious_blocked = not self.allow_suspicious and scan_result.verdict == Verdict.SUSPICIOUS

            if is_malicious or score_exceeded or suspicious_blocked:
                payload: dict[str, Any] = {
                    "error": "Document rejected: prompt injection or manipulation payload detected.",
                    "verdict": str(scan_result.verdict),
                    "risk_score": scan_result.risk_score,
                    "findings_count": len(scan_result.findings),
                }
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=payload,
                )

        return scan_result
