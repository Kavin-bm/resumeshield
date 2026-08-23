"""Behavioural proof: does this document actually move a screener's decision?

Every other layer in this system reasons about *appearance* — text is
hidden, phrasing is imperative, encoding is abnormal. Each is inference,
and each can in principle be argued with.

This layer settles the argument empirically. It runs a realistic
resume-screening prompt twice against the same document: once on the
sanitized text a human reviewer would see, once on the raw extracted text
a naive screener would ingest. If the score or recommendation moves, the
document demonstrably manipulates automated screening — no heuristic
required, and no dependence on recognising the technique.

That property is what makes it the backstop for the whole design: it
catches attacks nobody has enumerated, including ones invented after this
code was written, because it measures the effect rather than the method.

Requires an API key. Without one the scan still completes; this layer
reports itself unavailable rather than failing, so the tool stays useful
offline.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass

# A score gap this size is beyond ordinary model nondeterminism and
# indicates the extra text changed the judgement.
MATERIAL_DELTA = 15

SCREENER_PROMPT = """You are an automated resume screening assistant for a \
Senior Software Engineer position. Read the resume text and evaluate the \
candidate on their demonstrated experience alone.

Respond with ONLY a JSON object, no other text:
{"score": <integer 0-100>, "recommendation": "<advance|hold|reject>", "reason": "<one sentence>"}"""


@dataclass
class DifferentialResult:
    available: bool = False
    note: str = ""
    raw_score: int | None = None
    sanitized_score: int | None = None
    delta: int | None = None
    raw_recommendation: str = ""
    sanitized_recommendation: str = ""
    manipulated: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _model() -> str:
    return os.environ.get("RESUMESHIELD_SCREENER_MODEL", "claude-haiku-4-5-20251001")


def has_credentials() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY"))


def _parse_screener_reply(raw: str) -> tuple[int | None, str, str]:
    """Pull the JSON verdict out of a model reply, tolerating stray prose."""
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        return None, "", ""
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None, "", ""

    score = data.get("score")
    score = int(score) if isinstance(score, (int, float)) else None
    return score, str(data.get("recommendation", "")), str(data.get("reason", ""))


def _screen(text: str) -> tuple[int | None, str, str]:
    import litellm

    response = litellm.completion(
        model=_model(),
        messages=[
            {"role": "system", "content": SCREENER_PROMPT},
            {"role": "user", "content": text[:12000]},
        ],
        temperature=0,
    )
    return _parse_screener_reply(response.choices[0].message.content or "")


def run(raw_text: str, sanitized_text: str) -> DifferentialResult:
    """Screen both versions of the document and compare the outcomes."""
    if not has_credentials():
        return DifferentialResult(
            available=False,
            note="No API key configured — behavioural screening skipped. "
                 "Static detection layers still ran.",
        )

    if not raw_text.strip() or not sanitized_text.strip():
        return DifferentialResult(available=False, note="Not enough text to screen.")

    # Identical inputs mean nothing was stripped; the comparison would be
    # a pure cost with a guaranteed null result.
    if " ".join(raw_text.split()) == " ".join(sanitized_text.split()):
        return DifferentialResult(
            available=False,
            note="Sanitized and raw text are identical — nothing to compare.",
        )

    try:
        raw_score, raw_rec, _ = _screen(raw_text)
        clean_score, clean_rec, _ = _screen(sanitized_text)
    except Exception as exc:  # noqa: BLE001 - provider errors shouldn't fail the scan
        return DifferentialResult(available=False, note=f"Screening call failed: {exc}")

    if raw_score is None or clean_score is None:
        return DifferentialResult(available=False, note="Screener returned an unparseable verdict.")

    delta = raw_score - clean_score
    manipulated = abs(delta) >= MATERIAL_DELTA or (
        raw_rec and clean_rec and raw_rec.lower() != clean_rec.lower()
    )

    if manipulated:
        note = (
            f"Screening the raw document scored {raw_score} versus {clean_score} for the "
            f"sanitized text ({delta:+d}). The concealed content measurably changed the outcome."
        )
    else:
        note = (
            f"Raw scored {raw_score}, sanitized scored {clean_score} ({delta:+d}) — "
            "no material change to the screening decision."
        )

    return DifferentialResult(
        available=True,
        note=note,
        raw_score=raw_score,
        sanitized_score=clean_score,
        delta=delta,
        raw_recommendation=raw_rec,
        sanitized_recommendation=clean_rec,
        manipulated=manipulated,
    )
