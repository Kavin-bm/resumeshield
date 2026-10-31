"""Character-level concealment: zero-width characters and bidi overrides.

These attacks hide a payload inside otherwise ordinary-looking text, so no
amount of layout analysis finds them — the text is the right size, the
right colour, and on the page. Only the codepoints give it away.

Operates on already-extracted text, so the same checks apply whatever
produced the string. Characters below are written as escapes on purpose:
this file is about invisible codepoints, and the source should not contain
any.
"""
from __future__ import annotations

import unicodedata

from resumeshield.models import Category, Finding, Severity

ZERO_WIDTH = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
    "\u00ad": "SOFT HYPHEN",
}

BIDI_CONTROLS = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

# A handful of zero-width characters can appear legitimately (ligature
# control in some scripts, soft hyphens from a word processor). A run of
# them is how a payload gets smuggled, so only flag at volume.
ZERO_WIDTH_ALARM_COUNT = 8


def _context(text: str, index: int, window: int = 40) -> str:
    start, end = max(0, index - window), min(len(text), index + window)
    return text[start:end].replace("\n", " ")


def analyze(text: str, source: str = "body") -> list[Finding]:
    findings: list[Finding] = []
    if not text:
        return findings

    zero_width_hits = [(i, ch) for i, ch in enumerate(text) if ch in ZERO_WIDTH]
    if len(zero_width_hits) >= ZERO_WIDTH_ALARM_COUNT:
        names = sorted({ZERO_WIDTH[ch] for _, ch in zero_width_hits})
        first_index = zero_width_hits[0][0]
        findings.append(
            Finding(
                detector="unicode.zero_width",
                category=Category.UNICODE_TRICK,
                severity=Severity.HIGH,
                message=(
                    f"{len(zero_width_hits)} zero-width characters found in the {source} text. "
                    "These are invisible when rendered but are read by text extractors."
                ),
                evidence=_context(text, first_index),
                detail={"count": len(zero_width_hits), "characters": names, "source": source},
            )
        )

    bidi_hits = [(i, ch) for i, ch in enumerate(text) if ch in BIDI_CONTROLS]
    if bidi_hits:
        names = sorted({BIDI_CONTROLS[ch] for _, ch in bidi_hits})
        findings.append(
            Finding(
                detector="unicode.bidi_override",
                category=Category.UNICODE_TRICK,
                severity=Severity.HIGH,
                message=(
                    "Bidirectional control characters are present. These reorder how text "
                    "displays, so what a human reads can differ from what is extracted."
                ),
                evidence=_context(text, bidi_hits[0][0]),
                detail={"count": len(bidi_hits), "characters": names, "source": source},
            )
        )

    return findings


def strip_invisible(text: str) -> str:
    """Remove zero-width and bidi control characters.

    Used by the sanitizer. Also drops Unicode category Cf (format) chars
    generally, which covers variants not enumerated above, while leaving
    ordinary whitespace and newlines intact.
    """
    return "".join(
        ch for ch in text
        if ch not in ZERO_WIDTH
        and ch not in BIDI_CONTROLS
        and (unicodedata.category(ch) != "Cf" or ch in "\n\r\t")
    )
