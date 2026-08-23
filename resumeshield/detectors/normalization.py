"""Encoding-level concealment, detected by divergence rather than blocklist.

First principle: **text that means one thing to a human and another to a
machine has been encoded, not written.**

Rather than enumerate every trick character, this layer applies the
transformations a reader's eye applies for free — Unicode normalization,
script folding, format-character removal — and asks whether the text
*changed*. Legitimate resume text is already in normal form; it survives
normalization untouched. Text that shifts meaningfully under NFKC, or
that mixes scripts inside a single word, was constructed.

That framing generalizes: it catches confusable characters this module
has never heard of, because it tests the property (does normalization
change this?) instead of the instance (is this the Cyrillic 'а'?).
"""
from __future__ import annotations

import re
import unicodedata

from resumeshield.models import Category, Finding, Severity

# Codepoint ranges for the scripts that supply almost all Latin lookalikes.
SCRIPT_RANGES = {
    "latin": [(0x0041, 0x024F), (0x1E00, 0x1EFF)],
    "cyrillic": [(0x0400, 0x04FF), (0x0500, 0x052F)],
    "greek": [(0x0370, 0x03FF), (0x1F00, 0x1FFF)],
    "armenian": [(0x0530, 0x058F)],
    "cherokee": [(0x13A0, 0x13FF)],
}

WORD_RE = re.compile(r"[^\W\d_]{3,}", re.UNICODE)

# A couple of stray normalizations are ordinary (ligatures from a PDF, a
# curly quote). A payload smuggled through encoding moves far more.
NFKC_DIVERGENCE_CHARS = 12


def _script_of(char: str) -> str | None:
    code = ord(char)
    for script, ranges in SCRIPT_RANGES.items():
        if any(low <= code <= high for low, high in ranges):
            return script
    return None


def find_mixed_script_words(text: str) -> list[tuple[str, set[str]]]:
    """Words built from more than one script — the homoglyph signature.

    'pаssword' with a Cyrillic 'а' reads as Latin to a human and hashes as
    something else entirely to a machine. No legitimate English resume
    word mixes scripts.
    """
    hits = []
    for match in WORD_RE.finditer(text):
        word = match.group(0)
        scripts = {s for s in (_script_of(c) for c in word) if s}
        if len(scripts) > 1:
            hits.append((word, scripts))
    return hits


def _visible_delta(raw: str, normalized: str) -> int:
    """How many characters normalization actually changed."""
    return sum(1 for a, b in zip(raw, normalized) if a != b) + abs(len(raw) - len(normalized))


def analyze(text: str, source: str = "visible") -> list[Finding]:
    if not text or not text.strip():
        return []

    findings: list[Finding] = []

    mixed = find_mixed_script_words(text)
    if mixed:
        sample = ", ".join(f"{word!r} ({'+'.join(sorted(scripts))})" for word, scripts in mixed[:5])
        findings.append(
            Finding(
                detector="normalization.mixed_script",
                category=Category.UNICODE_TRICK,
                severity=Severity.HIGH,
                message=(
                    f"{len(mixed)} word(s) mix character sets that look identical when "
                    "rendered. This defeats keyword filters while reading normally to a human."
                ),
                evidence=sample,
                detail={
                    "count": len(mixed),
                    "words": [w for w, _ in mixed[:20]],
                    "source": source,
                },
            )
        )

    normalized = unicodedata.normalize("NFKC", text)
    delta = _visible_delta(text, normalized)
    if delta >= NFKC_DIVERGENCE_CHARS:
        findings.append(
            Finding(
                detector="normalization.nfkc_divergence",
                category=Category.UNICODE_TRICK,
                severity=Severity.MEDIUM,
                message=(
                    f"Text shifts by {delta} characters under Unicode normalization. "
                    "Ordinary text is already in normal form; large divergence means the "
                    "document was authored with compatibility or lookalike characters."
                ),
                evidence=" ".join(text[:160].split()),
                detail={"delta": delta, "source": source},
            )
        )

    return findings


def normalize_for_screening(text: str) -> str:
    """Canonical form to hand downstream: NFKC, format characters removed."""
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(
        ch for ch in normalized
        if unicodedata.category(ch) != "Cf" or ch in "\n\r\t"
    )
