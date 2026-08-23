"""Cross-extractor differential analysis.

First principle: **you do not control which library reads the resume.**
The screening system on the other side might use PyMuPDF, pypdf,
pdfminer, pdftotext, or whatever its vendor chose. Each implements the
PDF text model slightly differently — clipping, ordering, invisible text,
form XObjects, overlapping content streams.

An attacker can exploit exactly that gap: craft a document where the text
a *reviewer's* tooling shows is not the text the *screener's* tooling
feeds to its model. Neither side is malfunctioning; they simply disagree.

So instead of asking "is this text hidden," this layer asks a question
that needs no list of known tricks: **do independent parsers disagree
about what this document says?** Any content visible to one extractor and
absent from another is, by construction, extractor-dependent — and a
legitimate resume has no reason to contain any.

This is the layer that catches concealment techniques nobody has
enumerated yet, because it detects the *effect* rather than the method.
"""
from __future__ import annotations

import io
import re

from resumeshield.models import Category, Finding, Severity

# Runs shorter than this are noise: extractors legitimately differ on
# hyphenation, ligatures, headers, and whitespace. A payload that changes
# a screener's decision needs real words.
MIN_DIVERGENT_WORDS = 8

_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> list[str]:
    """Aggressively normalized tokens.

    Extractors disagree constantly about whitespace, ligatures, and
    punctuation; none of that is an attack. Reducing to lowercase
    alphanumeric words removes that noise so only genuine content
    differences survive.
    """
    return _WORD_RE.findall(text.lower())


def _shingles(tokens: list[str], size: int = MIN_DIVERGENT_WORDS) -> set[tuple[str, ...]]:
    if len(tokens) < size:
        return set()
    return {tuple(tokens[i : i + size]) for i in range(len(tokens) - size + 1)}


# ------------------------------------------------------------- extractors


def _extract_pymupdf(data: bytes) -> str:
    import pymupdf

    with pymupdf.open(stream=io.BytesIO(data), filetype="pdf") as doc:
        return "\n".join(page.get_text() for page in doc)


def _extract_pymupdf_unclipped(data: bytes) -> str:
    """PyMuPDF ignoring page boundaries — surfaces off-page content."""
    import pymupdf

    clip = pymupdf.Rect(-10000, -10000, 10000, 10000)
    with pymupdf.open(stream=io.BytesIO(data), filetype="pdf") as doc:
        return "\n".join(page.get_text("text", clip=clip) for page in doc)


def _extract_pypdf(data: bytes) -> str:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    return "\n".join((page.extract_text() or "") for page in reader.pages)


def _extract_pdfminer(data: bytes) -> str:
    from pdfminer.high_level import extract_text

    return extract_text(io.BytesIO(data)) or ""


EXTRACTORS = {
    "pymupdf": _extract_pymupdf,
    "pymupdf_unclipped": _extract_pymupdf_unclipped,
    "pypdf": _extract_pypdf,
    "pdfminer": _extract_pdfminer,
}


def extract_all(data: bytes) -> dict[str, str]:
    """Run every extractor. A failure is recorded, not raised — a parser
    crashing on a document is itself a signal worth keeping."""
    results = {}
    for name, extractor in EXTRACTORS.items():
        try:
            results[name] = extractor(data)
        except Exception as exc:  # noqa: BLE001 - third-party parsers fail in many ways
            results[name] = ""
            results[f"__error__{name}"] = str(exc)
    return results


def _reconstruct(shingles: set[tuple[str, ...]]) -> str:
    """Turn divergent shingles back into readable evidence."""
    if not shingles:
        return ""
    ordered = sorted(shingles)
    words: list[str] = list(ordered[0])
    for shingle in ordered[1:]:
        if shingle[-1] not in words[-MIN_DIVERGENT_WORDS:]:
            words.append(shingle[-1])
    return " ".join(words[:120])


def analyze(data: bytes) -> tuple[list[Finding], dict[str, str]]:
    """Compare what each extractor sees.

    Returns (findings, per-extractor text) — the text map is kept so the
    report can show a reviewer exactly which tool saw what.
    """
    texts = extract_all(data)
    real = {name: text for name, text in texts.items() if not name.startswith("__error__")}

    shingle_map = {name: _shingles(_tokens(text)) for name, text in real.items()}
    populated = {name: s for name, s in shingle_map.items() if s}
    if len(populated) < 2:
        return [], real

    universe: set[tuple[str, ...]] = set().union(*populated.values())
    common: set[tuple[str, ...]] = set.intersection(*populated.values())
    divergent = universe - common
    if not divergent:
        return [], real

    findings: list[Finding] = []
    for name, shingles in populated.items():
        unique = shingles & divergent
        if len(unique) < 1:
            continue
        evidence = _reconstruct(unique)
        if len(_tokens(evidence)) < MIN_DIVERGENT_WORDS:
            continue

        missing_from = sorted(n for n in populated if not (shingles & divergent) <= shingle_map[n])
        findings.append(
            Finding(
                detector=f"extractor_divergence.{name}",
                category=Category.HIDDEN_TEXT,
                severity=Severity.HIGH,
                message=(
                    f"Text is visible to the '{name}' extractor but absent from at least one "
                    "other parser. A resume should read identically to every PDF library; "
                    "content that only some tools see is placed to reach a specific reader."
                ),
                evidence=evidence,
                detail={
                    "extractor": name,
                    "divergent_shingles": len(unique),
                    "disagrees_with": missing_from[:4],
                },
            )
        )

    return findings, real
