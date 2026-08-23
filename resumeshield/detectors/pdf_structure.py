"""Structural analysis of a PDF: which text is actually visible to a human?

The governing idea: extract the *superset* of text in the document, then
classify each span by whether a human reader could plausibly see it.
Anything extractable but not visible is, by definition, text placed for a
machine reader only.

Extracting the superset matters more than it looks. PyMuPDF's default
`get_text()` clips to the page, so off-page payloads silently vanish —
but other extractors (pdftotext, pdfplumber, pypdf) surface them, and the
screener being defended might use any of those. Checking only what one
library returns would miss attacks that land on a different stack, so
extraction here uses a deliberately oversized clip.
"""
from __future__ import annotations

from dataclasses import dataclass

import pymupdf

from resumeshield.models import Category, Finding, Severity

# Real resumes essentially never go below ~6pt; 4.0 leaves headroom for
# dense legal footers while still catching payloads set at 1pt.
TINY_FONT_PT = 4.0

# 0-255. Render mode 3 (invisible) surfaces as alpha 0; a low threshold
# also catches near-transparent fills.
INVISIBLE_ALPHA = 25

# Relative-luminance gap below which text is unreadable against its
# background. 0.12 flags white-on-white while leaving mid-grey body text
# on white (gap ≈ 0.5+) far clear of the threshold.
MIN_LUMINANCE_GAP = 0.12

HUGE_CLIP = pymupdf.Rect(-10000, -10000, 10000, 10000)


@dataclass
class Span:
    """One run of text plus everything needed to judge its visibility."""

    text: str
    page: int
    bbox: tuple[float, float, float, float]
    size: float
    color: tuple[float, float, float]
    alpha: int
    font: str

    @property
    def is_blank(self) -> bool:
        return not self.text.strip()


def _int_to_rgb(color: int) -> tuple[float, float, float]:
    return ((color >> 16 & 255) / 255, (color >> 8 & 255) / 255, (color & 255) / 255)


def _relative_luminance(rgb: tuple[float, float, float]) -> float:
    """WCAG relative luminance — perceptual, not a naive RGB average."""

    def channel(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _rects_overlap(inner: tuple, outer: tuple) -> bool:
    return (
        inner[0] >= outer[0] - 1 and inner[1] >= outer[1] - 1
        and inner[2] <= outer[2] + 1 and inner[3] <= outer[3] + 1
    )


def _background_luminance(span: Span, fills: list[tuple[tuple, tuple[float, float, float]]]) -> float:
    """Luminance behind a span.

    Defaults to white (the page), but if a filled shape sits behind the
    text, that shape is the real background. Without this, light text on a
    dark banner — an ordinary resume design choice — would be reported as
    a hidden payload, and a false positive here means rejecting a real
    person's application.
    """
    for rect, rgb in reversed(fills):  # later drawings paint on top
        if _rects_overlap(span.bbox, rect):
            return _relative_luminance(rgb)
    return 1.0  # blank page


def load_spans(doc: pymupdf.Document) -> list[Span]:
    spans: list[Span] = []
    for page_index, page in enumerate(doc):
        data = page.get_text("dict", clip=HUGE_CLIP)
        for block in data.get("blocks", []):
            if block.get("type") != 0:
                continue
            for line in block.get("lines", []):
                for raw in line.get("spans", []):
                    spans.append(
                        Span(
                            text=raw.get("text", ""),
                            page=page_index,
                            bbox=tuple(raw["bbox"]),
                            size=float(raw.get("size", 0)),
                            color=_int_to_rgb(int(raw.get("color", 0))),
                            alpha=int(raw.get("alpha", 255)),
                            font=raw.get("font", ""),
                        )
                    )
    return spans


def _page_fills(page: pymupdf.Page) -> list[tuple[tuple, tuple[float, float, float]]]:
    """Filled shapes on a page, as (bbox, rgb) — used to infer background."""
    fills = []
    for drawing in page.get_drawings():
        fill = drawing.get("fill")
        if fill is None:
            continue
        rect = drawing.get("rect")
        if rect is None:
            continue
        fills.append(((rect.x0, rect.y0, rect.x1, rect.y1), tuple(fill)))
    return fills


def classify_span(
    span: Span, page_rect: pymupdf.Rect, fills: list
) -> tuple[str, str] | None:
    """Return (reason_code, human_message) if the span is hidden, else None."""
    if span.is_blank:
        return None

    if span.alpha <= INVISIBLE_ALPHA:
        return (
            "invisible_render",
            f"Text is painted invisibly (alpha={span.alpha}) but remains machine-readable.",
        )

    if span.size < TINY_FONT_PT:
        return (
            "tiny_font",
            f"Text is set at {span.size:.2f}pt — far below readable size.",
        )

    x0, y0, x1, y1 = span.bbox
    if x1 < page_rect.x0 or x0 > page_rect.x1 or y1 < page_rect.y0 or y0 > page_rect.y1:
        return (
            "offpage",
            "Text is positioned outside the visible page area.",
        )

    text_lum = _relative_luminance(span.color)
    bg_lum = _background_luminance(span, fills)
    if abs(text_lum - bg_lum) < MIN_LUMINANCE_GAP:
        return (
            "low_contrast",
            "Text colour is indistinguishable from the background behind it.",
        )

    return None


REASON_SEVERITY = {
    "invisible_render": Severity.CRITICAL,
    "low_contrast": Severity.CRITICAL,
    "offpage": Severity.HIGH,
    "tiny_font": Severity.HIGH,
}


def analyze(doc: pymupdf.Document) -> tuple[list[Finding], str, str]:
    """Analyze a PDF's structure.

    Returns (findings, visible_text, hidden_text). The two text streams are
    what makes the report legible: visible_text is what a human reviewer
    sees, hidden_text is what only the machine sees.
    """
    findings: list[Finding] = []
    visible_parts: list[str] = []
    hidden_parts: list[str] = []

    fills_by_page = {i: _page_fills(page) for i, page in enumerate(doc)}
    rects_by_page = {i: page.rect for i, page in enumerate(doc)}

    for span in load_spans(doc):
        if span.is_blank:
            continue
        verdict = classify_span(span, rects_by_page[span.page], fills_by_page[span.page])
        if verdict is None:
            visible_parts.append(span.text)
            continue

        reason, message = verdict
        hidden_parts.append(span.text)
        findings.append(
            Finding(
                detector=f"pdf_structure.{reason}",
                category=Category.HIDDEN_TEXT,
                severity=REASON_SEVERITY[reason],
                message=message,
                evidence=span.text.strip(),
                page=span.page,
                bbox=span.bbox,
                detail={
                    "font_size": round(span.size, 2),
                    "alpha": span.alpha,
                    "font": span.font,
                },
            )
        )

    return findings, " ".join(visible_parts), " ".join(hidden_parts)
