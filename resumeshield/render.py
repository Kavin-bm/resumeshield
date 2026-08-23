"""Renders PDF pages to PNG so the UI can show *where* a payload was hiding.

Returned inline as base64 rather than via a stored-file endpoint. That
keeps the API stateless — no upload directory, no scan-id lifecycle, no
cleanup job, and no window in which someone's resume sits on disk. A
resume is personal data, so not storing it is the better default, and a
one- or two-page render is small enough that inlining costs nothing.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

import pymupdf

# 110 DPI keeps a page legible on screen while staying a few hundred KB.
RENDER_DPI = 110


@dataclass
class RenderedPage:
    page: int
    width_pt: float
    height_pt: float
    png_base64: str

    def to_dict(self) -> dict:
        return {
            "page": self.page,
            "width_pt": self.width_pt,
            "height_pt": self.height_pt,
            "png_base64": self.png_base64,
        }


def render_pages(doc: pymupdf.Document, max_pages: int = 4) -> list[RenderedPage]:
    """Render up to `max_pages` pages.

    Page dimensions are reported in PDF points because finding bboxes are
    in points too — the client scales by (rendered_px / width_pt) to place
    highlight boxes over the image.
    """
    pages = []
    for index, page in enumerate(doc):
        if index >= max_pages:
            break
        pixmap = page.get_pixmap(dpi=RENDER_DPI)
        pages.append(
            RenderedPage(
                page=index,
                width_pt=page.rect.width,
                height_pt=page.rect.height,
                png_base64=base64.b64encode(pixmap.tobytes("png")).decode("ascii"),
            )
        )
    return pages
