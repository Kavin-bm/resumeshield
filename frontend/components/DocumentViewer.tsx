"use client";

import { useMemo, useState } from "react";
import type { Finding, RenderedPage } from "@/lib/api";

type Props = {
  pages: RenderedPage[];
  findings: Finding[];
};

/**
 * The reveal: the same page, shown as a human sees it and as a machine
 * reads it. Highlight boxes are positioned in percentages derived from
 * PDF points, so they stay aligned at any display width without needing
 * to measure the rendered image.
 */
export function DocumentViewer({ pages, findings }: Props) {
  const [revealed, setRevealed] = useState(false);

  const locatable = useMemo(
    () => findings.filter((f) => f.bbox && f.page !== null),
    [findings],
  );

  if (pages.length === 0) return null;

  return (
    <section className="space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium text-text">The document</h2>
          <p className="text-xs text-muted mt-0.5">
            {locatable.length > 0
              ? `${locatable.length} concealed region${locatable.length === 1 ? "" : "s"} located on the page.`
              : "Nothing concealed was located on the page."}
          </p>
        </div>

        <div
          className="inline-flex rounded-lg border border-border bg-surface p-0.5"
          role="group"
          aria-label="View mode"
        >
          <button
            onClick={() => setRevealed(false)}
            aria-pressed={!revealed}
            className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
              !revealed ? "bg-surface-2 text-text" : "text-muted hover:text-text"
            }`}
          >
            What a human sees
          </button>
          <button
            onClick={() => setRevealed(true)}
            aria-pressed={revealed}
            disabled={locatable.length === 0}
            className={`px-3 py-1.5 text-xs rounded-md transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
              revealed ? "bg-danger/15 text-danger" : "text-muted hover:text-text"
            }`}
          >
            What the AI reads
          </button>
        </div>
      </header>

      <div className="space-y-6">
        {pages.map((page) => (
          <PageCanvas
            key={page.page}
            page={page}
            findings={locatable.filter((f) => f.page === page.page)}
            revealed={revealed}
          />
        ))}
      </div>
    </section>
  );
}

function PageCanvas({
  page,
  findings,
  revealed,
}: {
  page: RenderedPage;
  findings: Finding[];
  revealed: boolean;
}) {
  // Payloads pushed past the page edge have no on-page position to box,
  // so they get an explicit marker instead of an invisible highlight.
  const onPage = findings.filter((f) => isOnPage(f, page));
  const offPage = findings.filter((f) => !isOnPage(f, page));

  return (
    <div className="space-y-2">
      <div className="relative overflow-hidden rounded-lg border border-border bg-paper shadow-2xl">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src={`data:image/png;base64,${page.png_base64}`}
          alt={`Page ${page.page + 1}`}
          className="block w-full"
        />

        {revealed &&
          onPage.map((finding, index) => {
            const [x0, y0, x1, y1] = finding.bbox!;
            return (
              <div
                key={index}
                className="highlight-box absolute border-2 border-danger bg-danger/25 rounded-[2px]"
                style={{
                  left: `${(x0 / page.width_pt) * 100}%`,
                  top: `${(y0 / page.height_pt) * 100}%`,
                  width: `${((x1 - x0) / page.width_pt) * 100}%`,
                  height: `${((y1 - y0) / page.height_pt) * 100}%`,
                }}
                title={finding.message}
              />
            );
          })}

        {revealed && onPage.length > 0 && (
          <div className="absolute bottom-3 left-3 rounded-md bg-danger px-2.5 py-1 text-[11px] font-medium text-white shadow-lg">
            {onPage.length} hidden region{onPage.length === 1 ? "" : "s"} revealed
          </div>
        )}
      </div>

      {revealed && offPage.length > 0 && (
        <div className="flex items-start gap-2 rounded-lg border border-danger/40 bg-danger-dim/40 px-3 py-2.5 text-xs">
          <span className="mt-px text-danger">↳</span>
          <p className="text-muted">
            <span className="text-danger font-medium">
              {offPage.length} payload{offPage.length === 1 ? "" : "s"} positioned outside the page
            </span>{" "}
            — beyond the printable area, so it cannot be boxed above, but text extractors still read it.
          </p>
        </div>
      )}
    </div>
  );
}

function isOnPage(finding: Finding, page: RenderedPage): boolean {
  const [x0, y0, x1, y1] = finding.bbox!;
  return x0 >= 0 && y0 >= 0 && x1 <= page.width_pt + 2 && y1 <= page.height_pt + 2;
}
