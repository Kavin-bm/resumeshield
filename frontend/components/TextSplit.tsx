"use client";

import type { ScanResult } from "@/lib/api";

/**
 * The two text streams side by side. This is the clearest statement of
 * the whole problem: the left column is the document a person reviews,
 * the right column is what actually reaches the model.
 */
export function TextSplit({ result }: { result: ScanResult }) {
  const hasHidden = result.hidden_text.trim().length > 0;

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-sm font-medium text-text">Two readings of one file</h2>
        <p className="text-xs text-muted mt-0.5">
          {hasHidden
            ? "The screener ingests everything on the right. A reviewer only ever sees the left."
            : "Both readings match — nothing is reaching the model that a person cannot see."}
        </p>
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        <Panel
          title="What a person reads"
          caption="Rendered and visible on the page"
          tone="neutral"
        >
          <p className="machine-text whitespace-pre-wrap text-muted">
            {result.visible_text || "(no visible text extracted)"}
          </p>
        </Panel>

        <Panel
          title="What the screener ingests"
          caption={hasHidden ? "Visible text plus concealed content" : "Identical to the left"}
          tone={hasHidden ? "danger" : "neutral"}
        >
          <p className="machine-text whitespace-pre-wrap text-muted">
            {result.visible_text}
            {hasHidden && (
              <>
                {" "}
                <mark className="rounded bg-danger/25 px-1 py-0.5 text-danger decoration-danger/60">
                  {result.hidden_text}
                </mark>
              </>
            )}
          </p>
        </Panel>
      </div>
    </section>
  );
}

function Panel({
  title,
  caption,
  tone,
  children,
}: {
  title: string;
  caption: string;
  tone: "neutral" | "danger";
  children: React.ReactNode;
}) {
  return (
    <div
      className={`rounded-xl border bg-surface ${
        tone === "danger" ? "border-danger/30" : "border-border"
      }`}
    >
      <div className="border-b border-border px-4 py-2.5">
        <div className="flex items-baseline justify-between gap-3">
          <span
            className={`text-xs font-medium ${tone === "danger" ? "text-danger" : "text-text"}`}
          >
            {title}
          </span>
          <span className="text-[11px] text-dim truncate">{caption}</span>
        </div>
      </div>
      <div className="max-h-72 overflow-y-auto px-4 py-3">{children}</div>
    </div>
  );
}
