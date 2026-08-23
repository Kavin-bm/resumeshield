"use client";

import { useState } from "react";
import { CATEGORY_LABEL, type Category, type Finding, type Severity } from "@/lib/api";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "text-danger border-danger/40 bg-danger/10",
  high: "text-danger border-danger/30 bg-danger/5",
  medium: "text-warning border-warning/30 bg-warning/5",
  low: "text-muted border-border bg-surface-2",
  info: "text-dim border-border bg-surface-2",
};

/** Explains why each category matters, in the reviewer's terms. */
const CATEGORY_BLURB: Record<Category, string> = {
  hidden_text: "Present in the file and readable by software, but not visible on the page.",
  unicode_trick: "Characters chosen to read one way to a person and another to a machine.",
  metadata: "Content stored outside the page body, where reviewers never look.",
  semantic_injection: "Text written to instruct the system evaluating this document.",
};

export function FindingsList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null;

  const groups = new Map<Category, Finding[]>();
  for (const finding of findings) {
    groups.set(finding.category, [...(groups.get(finding.category) ?? []), finding]);
  }

  const ordered = [...groups.entries()].sort(
    (a, b) =>
      SEVERITY_ORDER[worst(a[1])] - SEVERITY_ORDER[worst(b[1])] || b[1].length - a[1].length,
  );

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-sm font-medium text-text">
          Findings <span className="text-dim font-normal">({findings.length})</span>
        </h2>
        <p className="text-xs text-muted mt-0.5">
          Grouped by what was detected. Independent categories corroborate each other.
        </p>
      </div>

      <div className="space-y-3">
        {ordered.map(([category, group]) => (
          <div key={category} className="rounded-xl border border-border bg-surface overflow-hidden">
            <div className="border-b border-border px-4 py-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-medium text-text">{CATEGORY_LABEL[category]}</span>
                <span className="rounded-full bg-surface-2 px-2 py-0.5 text-[10px] text-muted">
                  {group.length}
                </span>
              </div>
              <p className="mt-1 text-[11px] text-dim">{CATEGORY_BLURB[category]}</p>
            </div>
            <div className="divide-y divide-border">
              {[...group]
                .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
                .map((finding, index) => (
                  <FindingRow key={index} finding={finding} />
                ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);

  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-surface-2/50"
      >
        <span
          className={`mt-0.5 shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${SEVERITY_STYLE[finding.severity]}`}
        >
          {finding.severity}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-xs text-text leading-relaxed">{finding.message}</span>
          <span className="mt-1 block font-mono text-[10px] text-dim">{finding.detector}</span>
        </span>
        <span className="mt-0.5 shrink-0 text-[10px] text-dim">{open ? "−" : "+"}</span>
      </button>

      {open && finding.evidence && (
        <div className="px-4 pb-3">
          <div className="rounded-lg border border-border bg-bg px-3 py-2.5">
            <div className="mb-1.5 text-[10px] uppercase tracking-wider text-dim">
              Extracted content
            </div>
            <p className="machine-text whitespace-pre-wrap break-words text-danger/90">
              {finding.evidence}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

function worst(findings: Finding[]): Severity {
  return findings.reduce<Severity>(
    (acc, f) => (SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[acc] ? f.severity : acc),
    "info",
  );
}
