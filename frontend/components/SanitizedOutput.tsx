"use client";

import { useState } from "react";
import type { ScanResult } from "@/lib/api";

/**
 * The remediation, not just the alarm. This is the text an ATS should
 * feed its model instead of raw extraction — which is the difference
 * between a report someone reads once and a fix that changes behaviour.
 */
export function SanitizedOutput({ result }: { result: ScanResult }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(result.sanitized_text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  const removed = result.visible_text.length + result.hidden_text.length
    - result.sanitized_text.length;

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-sm font-medium text-text">Safe text</h2>
        <p className="text-xs text-muted mt-0.5">
          What a screening system should read instead of raw extraction.
          {removed > 0 && ` ${removed} characters withheld.`}
        </p>
      </div>

      <div className="rounded-xl border border-ok/25 bg-surface overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
          <span className="text-xs font-medium text-ok">Sanitized output</span>
          <button
            onClick={copy}
            className="rounded-md border border-border bg-surface-2 px-2.5 py-1 text-[11px] text-muted transition-colors hover:text-text hover:border-border-bright"
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
        <div className="max-h-56 overflow-y-auto px-4 py-3">
          <p className="machine-text whitespace-pre-wrap text-muted">
            {result.sanitized_text || "(nothing extractable)"}
          </p>
        </div>
      </div>
    </section>
  );
}
