"use client";

import type { ScanResult, Verdict } from "@/lib/api";

const STYLES: Record<Verdict, { ring: string; dot: string; label: string; text: string }> = {
  clean: {
    ring: "border-ok/30 bg-ok/5",
    dot: "bg-ok",
    label: "Clean",
    text: "text-ok",
  },
  suspicious: {
    ring: "border-warning/35 bg-warning/5",
    dot: "bg-warning",
    label: "Suspicious",
    text: "text-warning",
  },
  malicious: {
    ring: "border-danger/40 bg-danger/5",
    dot: "bg-danger",
    label: "Manipulation detected",
    text: "text-danger",
  },
};

function summarize(result: ScanResult): string {
  if (result.verdict === "clean") {
    return "No concealed content and no instructions aimed at an automated reader.";
  }
  const concealed = result.findings.filter((f) => f.category !== "semantic_injection").length;
  const instructing = result.findings.filter((f) => f.category === "semantic_injection").length;

  if (concealed && instructing) {
    return `Instructions to the screening system were hidden inside this document — ${concealed} concealment signal${concealed === 1 ? "" : "s"} and ${instructing} instruction${instructing === 1 ? "" : "s"} found.`;
  }
  if (instructing) {
    return `This document addresses its reader as a machine and tells it how to score the candidate.`;
  }
  return `${concealed} piece${concealed === 1 ? "" : "s"} of content are readable by software but not visible to a person.`;
}

export function VerdictBanner({ result }: { result: ScanResult }) {
  const style = STYLES[result.verdict];

  return (
    <div className={`fade-up rounded-xl border ${style.ring} p-5 sm:p-6`}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2.5">
            <span className={`h-2.5 w-2.5 rounded-full ${style.dot}`} />
            <span className={`text-sm font-semibold tracking-tight ${style.text}`}>
              {style.label}
            </span>
            <span className="text-xs text-dim truncate">· {result.filename}</span>
          </div>
          <p className="mt-2 text-sm text-muted leading-relaxed max-w-2xl">
            {summarize(result)}
          </p>
        </div>

        <div className="text-right shrink-0">
          <div className={`text-3xl font-semibold tabular-nums ${style.text}`}>
            {result.risk_score}
          </div>
          <div className="text-[11px] uppercase tracking-wider text-dim">Risk score</div>
        </div>
      </div>

      <RiskMeter score={result.risk_score} verdict={result.verdict} />
    </div>
  );
}

function RiskMeter({ score, verdict }: { score: number; verdict: Verdict }) {
  const fill =
    verdict === "clean" ? "bg-ok" : verdict === "suspicious" ? "bg-warning" : "bg-danger";
  return (
    <div className="mt-4">
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
        <div
          className={`h-full rounded-full transition-all duration-700 ${fill}`}
          style={{ width: `${Math.max(score, 2)}%` }}
        />
      </div>
    </div>
  );
}
