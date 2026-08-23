"use client";

import { useState } from "react";
import { DocumentViewer } from "@/components/DocumentViewer";
import { FindingsList } from "@/components/FindingsList";
import { SanitizedOutput } from "@/components/SanitizedOutput";
import { TextSplit } from "@/components/TextSplit";
import { UploadZone } from "@/components/UploadZone";
import { VerdictBanner } from "@/components/VerdictBanner";
import { scanFile, scanSample, type ScanResult } from "@/lib/api";

export default function Home() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(scan: () => Promise<ScanResult>) {
    setBusy(true);
    setError(null);
    try {
      setResult(await scan());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto w-full max-w-5xl px-5 py-10 sm:py-14">
      <header className="mb-10">
        <div className="flex items-center gap-2">
          <span className="text-accent">◆</span>
          <span className="text-sm font-medium tracking-tight">ResumeShield</span>
        </div>
        <h1 className="mt-5 text-2xl sm:text-3xl font-semibold tracking-tight leading-tight max-w-2xl">
          Some resumes carry instructions meant for the machine reading them.
        </h1>
        <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted">
          When a company screens applications with an AI, anything the file
          contains becomes part of the prompt — including text a human reviewer
          will never see. This finds that text, shows you where it was hiding,
          and returns a clean version safe to screen.
        </p>
      </header>

      <UploadZone
        onFile={(file) => run(() => scanFile(file))}
        onSample={(id) => run(() => scanSample(id))}
        busy={busy}
      />

      {error && (
        <div className="mt-6 rounded-lg border border-danger/40 bg-danger/5 px-4 py-3 text-xs text-danger">
          {error}
        </div>
      )}

      {result && (
        <div className="mt-10 space-y-10">
          <VerdictBanner result={result} />
          {result.rendered_pages.length > 0 && (
            <DocumentViewer pages={result.rendered_pages} findings={result.findings} />
          )}
          <TextSplit result={result} />
          <FindingsList findings={result.findings} />
          <SanitizedOutput result={result} />
        </div>
      )}

      <footer className="mt-16 border-t border-border pt-5 text-[11px] leading-relaxed text-dim">
        Uploads are analysed in memory and never written to disk. Detection runs
        in layers — page structure, parser disagreement, character encoding, and
        instruction phrasing — so no single evasion defeats it.
      </footer>
    </div>
  );
}
