"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { listSamples, type Sample } from "@/lib/api";

type Props = {
  onFile: (file: File) => void;
  onSample: (id: string) => void;
  busy: boolean;
};

export function UploadZone({ onFile, onSample, busy }: Props) {
  const [dragging, setDragging] = useState(false);
  const [samples, setSamples] = useState<Sample[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    listSamples().then(setSamples).catch(() => setSamples([]));
  }, []);

  const handleDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();
      setDragging(false);
      const file = event.dataTransfer.files?.[0];
      if (file) onFile(file);
    },
    [onFile],
  );

  return (
    <div className="space-y-5">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`cursor-pointer rounded-xl border-2 border-dashed p-10 text-center transition-colors ${
          dragging
            ? "border-accent bg-accent/5"
            : "border-border hover:border-border-bright bg-surface/50"
        } ${busy ? "pointer-events-none opacity-60" : ""}`}
      >
        <input
          ref={inputRef}
          type="file"
          accept="application/pdf,.pdf"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) onFile(file);
            e.target.value = "";
          }}
        />
        <div className="text-sm text-text">
          {busy ? "Analysing…" : "Drop a resume PDF here"}
        </div>
        <div className="mt-1 text-xs text-dim">
          {busy ? "Running every detection layer" : "or click to choose a file — nothing is stored"}
        </div>
      </div>

      {samples.length > 0 && (
        <div>
          <div className="mb-2.5 flex items-baseline justify-between">
            <span className="text-xs font-medium text-text">No file handy? Try a sample</span>
            <span className="text-[11px] text-dim">each isolates one technique</span>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {samples.map((sample) => (
              <button
                key={sample.id}
                onClick={() => onSample(sample.id)}
                disabled={busy}
                className="group rounded-lg border border-border bg-surface p-3 text-left transition-colors hover:border-border-bright disabled:opacity-50"
              >
                <div className="flex items-center gap-2">
                  <span
                    className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                      sample.poisoned ? "bg-danger" : "bg-ok"
                    }`}
                  />
                  <span className="text-xs text-text">{sample.label}</span>
                </div>
                <p className="mt-1 pl-3.5 text-[11px] leading-relaxed text-dim">
                  {sample.description}
                </p>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
