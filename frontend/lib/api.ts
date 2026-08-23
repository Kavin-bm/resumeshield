const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Verdict = "clean" | "suspicious" | "malicious";
export type Category =
  | "hidden_text"
  | "unicode_trick"
  | "metadata"
  | "semantic_injection";

export type Finding = {
  detector: string;
  category: Category;
  severity: Severity;
  message: string;
  evidence: string;
  page: number | null;
  bbox: [number, number, number, number] | null;
  detail: Record<string, unknown>;
};

export type RenderedPage = {
  page: number;
  width_pt: number;
  height_pt: number;
  png_base64: string;
};

export type Differential = {
  available: boolean;
  note: string;
  raw_score: number | null;
  sanitized_score: number | null;
  delta: number | null;
  raw_recommendation: string;
  sanitized_recommendation: string;
  manipulated: boolean;
};

export type ScanResult = {
  filename: string;
  verdict: Verdict;
  risk_score: number;
  pages: number;
  findings: Finding[];
  visible_text: string;
  hidden_text: string;
  sanitized_text: string;
  errors: string[];
  rendered_pages: RenderedPage[];
  extractor_texts: Record<string, string>;
  differential: Differential | Record<string, never>;
};

export type Sample = {
  id: string;
  label: string;
  description: string;
  poisoned: boolean;
};

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.text();
    throw new Error(body || `${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export async function listSamples(): Promise<Sample[]> {
  return json(await fetch(`${API_BASE}/samples`, { cache: "no-store" }));
}

export async function scanSample(id: string): Promise<ScanResult> {
  return json(
    await fetch(`${API_BASE}/scan/sample/${id}?render=true`, { method: "POST" }),
  );
}

export async function scanFile(file: File): Promise<ScanResult> {
  const form = new FormData();
  form.append("file", file);
  return json(
    await fetch(`${API_BASE}/scan?render=true`, { method: "POST", body: form }),
  );
}

export const CATEGORY_LABEL: Record<Category, string> = {
  hidden_text: "Concealed from view",
  unicode_trick: "Character-level concealment",
  metadata: "Outside the visible page",
  semantic_injection: "Instructions to the reader",
};
