import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({ variable: "--font-inter", subsets: ["latin"] });
const mono = JetBrains_Mono({ variable: "--font-mono-face", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "ResumeShield — hidden prompt injection in resumes",
  description:
    "Finds instructions hidden inside resume files that manipulate AI screening systems.",
};

// Typed explicitly rather than with Next's generated `LayoutProps` global,
// which only exists once `next build` has written .next/types — so a bare
// `tsc --noEmit` on a clean checkout (as CI does) would fail to resolve it.
export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${inter.variable} ${mono.variable} h-full`}>
      <body className="min-h-full bg-bg text-text">{children}</body>
    </html>
  );
}
