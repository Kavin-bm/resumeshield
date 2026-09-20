"""Command-line interface for ResumeShield."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from resumeshield.config import ShieldConfig
from resumeshield.models import Severity, Verdict
from resumeshield.shield import Shield

# ANSI color codes for terminal formatting
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"


def _color_verdict(verdict: Verdict) -> str:
    if verdict == Verdict.CLEAN:
        return f"{GREEN}{BOLD}CLEAN{RESET}"
    if verdict == Verdict.SUSPICIOUS:
        return f"{YELLOW}{BOLD}SUSPICIOUS{RESET}"
    return f"{RED}{BOLD}MALICIOUS{RESET}"


def _color_severity(severity: Severity) -> str:
    if severity == Severity.CRITICAL:
        return f"{RED}{BOLD}CRITICAL{RESET}"
    if severity == Severity.HIGH:
        return f"{RED}HIGH{RESET}"
    if severity == Severity.MEDIUM:
        return f"{YELLOW}MEDIUM{RESET}"
    if severity == Severity.LOW:
        return f"{CYAN}LOW{RESET}"
    return f"{DIM}INFO{RESET}"


def cmd_scan(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        sys.stderr.write(f"Error: File not found: {path}\n")
        return 1

    config = ShieldConfig.from_file(args.config) if args.config else ShieldConfig.from_env()
    shield = Shield(config=config)

    result = shield.scan(
        path,
        render=args.render,
        differential_screening=args.diff,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.is_clean else 2

    print(f"\n{BOLD}ResumeShield Analysis Report{RESET}")
    print(f"File:        {path.name}")
    print(f"Verdict:     {_color_verdict(result.verdict)}")
    print(f"Risk Score:  {result.risk_score}/100")
    print(f"Findings:    {len(result.findings)}")

    if result.findings:
        print(f"\n{BOLD}Detected Issues:{RESET}")
        for i, f in enumerate(result.findings, 1):
            sev_badge = _color_severity(f.severity)
            print(f"  {i}. [{sev_badge}] {BOLD}{f.detector}{RESET} ({f.category})")
            print(f"     {DIM}{f.message}{RESET}")
            if f.evidence:
                print(f"     Evidence: \"{CYAN}{f.evidence[:100]}{RESET}\"")
            if f.page is not None:
                print(f"     Location: Page {f.page + 1}")

    if result.differential.get("available"):
        diff = result.differential
        print(f"\n{BOLD}Differential Screening Proof:{RESET}")
        print(f"  Raw Score:       {diff.get('raw_score')} ({diff.get('raw_recommendation')})")
        print(f"  Sanitized Score: {diff.get('sanitized_score')} ({diff.get('sanitized_recommendation')})")
        print(f"  Delta:           {diff.get('delta'):+d}")
        print(f"  Manipulated:     {diff.get('manipulated')}")

    print()
    return 0 if result.is_clean else 2


def cmd_sanitize(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        sys.stderr.write(f"Error: File not found: {path}\n")
        return 1

    shield = Shield.default()
    safe_text = shield.sanitize(path)

    if args.output:
        Path(args.output).write_text(safe_text, encoding="utf-8")
    else:
        print(safe_text)
    return 0


def cmd_samples(args: argparse.Namespace) -> int:
    from resumeshield.api import SAMPLE_LABELS

    print(f"\n{BOLD}ResumeShield Built-in Test Samples:{RESET}\n")
    print(f"{'ID':<25} {'Poisoned':<10} {'Label':<25} {'Description'}")
    print("-" * 80)
    for sample_id, (label, desc) in SAMPLE_LABELS.items():
        poisoned = "No" if sample_id in ("clean", "dark_banner") else "Yes"
        print(f"{sample_id:<25} {poisoned:<10} {label:<25} {desc}")
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="resumeshield",
        description="ResumeShield: Detect and neutralize prompt-injection payloads in resumes.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a resume file for injection payloads")
    scan_parser.add_argument("file", help="Path to PDF resume")
    scan_parser.add_argument("--json", action="store_true", help="Output full JSON report")
    scan_parser.add_argument("--render", action="store_true", help="Include page render data")
    scan_parser.add_argument("--diff", action="store_true", help="Run differential screening")
    scan_parser.add_argument("--config", help="Path to YAML or JSON config file")

    # Sanitize command
    sanitize_parser = subparsers.add_parser("sanitize", help="Extract and sanitize safe screening text")
    sanitize_parser.add_argument("file", help="Path to PDF resume")
    sanitize_parser.add_argument("-o", "--output", help="Output file path (default: stdout)")

    # Samples command
    subparsers.add_parser("samples", help="List built-in demonstration samples")

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "sanitize":
        return cmd_sanitize(args)
    if args.command == "samples":
        return cmd_samples(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
