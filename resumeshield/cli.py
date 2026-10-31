"""Command-line interface for ResumeShield."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from resumeshield import __version__
from resumeshield.config import ShieldConfig
from resumeshield.models import Severity, Verdict
from resumeshield.poison import CLEAN_TECHNIQUES
from resumeshield.shield import Shield

# ANSI color codes for terminal formatting
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"

_VERDICT_NOTE = {
    Verdict.CLEAN: "No concealment or instruction-like text found.",
    Verdict.SUSPICIOUS: "Concealment or instruction-like text, without both together.",
    Verdict.MALICIOUS: "Instruction-like text, or an instruction that was also concealed.",
}


def _color_enabled() -> bool:
    """Color only on a terminal, unless NO_COLOR or FORCE_COLOR says otherwise."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR", "").lower() in {"1", "true", "yes"}:
        return True
    isatty = getattr(sys.stdout, "isatty", None)
    return bool(isatty and isatty())


def _paint(text: str, *codes: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{''.join(codes)}{text}{RESET}"


def _color_verdict(verdict: Verdict, *, enabled: bool) -> str:
    label = verdict.value.upper()
    if verdict == Verdict.CLEAN:
        return _paint(label, GREEN, BOLD, enabled=enabled)
    if verdict == Verdict.SUSPICIOUS:
        return _paint(label, YELLOW, BOLD, enabled=enabled)
    return _paint(label, RED, BOLD, enabled=enabled)


def _color_severity(severity: Severity, *, enabled: bool) -> str:
    label = severity.value.upper()
    if severity == Severity.CRITICAL:
        return _paint(label, RED, BOLD, enabled=enabled)
    if severity == Severity.HIGH:
        return _paint(label, RED, enabled=enabled)
    if severity == Severity.MEDIUM:
        return _paint(label, YELLOW, enabled=enabled)
    if severity == Severity.LOW:
        return _paint(label, CYAN, enabled=enabled)
    return _paint(label, DIM, enabled=enabled)


def _require_file(path: Path) -> int | None:
    if not path.exists():
        sys.stderr.write(f"Error: File not found: {path}\n")
        return 1
    if not path.is_file():
        sys.stderr.write(f"Error: Not a file: {path}\n")
        return 1
    return None


def cmd_scan(args: argparse.Namespace) -> int:
    path = Path(args.file)
    missing = _require_file(path)
    if missing is not None:
        return missing
    if args.output and not args.json:
        sys.stderr.write("Error: --output applies to --json reports. Omit it, or pass --json.\n")
        return 1

    try:
        config = ShieldConfig.from_file(args.config) if args.config else ShieldConfig.from_env()
        shield = Shield(config=config)
        result = shield.scan(
            path,
            render=args.render,
            differential_screening=args.diff,
        )
    except OSError as exc:
        sys.stderr.write(f"Error: Could not read {path}: {exc}\n")
        return 1
    except (ValueError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"Error: Could not load config: {exc}\n")
        return 1

    if args.json:
        payload = json.dumps(result.to_dict(), indent=2)
        try:
            if args.output:
                Path(args.output).write_text(payload + "\n", encoding="utf-8")
            else:
                print(payload)
        except OSError as exc:
            sys.stderr.write(f"Error: Could not write report: {exc}\n")
            return 1
        return 0 if result.is_clean else 2

    color = _color_enabled()
    print(f"\n{_paint('ResumeShield Analysis Report', BOLD, enabled=color)}")
    print(f"File:        {path.name}")
    print(f"Verdict:     {_color_verdict(result.verdict, enabled=color)}")
    print(f"Risk Score:  {result.risk_score}/100")
    print(f"Pages:       {result.pages}")
    print(f"Findings:    {len(result.findings)}")
    print(f"Summary:     {_VERDICT_NOTE[result.verdict]}")

    if result.findings:
        names = ", ".join(sorted({f.detector for f in result.findings}))
        print(f"Detectors:   {names}")
        print(f"\n{_paint('Detected Issues:', BOLD, enabled=color)}")
        for i, finding in enumerate(result.findings, 1):
            sev_badge = _color_severity(finding.severity, enabled=color)
            detector = _paint(finding.detector, BOLD, enabled=color)
            print(f"  {i}. [{sev_badge}] {detector} ({finding.category})")
            print(f"     {_paint(finding.message, DIM, enabled=color)}")
            if finding.evidence:
                snippet = finding.evidence[:100]
                print(f"     Evidence: \"{_paint(snippet, CYAN, enabled=color)}\"")
            if finding.page is not None:
                print(f"     Location: Page {finding.page + 1}")

    if result.errors:
        print(f"\n{_paint('Errors:', BOLD, enabled=color)}")
        for error in result.errors:
            print(f"  - {error}")

    if result.differential.get("available"):
        diff = result.differential
        print(f"\n{_paint('Differential Screening Proof:', BOLD, enabled=color)}")
        print(f"  Raw Score:       {diff.get('raw_score')} ({diff.get('raw_recommendation')})")
        sanitized = f"{diff.get('sanitized_score')} ({diff.get('sanitized_recommendation')})"
        print(f"  Sanitized Score: {sanitized}")
        print(f"  Delta:           {diff.get('delta'):+d}")
        print(f"  Manipulated:     {diff.get('manipulated')}")

    print()
    return 0 if result.is_clean else 2


def cmd_sanitize(args: argparse.Namespace) -> int:
    path = Path(args.file)
    missing = _require_file(path)
    if missing is not None:
        return missing

    try:
        shield = Shield.default()
        safe_text = shield.sanitize(path)
    except OSError as exc:
        sys.stderr.write(f"Error: Could not read {path}: {exc}\n")
        return 1

    if args.output:
        Path(args.output).write_text(safe_text, encoding="utf-8")
    else:
        print(safe_text)
    return 0


def cmd_samples(_args: argparse.Namespace) -> int:
    from resumeshield.api import SAMPLE_LABELS

    print(f"\n{_paint('ResumeShield Built-in Test Samples:', BOLD, enabled=_color_enabled())}\n")
    print(f"{'ID':<25} {'Poisoned':<10} {'Label':<25} {'Description'}")
    print("-" * 80)
    for sample_id, (label, desc) in SAMPLE_LABELS.items():
        poisoned = "No" if sample_id in CLEAN_TECHNIQUES else "Yes"
        print(f"{sample_id:<25} {poisoned:<10} {label:<25} {desc}")
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="resumeshield",
        description="Detect and neutralize prompt-injection payloads hidden in resume PDFs.",
        epilog=(
            "Exit codes for scan: 0 when the verdict is clean, "
            "1 when the file or config cannot be read, "
            "2 when the verdict is suspicious or malicious."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    scan_parser = subparsers.add_parser("scan", help="Scan a resume file for injection payloads")
    scan_parser.add_argument("file", help="Path to PDF resume")
    scan_parser.add_argument("--json", action="store_true", help="Print a JSON report")
    scan_parser.add_argument(
        "-o",
        "--output",
        help="Write the JSON report to this path instead of stdout (requires --json)",
    )
    scan_parser.add_argument("--render", action="store_true", help="Include page render data")
    scan_parser.add_argument("--diff", action="store_true", help="Run differential screening")
    scan_parser.add_argument("--config", help="Path to a JSON or YAML config file")

    sanitize_parser = subparsers.add_parser(
        "sanitize", help="Extract and sanitize safe screening text"
    )
    sanitize_parser.add_argument("file", help="Path to PDF resume")
    sanitize_parser.add_argument("-o", "--output", help="Output file path (default: stdout)")

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
