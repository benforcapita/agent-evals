"""Implementation of `evals scan` for standalone redaction scanning and redacting."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evals.redaction.canaries import CanaryRegistry
from evals.redaction.scanner import ScanMode, redact_text, scan_path
from evals.schema.validator import EXIT_OK, EXIT_REDACTION_FINDING, EXIT_USAGE_ERROR


def register_scan_subparser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = subparsers.add_parser(
        "scan",
        help="Run the redaction scanner on a file or directory.",
    )
    parser.add_argument("path", type=Path, help="File or directory to scan.")
    parser.add_argument(
        "--mode",
        choices=[ScanMode.FIXTURE.value, ScanMode.OUTPUT.value],
        default=ScanMode.FIXTURE.value,
        help="Scan mode: 'fixture' allows registered canaries; 'output' fails on any canary.",
    )
    parser.add_argument(
        "--canary-file",
        type=Path,
        default=None,
        help="Optional JSON/YAML/text file of additional registered EVALCANARY_* tokens.",
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="Print redacted file content to stdout (single file only).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit findings as JSON.",
    )
    parser.set_defaults(handler=run_scan)


def run_scan(args: argparse.Namespace) -> int:
    target: Path = args.path
    if not target.exists():
        print(f"Error: path not found: {target}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    registry: CanaryRegistry | None = None
    if args.canary_file is not None:
        try:
            registry = CanaryRegistry.from_file(args.canary_file)
        except (OSError, ValueError) as exc:
            print(f"Error loading canary registry: {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    mode = ScanMode(args.mode)

    if args.redact:
        if not target.is_file():
            print("Error: --redact requires a single file path", file=sys.stderr)
            return EXIT_USAGE_ERROR
        content = target.read_text(encoding="utf-8")
        result = redact_text(content, path=str(target), mode=mode, registry=registry)
        sys.stdout.write(result.redacted_text)
        return EXIT_REDACTION_FINDING if result.has_findings else EXIT_OK

    findings = scan_path(target, mode=mode, registry=registry)
    if args.as_json:
        print(
            json.dumps(
                {
                    "path": str(target),
                    "mode": mode.value,
                    "clean": not findings,
                    "findings": [f.to_dict() for f in findings],
                },
                indent=2,
            )
        )
    elif not findings:
        print(f"CLEAN: {target} (mode={mode.value})")
    else:
        print(f"FINDINGS: {target} (mode={mode.value})")
        for finding in findings:
            print(f"  {finding.format_line()}")

    return EXIT_REDACTION_FINDING if findings else EXIT_OK
