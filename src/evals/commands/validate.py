"""Implementation of `evals validate` (LLD §5.1)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evals.redaction.canaries import CanaryRegistry
from evals.schema.validator import (
    EXIT_USAGE_ERROR,
    ValidationReport,
    validate_fixture,
    validate_output,
    validate_suite,
)


def register_validate_subparser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = subparsers.add_parser(
        "validate",
        help="Validate suite schemas, fixtures, and redaction rules (no model calls).",
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--suite",
        metavar="SLUG",
        help="Suite slug under suites/<slug> to validate.",
    )
    target_group.add_argument(
        "--fixture",
        metavar="PATH",
        help=(
            "Fixture file or directory to validate "
            "(placeholders and registered canaries allowed)."
        ),
    )
    target_group.add_argument(
        "--output",
        metavar="PATH",
        help="Subject output file or directory to scan (any secret or EVALCANARY_ fails).",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root directory (defaults to current working directory).",
    )
    parser.add_argument(
        "--canary-file",
        type=Path,
        default=None,
        help="Optional JSON/YAML/text file of additional registered EVALCANARY_* tokens.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit machine-readable JSON output.",
    )
    parser.set_defaults(handler=run_validate)


def _print_report(report: ValidationReport, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report.to_dict(), indent=2))
        return

    if report.is_valid:
        print(f"OK: {report.target} ({len(report.checked_files)} file(s) checked)")
        return

    print(f"FAIL: {report.target}")
    for issue in report.schema_errors:
        print(f"  SCHEMA: {issue.format_line()}")
    for finding in report.redaction_findings:
        print(f"  REDACTION: {finding.format_line()}")


def run_validate(args: argparse.Namespace) -> int:
    registry: CanaryRegistry | None = None
    if args.canary_file is not None:
        try:
            registry = CanaryRegistry.from_file(args.canary_file)
        except (OSError, ValueError) as exc:
            print(f"Error loading canary registry: {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    root: Path = args.root
    if args.suite:
        report = validate_suite(args.suite, root=root, canary_registry=registry)
    elif args.fixture:
        report = validate_fixture(Path(args.fixture), canary_registry=registry, root=root)
    else:
        report = validate_output(Path(args.output), canary_registry=registry, root=root)

    _print_report(report, as_json=args.as_json)
    return report.exit_code
