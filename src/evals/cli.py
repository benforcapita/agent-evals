"""Main CLI entry point for `evals` (LLD §1, §5.1)."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from evals import __version__
from evals.commands.notion import register_notion_subparser
from evals.commands.scan import register_scan_subparser
from evals.commands.validate import register_validate_subparser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evals",
        description="Agent Evals CLI: redaction scanner and offline suite/fixture validator.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    register_validate_subparser(subparsers)
    register_scan_subparser(subparsers)
    register_notion_subparser(subparsers)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
