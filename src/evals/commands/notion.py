"""Optional thin CLI hook for Notion schema checks (PRO-459).

Delegates to `scripts/notion/check-schema` when present; does not implement the
Notion schema or perform Notion API calls.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from evals.schema.validator import EXIT_USAGE_ERROR


def register_notion_subparser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = subparsers.add_parser(
        "notion",
        help="Thin delegation hook for Notion helper scripts.",
    )
    notion_sub = parser.add_subparsers(dest="notion_command", required=True)
    check_parser = notion_sub.add_parser(
        "check-schema",
        help="Delegate to scripts/notion/check-schema when installed.",
    )
    check_parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root containing scripts/notion/check-schema.",
    )
    check_parser.add_argument(
        "extra_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to scripts/notion/check-schema.",
    )
    check_parser.set_defaults(handler=run_notion_check_schema)


def _find_check_schema_script(root: Path) -> Path | None:
    candidates = [
        root / "scripts" / "notion" / "check-schema",
        root / "scripts" / "notion" / "check-schema.py",
        root / "scripts" / "notion" / "check-schema.sh",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def run_notion_check_schema(args: argparse.Namespace) -> int:
    script = _find_check_schema_script(args.root)
    if script is None:
        print(
            "Notion schema check script not installed at scripts/notion/check-schema.",
            file=sys.stderr,
        )
        return EXIT_USAGE_ERROR

    forwarded = list(args.extra_args or [])
    if forwarded and forwarded[0] == "--":
        forwarded = forwarded[1:]

    if script.suffix == ".py":
        cmd = [sys.executable, str(script), *forwarded]
    elif os.access(script, os.X_OK):
        cmd = [str(script), *forwarded]
    else:
        cmd = ["bash", str(script), *forwarded]

    completed = subprocess.run(cmd, check=False)
    return completed.returncode
