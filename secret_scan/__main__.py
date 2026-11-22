"""Command-line interface: ``python -m secret_scan <path>``.

Scans one file or a directory tree and prints a human-readable report
(see :mod:`secret_scan.report`) — findings grouped by file, with
redacted values only, so a full secret never reaches the terminal.
``--json`` prints the same result as a JSON document instead, for CI
pipelines that parse the output.

Exit code 0 means no findings, 1 means findings were found, 2 means
the invocation was wrong (missing path, or a path that does not exist).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .allowlist import Allowlist, DEFAULT_FILENAME
from .report import format_json, format_text
from .scan import scan_path

__all__ = ["main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret_scan",
        description="Scan a file or directory for likely committed secrets.",
    )
    parser.add_argument(
        "path",
        help="file or directory to scan",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the report as a JSON document (for CI) instead of text",
    )
    parser.add_argument(
        "--allowlist",
        metavar="FILE",
        default=None,
        help=(
            "allowlist file of reviewed findings to suppress "
            f"(default: <root>/{DEFAULT_FILENAME} when scanning a directory)"
        ),
    )
    parser.add_argument(
        "--no-gitignore",
        action="store_true",
        help="scan files .gitignore would skip (the .git directory is always skipped)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target = Path(args.path)
    if not target.exists():
        print(f"secret_scan: no such file or directory: {args.path}", file=sys.stderr)
        return 2

    allowlist = (
        Allowlist.from_file(args.allowlist)
        if args.allowlist is not None
        else None
    )
    result = scan_path(
        target,
        allowlist=allowlist,
        use_gitignore=not args.no_gitignore,
    )

    if args.json:
        print(format_json(result, target))
    else:
        print(format_text(result, target), end="")
    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
