"""Command-line interface: ``python -m secret_scan <path>``.

Scans one file or a whole directory tree and prints one line per
finding — ``path:line:column: rule-id redacted-value`` — so a full
secret never reaches the terminal. Exit code 0 means no findings,
1 means findings were found, 2 means the invocation was wrong
(missing path, or a path that does not exist).

A formatted text report and ``--json`` output land in a later step;
this CLI prints the same facts in the simplest usable form.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .allowlist import Allowlist, DEFAULT_FILENAME
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

    for finding in result.findings:
        print(
            f"{finding.file}:{finding.line}:{finding.column}: "
            f"{finding.rule} {finding.redacted}"
        )
    skipped = (
        f", {len(result.files_skipped)} file(s) skipped"
        if result.files_skipped
        else ""
    )
    print(
        f"scanned {result.files_scanned} file(s), "
        f"{len(result.findings)} finding(s){skipped}",
        file=sys.stderr,
    )
    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
