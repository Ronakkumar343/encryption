"""Scanner engine: walk a project folder and find secrets per file.

This is step (b) of the CryptoVault Audit scanner. It wraps the
pattern detector from :mod:`secret_scan.detect` with the plumbing a
real scan needs:

* a ``.gitignore``-aware directory walk (see :mod:`secret_scan.gitignore`),
* binary-file detection (a NUL byte in the first 8 KiB means "not text"),
* an allowlist of known false positives (see
  :mod:`secret_scan.allowlist`),
* per-file findings with paths relative to the scanned root.

Honesty notes
-------------
* A skipped file is *not* a clean file: binary and unreadable files are
  reported in :attr:`ScanResult.files_skipped`, never silently dropped.
* The scanner only reports what the pattern stage can see. It does not
  claim a clean result means "no secrets exist" — binary files, ignored
  files and unlabelled tokens are all outside its view (the entropy
  detector in a later step covers unlabelled tokens).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .allowlist import Allowlist
from .detect import Finding, scan_text
from .gitignore import IgnoreRules

__all__ = ["ScanResult", "is_binary", "scan_file", "scan_path"]

# Directories that are never scanned, even with --no-gitignore: the
# version-control metadata itself is not project source.
_ALWAYS_SKIP_DIRS = {".git"}

# How many bytes to sniff when deciding whether a file is binary.
_BINARY_SNIFF_BYTES = 8192


def is_binary(data: bytes) -> bool:
    """True if ``data`` looks binary: a NUL byte in the sniffed prefix."""
    return b"\x00" in data[:_BINARY_SNIFF_BYTES]


@dataclass
class ScanResult:
    """Everything one scan found, plus what it skipped."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    # (root-relative path, reason) for every file that was not scanned.
    files_skipped: list[tuple[str, str]] = field(default_factory=list)


def _read_text(path: Path) -> str | None:
    """Read ``path`` as text, or None if it is binary or unreadable."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if is_binary(data):
        return None
    # Not valid UTF-8? Scan what we can rather than skipping the file:
    # replacement characters cannot create a secret-shaped match.
    return data.decode("utf-8", errors="replace")


def scan_file(path: str | Path, display_path: str | None = None) -> list[Finding]:
    """Scan one file and return its findings.

    ``display_path`` is the name recorded on the findings (the
    root-relative path when called from :func:`scan_path`); it defaults
    to ``str(path)``. Returns ``[]`` for binary or unreadable files —
    callers that need the reason should use :func:`scan_path`.
    """
    path = Path(path)
    text = _read_text(path)
    if text is None:
        return []
    return scan_text(text, display_path if display_path is not None else str(path))


def scan_path(
    root: str | Path,
    *,
    allowlist: Allowlist | None = None,
    use_gitignore: bool = True,
) -> ScanResult:
    """Scan a file or a directory tree and return a :class:`ScanResult`.

    ``root`` may be a single file (scanned directly, gitignore rules
    from its parent directory still apply) or a directory (walked
    recursively). When ``allowlist`` is None and ``root`` is a directory,
    ``<root>/.secret-scan-allowlist`` is loaded automatically if it
    exists. Findings matching the allowlist are dropped before they are
    returned.
    """
    root = Path(root)
    result = ScanResult()

    if root.is_file():
        _scan_one_file(root, str(root), result, allowlist)
        return result
    if not root.is_dir():
        raise FileNotFoundError(f"no such file or directory: {root}")

    if allowlist is None:
        allowlist = Allowlist.load_default(root)

    rules = IgnoreRules()
    if use_gitignore:
        _load_gitignore_files(root, rules)

    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        rel_dir = current.relative_to(root).as_posix()
        if rel_dir == ".":
            rel_dir = ""
        # Prune ignored / always-skipped directories in place so
        # os.walk never descends into them.
        kept: list[str] = []
        for name in sorted(dirnames):
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if name in _ALWAYS_SKIP_DIRS:
                continue
            if use_gitignore and rules.is_ignored(rel, is_dir=True):
                # The directory is pruned, so its files are never seen:
                # record the directory itself so the skip stays visible.
                result.files_skipped.append((rel + "/", "ignored directory"))
                continue
            kept.append(name)
        dirnames[:] = kept
        # Load a nested .gitignore before scanning this directory's files.
        # (The root one was already loaded before the walk.)
        if use_gitignore and rel_dir:
            ignore_file = current / ".gitignore"
            if ignore_file.is_file():
                try:
                    rules.add_file(rel_dir, ignore_file.read_text("utf-8", errors="replace"))
                except OSError:
                    result.files_skipped.append(
                        (_rel(root, ignore_file), "unreadable .gitignore")
                    )
        for name in sorted(filenames):
            path = current / name
            rel = _rel(root, path)
            if use_gitignore and rules.is_ignored(rel, is_dir=False):
                result.files_skipped.append((rel, "ignored by .gitignore"))
                continue
            _scan_one_file(path, rel, result, allowlist)

    return result


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _load_gitignore_files(root: Path, rules: IgnoreRules) -> None:
    """Load the root ``.gitignore`` (nested ones load during the walk)."""
    ignore_file = root / ".gitignore"
    if ignore_file.is_file():
        try:
            rules.add_file("", ignore_file.read_text("utf-8", errors="replace"))
        except OSError:
            pass  # The walk reports it when it reaches the file.


def _scan_one_file(
    path: Path,
    display_path: str,
    result: ScanResult,
    allowlist: Allowlist | None,
) -> None:
    try:
        data = path.read_bytes()
    except OSError as exc:
        result.files_skipped.append((display_path, f"unreadable: {exc.strerror or exc}"))
        return
    if is_binary(data):
        result.files_skipped.append((display_path, "binary file"))
        return
    result.files_scanned += 1
    text = data.decode("utf-8", errors="replace")
    for finding in scan_text(text, display_path):
        if allowlist is not None and allowlist.suppresses(finding):
            continue
        result.findings.append(finding)
