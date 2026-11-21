"""Allowlist for known false positives.

A project can record findings it has already reviewed in a
``.secret-scan-allowlist`` file at the scan root (or any file passed
with ``--allowlist``). One entry per line; ``#`` comments and blank
lines are ignored. Three forms, most specific first:

* ``rule-id path/glob:line`` — suppress that rule at one exact line
  of the files matching the glob (``path/glob`` uses ``fnmatch`` syntax;
  ``*`` also matches ``/``, so ``docs/*`` covers nested files).
* ``rule-id path/glob`` — suppress that rule in every matching file.
* ``rule-id`` — suppress that rule everywhere (use sparingly: it hides
  real future hits too).

Paths are matched against the root-relative path the scanner reports
(``src/config.py``, never an absolute path), so an allowlist written
for one checkout works on any machine.

An allowlist entry is a *reviewed* decision, not a claim the value is
safe: the scanner still reports the finding the first time, and only
suppresses it once a human has written the entry down.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from .detect import Finding

__all__ = ["Allowlist", "AllowlistEntry", "DEFAULT_FILENAME"]

DEFAULT_FILENAME = ".secret-scan-allowlist"


@dataclass(frozen=True)
class AllowlistEntry:
    rule: str
    path_glob: str | None = None
    line: int | None = None

    def matches(self, finding: Finding) -> bool:
        if finding.rule != self.rule:
            return False
        if self.path_glob is not None and not fnmatch.fnmatch(
            finding.file, self.path_glob
        ):
            return False
        if self.line is not None and finding.line != self.line:
            return False
        return True


class Allowlist:
    """A parsed allowlist file."""

    def __init__(self, entries: list[AllowlistEntry] | None = None) -> None:
        self.entries: list[AllowlistEntry] = list(entries or [])

    @classmethod
    def from_lines(cls, lines: list[str]) -> "Allowlist":
        entries: list[AllowlistEntry] = []
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            rule = parts[0]
            if len(parts) == 1:
                entries.append(AllowlistEntry(rule=rule))
                continue
            path_part = parts[1].strip()
            path_glob, _, line_no = path_part.rpartition(":")
            if line_no.isdigit() and path_glob:
                entries.append(
                    AllowlistEntry(
                        rule=rule, path_glob=path_glob, line=int(line_no)
                    )
                )
            else:
                entries.append(AllowlistEntry(rule=rule, path_glob=path_part))
        return cls(entries)

    @classmethod
    def from_file(cls, path: str | Path) -> "Allowlist":
        return cls.from_lines(Path(path).read_text("utf-8", errors="replace").splitlines())

    @classmethod
    def load_default(cls, root: str | Path) -> "Allowlist":
        """Load ``<root>/.secret-scan-allowlist`` if it exists, else empty."""
        candidate = Path(root) / DEFAULT_FILENAME
        if candidate.is_file():
            return cls.from_file(candidate)
        return cls()

    def suppresses(self, finding: Finding) -> bool:
        return any(entry.matches(finding) for entry in self.entries)

    def __len__(self) -> int:
        return len(self.entries)
