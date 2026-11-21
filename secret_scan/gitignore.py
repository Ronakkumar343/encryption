"""Minimal ``.gitignore`` pattern matching (standard library only).

This is a deliberately small subset of git's ignore rules — enough for a
secret scanner to skip the files a project already ignores, without
depending on an external package:

* ``#`` comments and blank lines are skipped.
* A trailing ``/`` marks a directory-only pattern.
* A leading ``/`` anchors the pattern to the directory holding the
  ``.gitignore`` file; a pattern with no other ``/`` matches the basename
  at any depth below that directory; any other pattern is matched
  relative to that directory.
* ``*`` matches any run of characters except ``/``, ``?`` matches one
  character except ``/``, ``**`` matches across directories, and
  ``[...]`` character classes work as in ``fnmatch``.
* ``!`` negates a pattern: the *last* matching pattern in a file wins.
  A file inside an ignored directory cannot be re-included by negating
  the file alone — the scanner never descends into ignored directories,
  which is the same behaviour git shows for ``git status``.

Patterns from deeper ``.gitignore`` files win over patterns from files
higher up the tree, exactly as git orders them.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

__all__ = ["Gitignore", "IgnoreRules"]


def _translate(pattern: str) -> str:
    """Translate one gitignore glob into a regex body (no anchors)."""
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        char = pattern[i]
        if char == "*":
            if pattern[i : i + 2] == "**":
                # "**/" matches zero or more directories; a trailing
                # "/**" matches everything below; bare "**" is ".*".
                if pattern[i : i + 3] == "**/":
                    out.append("(?:.*/)?")
                    i += 3
                elif pattern[i - 1 : i] == "/" and i + 2 == n:
                    out.append(".*")
                    i += 2
                else:
                    out.append(".*")
                    i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif char == "?":
            out.append("[^/]")
            i += 1
        elif char == "[":
            # Character class: copy through, keeping a leading "!" as "^".
            j = i + 1
            if j < n and pattern[j] in "!^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                out.append(re.escape("["))
                i += 1
            else:
                stuff = pattern[i + 1 : j]
                if stuff.startswith("!"):
                    stuff = "^" + stuff[1:]
                out.append(f"[{stuff}]")
                i = j + 1
        else:
            out.append(re.escape(char))
            i += 1
    return "".join(out)


class _Rule:
    """One parsed gitignore line, anchored to one directory."""

    def __init__(self, base: str, raw: str) -> None:
        self.negated = raw.startswith("!")
        pattern = raw[1:] if self.negated else raw
        self.dir_only = pattern.endswith("/")
        pattern = pattern.rstrip("/")
        self.anchored = pattern.startswith("/") or "/" in pattern
        pattern = pattern.lstrip("/")
        self.pattern = pattern
        body = _translate(pattern)
        if self.anchored:
            # Match from the base directory down; a directory pattern
            # also matches everything beneath it.
            regex = f"^{body}(/.*)?$" if self.dir_only else f"^{body}$"
        else:
            # Basename match at any depth below the base directory.
            regex = f"(^|.*/){body}(/.*)?$" if self.dir_only else f"(^|.*/){body}$"
        self.regex = re.compile(regex)
        # Base directory, as a posix path relative to the scan root
        # ("" for the root itself).
        self.base = base

    def matches(self, rel_path: str, is_dir: bool) -> bool:
        """True if this rule applies to ``rel_path`` (root-relative)."""
        if self.dir_only and not is_dir:
            # A directory pattern only matches a file via its parent
            # directories; the regex's "(/.*)?" suffix handles that for
            # anchored patterns, and the basename form needs the path
            # itself to be inside such a directory — checked by the
            # caller through its parent directories.
            return False
        if self.base:
            if rel_path != self.base and not rel_path.startswith(
                self.base + "/"
            ):
                return False
            rel_path = rel_path[len(self.base) + 1 :]
        return self.regex.match(rel_path) is not None


class Gitignore:
    """The parsed contents of one ``.gitignore`` file."""

    def __init__(self, base: str, text: str) -> None:
        self.base = base
        self.rules: list[_Rule] = []
        for raw_line in text.splitlines():
            line = raw_line.rstrip()
            if not line or line.startswith("#"):
                continue
            # A backslash-escaped leading "#" or "!" is a literal.
            if line.startswith("\\#") or line.startswith("\\!"):
                line = line[1:]
            self.rules.append(_Rule(base, line))

    def is_ignored(self, rel_path: str, is_dir: bool) -> bool | None:
        """Return True/False if a rule decides, else None (no opinion)."""
        decision: bool | None = None
        for rule in self.rules:
            if rule.matches(rel_path, is_dir):
                decision = not rule.negated
        return decision


class IgnoreRules:
    """The stacked ``.gitignore`` files of one scanned tree.

    ``.gitignore`` files in deeper directories override files higher up,
    and within one file the last matching pattern wins — both per git.
    """

    def __init__(self) -> None:
        # Ordered shallow-to-deep; the last decisive file wins.
        self._files: list[Gitignore] = []

    def add_file(self, base: str, text: str) -> None:
        """Register the ``.gitignore`` found in directory ``base``."""
        self._files.append(Gitignore(base, text))

    @classmethod
    def from_text(cls, text: str, base: str = "") -> "IgnoreRules":
        rules = cls()
        rules.add_file(base, text)
        return rules

    def is_ignored(self, rel_path: str, is_dir: bool = False) -> bool:
        """True if ``rel_path`` (root-relative, posix) is ignored.

        A directory-only pattern also ignores everything beneath the
        directory, so a file under an ignored directory is ignored
        even though the pattern itself only names the directory.
        """
        # Walk the path's ancestors too: "build/" ignores "build/x.py"
        # because the directory itself is ignored.
        parts = PurePosixPath(rel_path).parts
        for depth in range(1, len(parts) + 1):
            ancestor = "/".join(parts[:depth])
            ancestor_is_dir = depth < len(parts) or is_dir
            decision = self._decide(ancestor, ancestor_is_dir)
            if decision is not None:
                return decision
        return False

    def _decide(self, rel_path: str, is_dir: bool) -> bool | None:
        decision: bool | None = None
        for gitignore in self._files:
            result = gitignore.is_ignored(rel_path, is_dir)
            if result is not None:
                decision = result
        return decision
