"""Reporters: turn a scan result into something a human or CI can use.

This is step (d) of the CryptoVault Audit scanner. It renders a
:class:`secret_scan.scan.ScanResult` in two forms:

* a human-readable text report (:func:`format_text`), and
* a machine-readable JSON document (:func:`format_json`, via
  :func:`report_to_dict`), for CI pipelines that parse the result.

Honesty notes
-------------
* A report NEVER contains a full matched secret. Findings are rendered
  through :attr:`secret_scan.detect.Finding.redacted` only — the JSON
  output has no ``matched`` key at all, so even a careless consumer
  cannot leak one.
* The JSON ``confidence`` is the detector's heuristic score (a ranking
  signal, never a probability); pattern findings carry 1.0, entropy
  findings carry their computed score.
* The text report is printed even on a clean scan, so a clean result is
  visibly "no findings" rather than silence that could be mistaken for
  "the scan never ran". The CLI still exits 0 on clean, 1 on findings,
  2 on a usage error — the exit code, not the output, is what CI gates
  on.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from .scan import ScanResult

__all__ = ["format_json", "format_text", "report_to_dict"]


def report_to_dict(result: ScanResult, root: str | Path) -> dict:
    """Render ``result`` as a JSON-serialisable document.

    The document carries redacted values only — there is deliberately
    no ``matched`` key anywhere in it.
    """
    findings = [
        {
            "rule": finding.rule,
            "file": finding.file,
            "line": finding.line,
            "column": finding.column,
            "redacted": finding.redacted,
            "confidence": finding.confidence,
        }
        for finding in result.findings
    ]
    return {
        "tool": "secret_scan",
        "version": __version__,
        "root": str(root),
        "files_scanned": result.files_scanned,
        "findings": findings,
        "files_skipped": [
            {"path": path, "reason": reason}
            for path, reason in result.files_skipped
        ],
        "summary": {
            "findings": len(result.findings),
            "files_with_findings": len({f.file for f in result.findings}),
            "files_skipped": len(result.files_skipped),
            "result": "fail" if result.findings else "ok",
        },
    }


def format_json(result: ScanResult, root: str | Path) -> str:
    """Render ``result`` as a deterministic JSON document (sorted keys)."""
    return json.dumps(report_to_dict(result, root), indent=2, sort_keys=True)


def format_text(result: ScanResult, root: str | Path) -> str:
    """Render ``result`` as a human-readable text report."""
    lines = [f"secret_scan report — {root}", ""]

    if not result.findings:
        lines.append("No findings.")
    else:
        lines.append(f"Findings ({len(result.findings)}):")
        # Group by file, in the order findings were found.
        by_file: dict[str, list] = {}
        for finding in result.findings:
            by_file.setdefault(finding.file, []).append(finding)
        for file, findings in by_file.items():
            lines.append(f"  {file}")
            for finding in findings:
                confidence = (
                    f" (confidence {finding.confidence:.2f})"
                    if finding.confidence < 1.0
                    else ""
                )
                lines.append(
                    f"    {finding.line}:{finding.column}  "
                    f"{finding.rule}  {finding.redacted}{confidence}"
                )
        lines.append("")

    if result.files_skipped:
        lines.append(f"Skipped ({len(result.files_skipped)}):")
        for path, reason in result.files_skipped:
            lines.append(f"  {path} — {reason}")
        lines.append("")

    files_with_findings = len({f.file for f in result.findings})
    lines.append(
        f"Summary: {len(result.findings)} finding(s) in "
        f"{files_with_findings} file(s); {result.files_scanned} file(s) "
        f"scanned, {len(result.files_skipped)} skipped."
    )
    if result.findings:
        lines.append(
            f"Result: FAIL — {len(result.findings)} finding(s) present."
        )
    else:
        lines.append("Result: OK — no findings.")
    return "\n".join(lines) + "\n"
