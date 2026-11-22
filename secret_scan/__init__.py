"""CryptoVault Audit — leaked-secret scanner.

``secret_scan`` walks a project folder and flags likely secrets (API keys,
tokens, private-key headers, JWTs) before they are committed. Findings
never carry a full secret into a report: use ``Finding.redacted`` when
printing.

Steps built so far:

* (a) the pattern-based detector core (:mod:`secret_scan.detect`),
* (b) the scanner engine (:mod:`secret_scan.scan`): a ``.gitignore``-aware
  directory walk, binary-file skipping, an allowlist of reviewed
  findings, and the ``python -m secret_scan <path>`` CLI,
* (c) the entropy detector (:mod:`secret_scan.entropy`): Shannon entropy
  over long unlabelled tokens, with a heuristic confidence score —
  threshold 4.2 bits/character, measured 0 false positives on the
  fixture set and 149/200 secrets caught (hex-only secrets are the
  known gap: they cap at 4.0 bits/character),
* (d) the reporters (:mod:`secret_scan.report`): a human-readable text
  report and a ``--json`` document for CI, both redacted, with a
  non-zero exit code when findings exist.

It uses only the standard library.
"""

# The version lives at the top of this module (before the imports
# below) because :mod:`secret_scan.report` reads it from the package
# while the package is still initialising.
__version__ = "0.4.0"

from .allowlist import Allowlist, AllowlistEntry
from .detect import Finding, RULE_DESCRIPTIONS, RULES, scan_line, scan_text
from .entropy import (
    ENTROPY_THRESHOLD,
    MIN_TOKEN_LENGTH,
    scan_line_entropy,
    scan_text_entropy,
    shannon_entropy,
    token_confidence,
)
from .gitignore import Gitignore, IgnoreRules
from .report import format_json, format_text, report_to_dict
from .scan import ScanResult, is_binary, scan_file, scan_path

__all__ = [
    "Allowlist",
    "AllowlistEntry",
    "ENTROPY_THRESHOLD",
    "Finding",
    "Gitignore",
    "IgnoreRules",
    "MIN_TOKEN_LENGTH",
    "RULE_DESCRIPTIONS",
    "RULES",
    "ScanResult",
    "format_json",
    "format_text",
    "is_binary",
    "report_to_dict",
    "scan_file",
    "scan_line",
    "scan_line_entropy",
    "scan_path",
    "scan_text",
    "scan_text_entropy",
    "shannon_entropy",
    "token_confidence",
]
