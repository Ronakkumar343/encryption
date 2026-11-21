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
  known gap: they cap at 4.0 bits/character).

It uses only the standard library. The formatted reporters land in a
later step.
"""

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
    "is_binary",
    "scan_file",
    "scan_line",
    "scan_line_entropy",
    "scan_path",
    "scan_text",
    "scan_text_entropy",
    "shannon_entropy",
    "token_confidence",
]

__version__ = "0.3.0"
