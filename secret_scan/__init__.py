"""CryptoVault Audit — leaked-secret scanner.

``secret_scan`` walks a project folder and flags likely secrets (API keys,
tokens, private-key headers, JWTs) before they are committed. Findings
never carry a full secret into a report: use ``Finding.redacted`` when
printing.

This module is step (a) of the scanner: the pattern-based detector core.
It uses only the standard library. The scanner engine (directory walk,
.gitignore handling, CLI) and the entropy detector land in later steps.
"""

from .detect import Finding, RULE_DESCRIPTIONS, RULES, scan_line, scan_text

__all__ = ["Finding", "RULE_DESCRIPTIONS", "RULES", "scan_line", "scan_text"]

__version__ = "0.1.0"
