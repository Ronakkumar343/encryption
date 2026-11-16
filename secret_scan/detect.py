"""Pattern-based secret detection.

The detector core of the CryptoVault Audit scanner. It scans text line by
line against a small library of high-confidence secret formats and returns
:class:`Finding` objects carrying the rule id, file, 1-based line and column,
and the matched value.

Honesty notes
-------------
* Every pattern here targets a *format* with a fixed, recognisable shape
  (a known prefix plus a fixed-length token, a PEM header, a JWT). A match
  is strong evidence, not proof — a placeholder built from a real prefix
  plus filler characters still matches the Stripe shape, so the scanner
  reports "likely secret", never "confirmed secret".
* The generic assigned-secret rule only fires when a value is explicitly
  labelled (``api_key = "..."`` and friends). An unlabelled long token is
  the entropy detector's job (a later step), not this module's.
* Fixtures in the tests use SYNTHETIC values only — the documented AWS
  example key and obviously invented tokens. Never a real key.
* ``Finding.matched`` holds the full matched value so callers can act on
  it (for example, to check it against an allowlist). Anything shown to a
  human must go through ``Finding.redacted`` instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "Finding",
    "RULE_DESCRIPTIONS",
    "RULES",
    "scan_line",
    "scan_text",
]


@dataclass(frozen=True)
class Finding:
    """One likely secret found in one line of one file."""

    rule: str
    file: str
    line: int
    column: int  # 1-based column where the matched value starts
    matched: str

    @property
    def redacted(self) -> str:
        """The matched value with its middle hidden.

        Long values show the first and last 4 characters only
        (``AKIA...MPLE``); short values are masked entirely, so a report
        never leaks a usable secret.
        """
        value = self.matched
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}...{value[-4:]}"


# Each rule: (rule id, compiled pattern, capture-group holding the secret).
# Group 0 for whole-match rules; group 1 for the generic rule, where the
# match includes the label and quotes and only the value is the secret.
RULES: list[tuple[str, "re.Pattern[str]", int]] = [
    (
        "aws-access-key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        0,
    ),
    (
        "github-token",
        # Classic personal access tokens and OAuth/server-to-server tokens:
        # ghp_ (PAT), gho_ (OAuth), ghu_ (user-to-server), ghs_ (server),
        # ghr_ (refresh) — each followed by 36 alphanumerics.
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
        0,
    ),
    (
        "github-fine-grained-token",
        # Fine-grained PATs: github_pat_ + 22 chars + _ + 59 chars.
        re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"),
        0,
    ),
    (
        "stripe-live-key",
        # Live secret keys only — sk_test_ keys are harmless test keys
        # and are deliberately NOT flagged.
        re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        0,
    ),
    (
        "private-key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
        ),
        0,
    ),
    (
        "jwt",
        # header.payload.signature, each part base64url; the header and
        # payload of a real JWT both decode to JSON starting with "eyJ".
        re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        0,
    ),
    (
        "generic-assigned-secret",
        # A labelled assignment: api_key / secret / token / password, then
        # a quoted value of at least 16 characters. The label is what
        # makes this rule trustworthy enough for the pattern stage; an
        # unlabelled token needs the entropy detector (later step).
        re.compile(
            r"""(?i)(?:api[_-]?key|api[_-]?secret|secret[_-]?key"""
            r"""|access[_-]?token|auth[_-]?token|password|passwd|pwd)"""
            r"""\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{16,})["']"""
        ),
        1,
    ),
]

RULE_DESCRIPTIONS: dict[str, str] = {
    "aws-access-key": "AWS access key ID (AKIA + 16 characters)",
    "github-token": "GitHub classic token (ghp_/gho_/ghu_/ghs_/ghr_ + 36 characters)",
    "github-fine-grained-token": "GitHub fine-grained personal access token",
    "stripe-live-key": "Stripe live secret key (sk_live_)",
    "private-key": "PEM private-key header",
    "jwt": "JSON Web Token (header.payload.signature)",
    "generic-assigned-secret": "Labelled assignment of a long secret value",
}


def scan_line(line: str, path: str, lineno: int) -> list[Finding]:
    """Scan one line and return every finding, ordered by column then rule.

    Different rules may flag the same span (for example, an AWS key stored
    under ``api_key = ...`` matches both the AWS rule and the generic
    rule); both findings are reported, since each rule is independent
    evidence.
    """
    findings: list[Finding] = []
    for rule_id, pattern, group in RULES:
        for match in pattern.finditer(line):
            value = match.group(group)
            findings.append(
                Finding(
                    rule=rule_id,
                    file=path,
                    line=lineno,
                    column=match.start(group) + 1,
                    matched=value,
                )
            )
    findings.sort(key=lambda finding: (finding.column, finding.rule))
    return findings


def scan_text(text: str, path: str = "<string>") -> list[Finding]:
    """Scan a whole text, returning findings in file order."""
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        findings.extend(scan_line(line, path, lineno))
    return findings
