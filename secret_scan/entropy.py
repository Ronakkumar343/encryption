"""Shannon-entropy detector for unlabelled high-entropy tokens.

The pattern stage (:mod:`secret_scan.detect`) only catches secrets with a
recognisable shape — a known prefix, a PEM header, a JWT — or a value that
is explicitly labelled (``api_key = "..."``). A bare random-looking token
with no label and no known prefix slips past it. This module catches
that case: it measures the Shannon entropy of every long token-like
string on a line and flags the ones that look random.

Honesty notes
-------------
* Entropy is a *heuristic*, not a proof. The confidence attached to a
  finding is a ranking signal (how far the token sits above the
  threshold, and how long it is), never a probability that the token
  is a real secret. Report it as "likely secret", as with the pattern
  rules.
* Thresholds are measured, not guessed. On the fixture set in
  ``tests/test_entropy.py`` (200 synthetic secret-like tokens and 100
  benign code/text tokens, seeded RNG):

  * threshold 4.2 bits/character, minimum length 20 characters,
  * recall 149/200 (74.5%) overall — and 149/150 (99.3%) once the 50
    hex-only secrets are set aside,
  * false positives 0/100.

  The hex gap is structural, not a bug: a hex string uses 16 symbols,
  so its entropy can never exceed log2(16) = 4.0 bits/character, which
  is below the threshold — and a real hex digest (a git SHA, a
  checksum) looks exactly the same. Entropy cannot tell a hex secret
  from a hex digest; that is what the pattern rules are for. The
  threshold is deliberately set above 4.0 so ordinary hex digests are
  not flagged.
* Fixtures use SYNTHETIC values only — seeded random strings. Never a
  real key.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from .detect import Finding

__all__ = [
    "ENTROPY_THRESHOLD",
    "MIN_TOKEN_LENGTH",
    "TOKEN_RE",
    "scan_line_entropy",
    "scan_text_entropy",
    "shannon_entropy",
    "token_confidence",
]

# Measured on the fixture set (see the module docstring): 4.2 keeps the
# false-positive rate at 0/100 while catching 99.3% of non-hex secrets.
ENTROPY_THRESHOLD = 4.2
MIN_TOKEN_LENGTH = 20

# Token-like strings: letters, digits and the characters that appear in
# base64/base64url/hex tokens, at least MIN_TOKEN_LENGTH long. Shorter
# strings carry too little entropy signal to judge.
TOKEN_RE = re.compile(r"[A-Za-z0-9_\-./+=]{%d,}" % MIN_TOKEN_LENGTH)


def shannon_entropy(token: str) -> float:
    """Shannon entropy of ``token`` in bits per character.

    0.0 for a single repeated character; log2 of the alphabet size for a
    perfectly uniform token (4.0 for hex, ~5.95 for base62). Empty input
    is 0.0.
    """
    if not token:
        return 0.0
    counts = Counter(token)
    length = len(token)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def token_confidence(entropy: float, length: int) -> float:
    """Heuristic confidence (0..1) that a token is a secret.

    A ranking signal only, never a probability: 70% from how far the
    entropy sits above the threshold (4.2 -> 0, 5.2 -> 1) and 30% from
    length (20 chars -> 0, 40 chars -> 1). A 32-character token at the
    median secret entropy of 4.54 scores about 0.42.
    """
    entropy_part = min(1.0, max(0.0, (entropy - ENTROPY_THRESHOLD) / 1.0))
    length_part = min(1.0, max(0.0, (length - MIN_TOKEN_LENGTH) / 20.0))
    return round(0.7 * entropy_part + 0.3 * length_part, 3)


def scan_line_entropy(line: str, path: str, lineno: int) -> list[Finding]:
    """Flag high-entropy tokens on one line.

    Returns one :class:`Finding` per flagged token (rule id
    ``"high-entropy-token"``), ordered by column. A token already flagged
    by a pattern rule is still reported here — the two rules are
    independent evidence, the same convention as :mod:`secret_scan.detect`.
    """
    findings: list[Finding] = []
    for match in TOKEN_RE.finditer(line):
        token = match.group(0)
        entropy = shannon_entropy(token)
        if entropy < ENTROPY_THRESHOLD:
            continue
        findings.append(
            Finding(
                rule="high-entropy-token",
                file=path,
                line=lineno,
                column=match.start() + 1,
                matched=token,
                confidence=token_confidence(entropy, len(token)),
            )
        )
    return findings


def scan_text_entropy(text: str, path: str = "<string>") -> list[Finding]:
    """Flag high-entropy tokens in a whole text, in file order."""
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        findings.extend(scan_line_entropy(line, path, lineno))
    return findings
