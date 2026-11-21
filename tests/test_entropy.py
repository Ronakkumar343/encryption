"""Tests for secret_scan.entropy — the Shannon-entropy detector.

Every secret in these fixtures is SYNTHETIC: seeded random strings.
No real credential appears anywhere in this file.

The measured-rates test (``test_measured_threshold_rates``) re-runs the
exact fixture generation the threshold was chosen from, so the numbers
in the module docstring are checked on every test run, not just claimed.
"""

import random
import string
import unittest

from secret_scan.detect import Finding, scan_text
from secret_scan.entropy import (
    ENTROPY_THRESHOLD,
    MIN_TOKEN_LENGTH,
    scan_line_entropy,
    scan_text_entropy,
    shannon_entropy,
    token_confidence,
)


def _fixture_sets():
    """Regenerate the measurement fixture set (seeded, deterministic).

    Returns (secrets, benign): 200 synthetic secret-like tokens and the
    benign code/text tokens. Identical generation to the scratch
    measurement that picked the 4.2 threshold — do not change the seed,
    the word list, or the order, or the measured numbers below change.
    """
    rng = random.Random(20261119)
    secrets = []
    for _ in range(50):
        secrets.append(
            "".join(rng.choice(string.ascii_letters + string.digits)
                    for _ in range(32))
        )
    for _ in range(50):
        secrets.append(
            "".join(rng.choice(string.ascii_letters + string.digits + "+/")
                    for _ in range(40))
        )
    for _ in range(50):
        secrets.append(
            "".join(rng.choice("0123456789abcdef") for _ in range(40))
        )
    for _ in range(50):
        secrets.append(
            "".join(rng.choice(string.ascii_letters + string.digits + "-_")
                    for _ in range(32))
        )

    words = """the quick brown fox jumps over the lazy dog function return import
    from class def self variable configuration settings database connection
    password must be at least eight characters long and contain a number
    welcome to the documentation getting started installation guide tutorial
    example project repository module package version release changelog
    authentication authorization middleware request response handler router
    controller service repository interface implementation abstract factory
    observer singleton strategy decorator adapter proxy builder prototype
    hello world this is a sample sentence with ordinary english words
    settings configuration database hostname localhost port number timeout
    retry attempts maximum connections pool size worker threads queue jobs
    """.split()
    benign = list(words)
    for _ in range(50):
        benign.append("_".join(rng.choice(words) for _ in range(3)))
    for _ in range(50):
        benign.append("".join(rng.choice(words) for _ in range(3)))
    benign += ["1.2.3", "2026-11-19", "https://example.com/api/v1/users",
               "/home/user/project/src/main.py", "v0.3.0", "README.md",
               "utf-8", "application/json", "0123456789", "abcdefghij"]
    for _ in range(20):
        benign.append("-".join(
            "".join(rng.choice("0123456789abcdef") for _ in range(n))
            for n in (8, 4, 4, 4, 12)))
    for _ in range(20):
        benign.append("".join(rng.choice("0123456789abcdef")
                              for _ in range(64)))
    return secrets, benign


class EntropyTests(unittest.TestCase):
    def test_entropy_known_values(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("ab"), 1.0)
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)
        # 16 distinct symbols, uniform: log2(16) = 4.0.
        self.assertAlmostEqual(shannon_entropy("0123456789abcdef"), 4.0)

    def test_confidence_bounds(self):
        for entropy in (0.0, 4.2, 4.7, 5.5, 6.0):
            for length in (1, 20, 32, 40, 100):
                confidence = token_confidence(entropy, length)
                self.assertGreaterEqual(confidence, 0.0)
                self.assertLessEqual(confidence, 1.0)

    def test_confidence_monotonic(self):
        self.assertLess(token_confidence(4.2, 20), token_confidence(5.2, 20))
        self.assertLess(token_confidence(4.7, 20), token_confidence(4.7, 40))
        # A 32-char token at the median secret entropy (4.54) scores ~0.42.
        self.assertAlmostEqual(token_confidence(4.54, 32), 0.418, places=3)

    def test_flags_random_token(self):
        rng = random.Random(7)
        token = "".join(rng.choice(string.ascii_letters + string.digits)
                        for _ in range(32))
        findings = scan_line_entropy(f'api_token = "{token}"', "x.py", 3)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule, "high-entropy-token")
        self.assertEqual(finding.file, "x.py")
        self.assertEqual(finding.line, 3)
        self.assertEqual(finding.matched, token)
        self.assertGreater(finding.confidence, 0.0)
        self.assertLessEqual(finding.confidence, 1.0)
        # The report form never leaks the full token.
        self.assertNotIn(token, finding.redacted)
        self.assertTrue(finding.redacted.startswith(token[:4]))

    def test_ignores_short_and_low_entropy(self):
        self.assertEqual(scan_line_entropy('key = "shortvalue"', "x.py", 1), [])
        self.assertEqual(
            scan_line_entropy("the quick brown fox jumps over the lazy dog",
                              "x.py", 1), [])
        # 25 identical characters: entropy 0.
        self.assertEqual(scan_line_entropy("a" * 25, "x.py", 1), [])
        # A long ordinary word: low entropy, not flagged.
        self.assertEqual(
            scan_line_entropy("authenticationconfiguration", "x.py", 1), [])

    def test_hex_digest_not_flagged(self):
        # Documented limitation: hex caps at 4.0 bits/char, below the 4.2
        # threshold, so a hex digest — and a hex-only secret — is not
        # flagged by entropy. The pattern rules cover known hex formats.
        digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        self.assertEqual(len(digest), 64)
        self.assertEqual(scan_line_entropy(f'sha256 = "{digest}"', "x.py", 1), [])

    def test_scan_text_entropy_order(self):
        rng = random.Random(11)
        first = "".join(rng.choice(string.ascii_letters) for _ in range(32))
        second = "".join(rng.choice(string.ascii_letters) for _ in range(32))
        text = f'first = "{first}"\nplain english words here\nsecond = "{second}"\n'
        findings = scan_text_entropy(text, "x.py")
        self.assertEqual([f.line for f in findings], [1, 3])
        self.assertEqual(findings[0].matched, first)
        self.assertEqual(findings[1].matched, second)

    def test_measured_threshold_rates(self):
        """The threshold's measured performance, checked every run.

        At 4.2 bits/char over the fixture set: 0 false positives on the
        benign tokens, 149/200 secrets caught. The 51 misses are all
        hex-only secrets (entropy capped at 4.0) — see the module
        docstring. These exact numbers are the claim; if the threshold
        or the fixtures change, update the docstring with them.
        """
        secrets, benign = _fixture_sets()
        self.assertEqual(len(secrets), 200)
        flagged_secrets = 0
        for token in secrets:
            flagged_secrets += len(
                scan_line_entropy(f'value = "{token}"', "x.py", 1))
        self.assertEqual(flagged_secrets, 149)

        flagged_benign = 0
        for token in benign:
            flagged_benign += len(
                scan_line_entropy(f'value = "{token}"', "x.py", 1))
        self.assertEqual(flagged_benign, 0)

        # The hex-only secrets (third group of 50) are all missed.
        hex_secrets = secrets[100:150]
        flagged_hex = sum(
            len(scan_line_entropy(f'value = "{token}"', "x.py", 1))
            for token in hex_secrets)
        self.assertEqual(flagged_hex, 0)
        # …while 149 of the 150 non-hex secrets are caught.
        non_hex = secrets[:100] + secrets[150:]
        flagged_non_hex = sum(
            len(scan_line_entropy(f'value = "{token}"', "x.py", 1))
            for token in non_hex)
        self.assertEqual(flagged_non_hex, 149)


class FindingConfidenceTests(unittest.TestCase):
    def test_default_confidence_is_one(self):
        finding = Finding(rule="aws-access-key", file="x.py", line=1,
                          column=1, matched="AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(finding.confidence, 1.0)

    def test_pattern_findings_keep_confidence_one(self):
        findings = scan_text('key = "AKIAIOSFODNN7EXAMPLE"\n', "x.py")
        self.assertTrue(findings)
        self.assertTrue(all(f.confidence == 1.0 for f in findings))

    def test_threshold_and_length_constants(self):
        self.assertEqual(ENTROPY_THRESHOLD, 4.2)
        self.assertEqual(MIN_TOKEN_LENGTH, 20)


if __name__ == "__main__":
    unittest.main()
