"""Tests for secret_scan.detect — the pattern-based detector core.

Every secret in these fixtures is SYNTHETIC: the AWS key is the example
key from Amazon's own documentation, and every other token is invented
for the test. No real credential appears anywhere in this file.
"""

import base64
import random
import unittest

from secret_scan.detect import Finding, RULES, scan_line, scan_text


def _b64url(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")


def _synthetic_stripe_key(prefix: str, rng: random.Random) -> str:
    """Build a Stripe-shaped key at runtime.

    No key-shaped literal may appear in this file: GitHub's push
    protection rejects even obviously fake ``sk_live_``/``sk_test_``
    literals, so the 24-character suffix is drawn from a seeded RNG
    instead of being written out. The value is deterministic (seeded),
    so the tests are stable run to run.
    """
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return prefix + "".join(rng.choice(alphabet) for _ in range(24))


_rng = random.Random(20261116)


# Synthetic fixtures -------------------------------------------------------
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # Amazon's documented example key
GITHUB_TOKEN = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
GITHUB_FINE_GRAINED = "github_pat_" + "A" * 22 + "_" + "B" * 59
STRIPE_LIVE_KEY = _synthetic_stripe_key("sk_live_", _rng)
STRIPE_TEST_KEY = _synthetic_stripe_key("sk_test_", _rng)
PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
JWT = ".".join(
    [
        _b64url('{"alg":"HS256","typ":"JWT"}'),
        _b64url('{"sub":"1234567890","name":"Test User"}'),
        _b64url("fakesignature"),
    ]
)


class AwsKeyTests(unittest.TestCase):
    def test_detects_documented_example_key(self):
        findings = scan_text(f'aws_key = "{AWS_KEY}"\n', "config.py")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule, "aws-access-key")
        self.assertEqual(finding.file, "config.py")
        self.assertEqual(finding.line, 1)
        self.assertEqual(finding.matched, AWS_KEY)

    def test_short_or_lowercase_akia_is_not_a_key(self):
        self.assertEqual(scan_text("AKIA123\n"), [])
        self.assertEqual(scan_text("akiaiosfodnn7example\n"), [])


class GitHubTokenTests(unittest.TestCase):
    def test_detects_classic_pat(self):
        findings = scan_text(f"token = {GITHUB_TOKEN}\n")
        self.assertEqual(
            [f.rule for f in findings], ["github-token"]
        )
        self.assertEqual(findings[0].matched, GITHUB_TOKEN)

    def test_detects_other_classic_prefixes(self):
        for prefix in ("gho_", "ghu_", "ghs_", "ghr_"):
            token = prefix + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
            findings = scan_text(token)
            self.assertEqual(
                [f.rule for f in findings], ["github-token"], prefix
            )

    def test_detects_fine_grained_pat(self):
        findings = scan_text(GITHUB_FINE_GRAINED)
        self.assertEqual(
            [f.rule for f in findings], ["github-fine-grained-token"]
        )
        self.assertEqual(findings[0].matched, GITHUB_FINE_GRAINED)

    def test_short_ghp_value_is_not_flagged(self):
        self.assertEqual(scan_text("ghp_short"), [])


class StripeKeyTests(unittest.TestCase):
    def test_detects_live_key(self):
        findings = scan_text(f'stripe_key = "{STRIPE_LIVE_KEY}"')
        self.assertEqual(
            [f.rule for f in findings], ["stripe-live-key"]
        )

    def test_test_key_is_not_flagged(self):
        # sk_test_ keys are harmless test keys by design.
        self.assertEqual(
            scan_text(f'stripe_key = "{STRIPE_TEST_KEY}"'), []
        )


class PrivateKeyTests(unittest.TestCase):
    def test_detects_rsa_and_plain_headers(self):
        for header in (
            "-----BEGIN PRIVATE KEY-----",
            PRIVATE_KEY_HEADER,
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ):
            findings = scan_text(header)
            self.assertEqual(
                [f.rule for f in findings], ["private-key"], header
            )

    def test_public_key_header_is_not_flagged(self):
        self.assertEqual(scan_text("-----BEGIN PUBLIC KEY-----"), [])
        self.assertEqual(scan_text("-----BEGIN CERTIFICATE-----"), [])


class JwtTests(unittest.TestCase):
    def test_detects_jwt_shape(self):
        findings = scan_text(f"Authorization: Bearer {JWT}")
        self.assertEqual([f.rule for f in findings], ["jwt"])
        self.assertEqual(findings[0].matched, JWT)

    def test_two_part_dotted_string_is_not_a_jwt(self):
        self.assertEqual(scan_text("eyJabc.eyJdef"), [])


class GenericAssignedSecretTests(unittest.TestCase):
    def test_detects_labelled_assignment(self):
        findings = scan_text('api_key = "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"')
        self.assertEqual(
            [f.rule for f in findings], ["generic-assigned-secret"]
        )
        # Only the secret value is captured, not the label or quotes.
        self.assertEqual(
            findings[0].matched, "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
        )

    def test_other_labels_and_colon_separator(self):
        for line in (
            'secret_key: "Zx9q8w7e6r5t4y3u2i1o0p9a8s7d6f"',
            "password = 'correct-horse-battery-staple-99'",
            'access_token = "tok_9f8e7d6c5b4a39281706f5e4d3c2b1a"',
        ):
            findings = scan_text(line)
            self.assertEqual(
                [f.rule for f in findings],
                ["generic-assigned-secret"],
                line,
            )

    def test_short_value_is_not_flagged(self):
        self.assertEqual(scan_text('api_key = "short"'), [])

    def test_unlabelled_long_token_is_not_flagged_here(self):
        # Unlabelled tokens are the entropy detector's job (later step);
        # the pattern stage must not guess at them.
        self.assertEqual(
            scan_text("aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdef"), []
        )


class ScanBehaviourTests(unittest.TestCase):
    def test_clean_text_has_no_findings(self):
        text = (
            "import os\n"
            'API_URL = "https://api.example.com/v1"\n'
            "# TODO: add the key handling later\n"
        )
        self.assertEqual(scan_text(text), [])

    def test_line_numbers_and_columns_are_1_based(self):
        text = "clean line\n" f"key = {GITHUB_TOKEN}\n" "clean again\n"
        findings = scan_text(text, "app.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 2)
        self.assertEqual(
            findings[0].column, text.splitlines()[1].index(GITHUB_TOKEN) + 1
        )

    def test_multiple_findings_on_one_line(self):
        line = f"{AWS_KEY} and {STRIPE_LIVE_KEY}"
        findings = scan_line(line, "x.py", 3)
        self.assertEqual(
            [f.rule for f in findings],
            ["aws-access-key", "stripe-live-key"],
        )
        self.assertTrue(all(f.line == 3 for f in findings))

    def test_same_span_can_match_two_rules(self):
        # An AWS key stored under an api_key label is evidence under
        # both rules; both findings are reported.
        findings = scan_text(f'api_key = "{AWS_KEY}"')
        self.assertEqual(
            sorted(f.rule for f in findings),
            ["aws-access-key", "generic-assigned-secret"],
        )

    def test_empty_text(self):
        self.assertEqual(scan_text(""), [])
        self.assertEqual(scan_line("", "x.py", 1), [])

    def test_every_rule_has_a_description(self):
        from secret_scan.detect import RULE_DESCRIPTIONS

        self.assertEqual(
            {rule_id for rule_id, _, _ in RULES},
            set(RULE_DESCRIPTIONS),
        )


class RedactionTests(unittest.TestCase):
    def test_redacted_keeps_first_and_last_four_only(self):
        finding = Finding("aws-access-key", "x.py", 1, 1, AWS_KEY)
        redacted = finding.redacted
        self.assertTrue(redacted.startswith("AKIA"))
        self.assertTrue(redacted.endswith("MPLE"))
        self.assertNotIn(AWS_KEY[4:-4], redacted)
        self.assertEqual(redacted, "AKIA...MPLE")

    def test_short_value_is_fully_masked(self):
        finding = Finding("jwt", "x.py", 1, 1, "abc123")
        self.assertEqual(finding.redacted, "******")
        self.assertNotIn("abc123", finding.redacted)


if __name__ == "__main__":
    unittest.main()
