"""Tests for secret_scan.report and the --json CLI flag.

Every secret in these fixtures is SYNTHETIC: the AWS key is the example
key from Amazon's own documentation, and every other token is invented
for the test or drawn from a seeded RNG. No real credential appears
anywhere in this file. The Stripe-shaped key is built at runtime for
the same reason as in test_detect.py: GitHub's push protection rejects
even obviously fake ``sk_live_`` literals.
"""

import json
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from secret_scan import __version__
from secret_scan.detect import Finding
from secret_scan.report import format_json, format_text, report_to_dict
from secret_scan.scan import ScanResult

PROJECT_ROOT = Path(__file__).resolve().parent.parent

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # Amazon's documented example key
GITHUB_TOKEN = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


def _synthetic_stripe_key(rng: random.Random) -> str:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return "sk_live_" + "".join(rng.choice(alphabet) for _ in range(24))


STRIPE_KEY = _synthetic_stripe_key(random.Random(20261122))


def _write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _result_with_findings() -> ScanResult:
    return ScanResult(
        findings=[
            Finding("aws-access-key", "config.py", 1, 10, AWS_KEY),
            Finding("github-token", "config.py", 3, 9, GITHUB_TOKEN),
            Finding(
                "high-entropy-token", "app.py", 2, 5,
                "Xy9qLm2vRt8wZs4kPj7hNn3bVc6x", confidence=0.87,
            ),
        ],
        files_scanned=12,
        files_skipped=[("build/output.bin", "binary file")],
    )


class TextReportTests(unittest.TestCase):
    def test_finding_lines_show_redacted_value_not_the_secret(self):
        report = format_text(_result_with_findings(), "/proj")
        self.assertIn("AKIA...MPLE", report)
        self.assertIn("ghp_...6789", report)
        self.assertNotIn(AWS_KEY, report)
        self.assertNotIn(GITHUB_TOKEN, report)

    def test_findings_grouped_by_file_with_line_and_column(self):
        report = format_text(_result_with_findings(), "/proj")
        self.assertIn("config.py", report)
        self.assertIn("1:10", report)
        self.assertIn("3:9", report)
        self.assertIn("aws-access-key", report)
        self.assertIn("github-token", report)
        # config.py appears once as a heading for both of its findings.
        self.assertEqual(report.count("  config.py\n"), 1)

    def test_confidence_shown_only_below_one(self):
        report = format_text(_result_with_findings(), "/proj")
        self.assertIn("confidence 0.87", report)
        # Pattern findings (confidence 1.0) carry no confidence note.
        self.assertEqual(report.count("confidence"), 1)

    def test_clean_result_says_no_findings(self):
        report = format_text(
            ScanResult(findings=[], files_scanned=3), "/proj"
        )
        self.assertIn("No findings.", report)
        self.assertIn("Result: OK — no findings.", report)
        self.assertIn("0 finding(s)", report)
        self.assertIn("3 file(s) scanned", report)

    def test_skipped_files_listed_with_reason(self):
        report = format_text(_result_with_findings(), "/proj")
        self.assertIn("Skipped (1):", report)
        self.assertIn("build/output.bin — binary file", report)

    def test_summary_counts_and_fail_verdict(self):
        report = format_text(_result_with_findings(), "/proj")
        self.assertIn("3 finding(s) in 2 file(s)", report)
        self.assertIn("12 file(s) scanned, 1 skipped", report)
        self.assertIn("Result: FAIL — 3 finding(s) present.", report)


class JsonReportTests(unittest.TestCase):
    def test_parses_and_carries_redacted_values_only(self):
        doc = report_to_dict(_result_with_findings(), "/proj")
        text = format_json(_result_with_findings(), "/proj")
        self.assertEqual(json.loads(text), doc)
        # There is deliberately no "matched" key anywhere in the output.
        self.assertNotIn("matched", text)
        self.assertNotIn(AWS_KEY, text)
        self.assertNotIn(GITHUB_TOKEN, text)
        self.assertEqual(doc["findings"][0]["redacted"], "AKIA...MPLE")
        self.assertEqual(doc["findings"][0]["rule"], "aws-access-key")
        self.assertEqual(doc["findings"][0]["line"], 1)
        self.assertEqual(doc["findings"][0]["column"], 10)
        self.assertEqual(doc["findings"][0]["confidence"], 1.0)
        self.assertEqual(doc["findings"][2]["confidence"], 0.87)

    def test_metadata_and_summary(self):
        doc = report_to_dict(_result_with_findings(), "/proj")
        self.assertEqual(doc["tool"], "secret_scan")
        self.assertEqual(doc["version"], __version__)
        self.assertEqual(doc["root"], "/proj")
        self.assertEqual(doc["files_scanned"], 12)
        self.assertEqual(doc["summary"]["findings"], 3)
        self.assertEqual(doc["summary"]["files_with_findings"], 2)
        self.assertEqual(doc["summary"]["result"], "fail")
        self.assertEqual(
            doc["files_skipped"],
            [{"path": "build/output.bin", "reason": "binary file"}],
        )

    def test_clean_result_reports_ok(self):
        doc = report_to_dict(ScanResult(findings=[], files_scanned=3), "/proj")
        self.assertEqual(doc["findings"], [])
        self.assertEqual(doc["summary"]["result"], "ok")


class JsonCliTests(unittest.TestCase):
    def _run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "secret_scan", *args],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_json_flag_outputs_parseable_redacted_json_and_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "config.py", f'aws_key = "{AWS_KEY}"\n')
            proc = self._run_cli(str(root), "--json")
            self.assertEqual(proc.returncode, 1)
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["summary"]["result"], "fail")
            self.assertEqual(len(doc["findings"]), 1)
            self.assertEqual(doc["findings"][0]["redacted"], "AKIA...MPLE")
            self.assertNotIn(AWS_KEY, proc.stdout)
            self.assertNotIn("matched", proc.stdout)

    def test_json_flag_clean_tree_exits_0_with_ok_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "app.py", "print('hello')\n")
            proc = self._run_cli(str(root), "--json")
            self.assertEqual(proc.returncode, 0)
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["summary"]["result"], "ok")
            self.assertEqual(doc["findings"], [])

    def test_text_report_printed_for_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "config.py", f'aws_key = "{AWS_KEY}"\n')
            proc = self._run_cli(str(root))
            self.assertEqual(proc.returncode, 1)
            self.assertIn("secret_scan report", proc.stdout)
            self.assertIn("config.py", proc.stdout)
            self.assertIn("1:12", proc.stdout)
            self.assertIn("aws-access-key", proc.stdout)
            self.assertIn("AKIA...MPLE", proc.stdout)
            self.assertIn("Result: FAIL", proc.stdout)
            self.assertNotIn(AWS_KEY, proc.stdout)

    def test_text_report_printed_for_clean_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "app.py", "print('hello')\n")
            proc = self._run_cli(str(root))
            self.assertEqual(proc.returncode, 0)
            self.assertIn("No findings.", proc.stdout)
            self.assertIn("Result: OK", proc.stdout)

    def test_stripe_fixture_is_flagged_in_the_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "pay.py", f'key = "{STRIPE_KEY}"\n')
            proc = self._run_cli(str(root), "--json")
            self.assertEqual(proc.returncode, 1)
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["findings"][0]["rule"], "stripe-live-key")
            self.assertNotIn(STRIPE_KEY, proc.stdout)


if __name__ == "__main__":
    unittest.main()
