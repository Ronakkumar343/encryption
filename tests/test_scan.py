"""Tests for secret_scan.scan — the scanner engine (step 9b).

Every secret in these fixtures is SYNTHETIC: the AWS key is the example
key from Amazon's own documentation, and every other token is invented
for the test. Stripe-shaped keys are built at runtime from a seeded RNG
so no key-shaped literal appears in this file — GitHub's push
protection rejects even obviously fake ``sk_live_`` literals.
No real credential appears anywhere in this file.
"""

import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from secret_scan.allowlist import Allowlist
from secret_scan.detect import Finding
from secret_scan.gitignore import IgnoreRules
from secret_scan.scan import ScanResult, is_binary, scan_file, scan_path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # Amazon's documented example key
GITHUB_TOKEN = "ghp_" + "Z" * 36


def _synthetic_stripe_key(prefix: str, rng: random.Random) -> str:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return prefix + "".join(rng.choice(alphabet) for _ in range(24))


_rng = random.Random(20261117)
STRIPE_LIVE_KEY = _synthetic_stripe_key("sk_live_", _rng)


def _write(root: Path, rel: str, content: str | bytes) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


class GitignoreTests(unittest.TestCase):
    def test_basename_pattern_matches_at_any_depth(self):
        rules = IgnoreRules.from_text("*.log\n")
        self.assertTrue(rules.is_ignored("debug.log"))
        self.assertTrue(rules.is_ignored("sub/deep/debug.log"))
        self.assertFalse(rules.is_ignored("debug.txt"))

    def test_negation_reincludes_a_file(self):
        rules = IgnoreRules.from_text("*.log\n!keep.log\n")
        self.assertTrue(rules.is_ignored("debug.log"))
        self.assertFalse(rules.is_ignored("keep.log"))

    def test_directory_pattern_ignores_everything_beneath(self):
        rules = IgnoreRules.from_text("build/\n")
        self.assertTrue(rules.is_ignored("build", is_dir=True))
        self.assertTrue(rules.is_ignored("build/output.py"))
        self.assertFalse(rules.is_ignored("src/build.py"))

    def test_anchored_pattern_only_matches_at_the_root(self):
        rules = IgnoreRules.from_text("/root.txt\n")
        self.assertTrue(rules.is_ignored("root.txt"))
        self.assertFalse(rules.is_ignored("sub/root.txt"))

    def test_negation_cannot_reinclude_inside_an_ignored_directory(self):
        # Same rule as git: once a directory is excluded, a negated file
        # inside it stays excluded.
        rules = IgnoreRules.from_text("build/\n!build/keep.py\n")
        self.assertTrue(rules.is_ignored("build/keep.py"))

    def test_double_star_matches_across_directories(self):
        rules = IgnoreRules.from_text("**/temp.txt\n")
        self.assertTrue(rules.is_ignored("a/b/temp.txt"))
        self.assertTrue(rules.is_ignored("temp.txt"))


class BinaryTests(unittest.TestCase):
    def test_nul_byte_means_binary(self):
        self.assertTrue(is_binary(b"hello\x00world"))
        self.assertTrue(is_binary(b"\x00" + b"x" * 9000))
        self.assertFalse(is_binary(b"plain text, no NULs here\n"))

    def test_binary_file_is_skipped_not_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "data.bin", b"\x00\x01\x02" + AWS_KEY.encode())
            result = scan_path(root)
            self.assertEqual(result.findings, [])
            self.assertEqual(result.files_scanned, 0)
            self.assertEqual(
                result.files_skipped, [("data.bin", "binary file")]
            )


class ScanPathTests(unittest.TestCase):
    def test_finds_secrets_in_nested_files_with_relative_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "config.py", f'aws_key = "{AWS_KEY}"\n')
            _write(root, "sub/token.txt", f"token {GITHUB_TOKEN}\n")
            _write(root, "clean.py", "x = 1\n")
            result = scan_path(root)
            self.assertEqual(result.files_scanned, 3)
            self.assertEqual(
                [(f.rule, f.file) for f in result.findings],
                [
                    ("aws-access-key", "config.py"),
                    ("github-token", "sub/token.txt"),
                ],
            )
            self.assertEqual(result.files_skipped, [])

    def test_git_directory_is_always_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, ".git/config", f"token {GITHUB_TOKEN}\n")
            _write(root, "app.py", "x = 1\n")
            # Even with gitignore handling off, .git is never scanned.
            result = scan_path(root, use_gitignore=False)
            self.assertEqual(result.findings, [])
            self.assertEqual(result.files_scanned, 1)

    def test_gitignore_skips_files_and_reports_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, ".gitignore", "*.log\nbuild/\n")
            _write(root, "debug.log", f"key {AWS_KEY}\n")
            _write(root, "build/out.py", f"key {AWS_KEY}\n")
            _write(root, "main.py", "x = 1\n")
            result = scan_path(root)
            self.assertEqual(result.findings, [])
            self.assertEqual(result.files_scanned, 2)  # main.py + .gitignore
            # build/ is pruned as a directory (its files are never seen),
            # so the directory itself is the recorded skip.
            self.assertEqual(
                sorted(result.files_skipped),
                [
                    ("build/", "ignored directory"),
                    ("debug.log", "ignored by .gitignore"),
                ],
            )

    def test_nested_gitignore_applies_to_its_own_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "sub/.gitignore", "notes.txt\n")
            _write(root, "sub/notes.txt", f"key {AWS_KEY}\n")
            _write(root, "notes.txt", f"key {AWS_KEY}\n")
            result = scan_path(root)
            # The nested ignore hides sub/notes.txt; the root one is found.
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0].file, "notes.txt")

    def test_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan_path("/definitely/not/a/real/path")

    def test_scan_file_reports_one_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = _write(root, "a.py", f"line one\nkey = {AWS_KEY}\n")
            findings = scan_file(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].line, 2)
            self.assertEqual(findings[0].rule, "aws-access-key")


class AllowlistTests(unittest.TestCase):
    def _project_with_two_hits(self, root: Path) -> Path:
        return _write(
            root,
            "config.py",
            f'aws_key = "{AWS_KEY}"\n'
            "clean = 1\n"
            f'stripe = "{STRIPE_LIVE_KEY}"\n',
        )

    def test_rule_and_path_suppresses_only_that_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project_with_two_hits(root)
            _write(root, "other.py", f'aws_key = "{AWS_KEY}"\n')
            allowlist = Allowlist.from_lines(["aws-access-key config.py"])
            result = scan_path(root, allowlist=allowlist)
            rules = sorted(f.rule for f in result.findings)
            self.assertEqual(rules, ["aws-access-key", "stripe-live-key"])

    def test_rule_path_and_line_suppresses_only_that_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project_with_two_hits(root)
            allowlist = Allowlist.from_lines(["aws-access-key config.py:1"])
            result = scan_path(root, allowlist=allowlist)
            self.assertEqual(
                [f.rule for f in result.findings], ["stripe-live-key"]
            )

    def test_rule_only_suppresses_everywhere(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project_with_two_hits(root)
            allowlist = Allowlist.from_lines(["aws-access-key"])
            result = scan_path(root, allowlist=allowlist)
            self.assertEqual(
                [f.rule for f in result.findings], ["stripe-live-key"]
            )

    def test_non_matching_entry_suppresses_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project_with_two_hits(root)
            allowlist = Allowlist.from_lines(
                ["aws-access-key other.py", "jwt config.py:1"]
            )
            result = scan_path(root, allowlist=allowlist)
            self.assertEqual(len(result.findings), 2)

    def test_default_allowlist_file_is_loaded_automatically(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project_with_two_hits(root)
            _write(
                root,
                ".secret-scan-allowlist",
                "# reviewed: example key in the docs\n"
                "aws-access-key config.py:1\n",
            )
            result = scan_path(root)
            self.assertEqual(
                [f.rule for f in result.findings], ["stripe-live-key"]
            )

    def test_allowlist_entry_parsing(self):
        allowlist = Allowlist.from_lines(
            [
                "# a comment",
                "",
                "aws-access-key",
                "github-token src/*.py",
                "stripe-live-key config.py:12",
            ]
        )
        self.assertEqual(len(allowlist), 3)
        self.assertTrue(
            allowlist.suppresses(
                Finding("aws-access-key", "anywhere.py", 5, 1, "x")
            )
        )
        self.assertTrue(
            allowlist.suppresses(
                Finding("github-token", "src/auth.py", 2, 1, "x")
            )
        )
        self.assertFalse(
            allowlist.suppresses(
                Finding("github-token", "tests/auth.py", 2, 1, "x")
            )
        )
        self.assertTrue(
            allowlist.suppresses(
                Finding("stripe-live-key", "config.py", 12, 1, "x")
            )
        )
        self.assertFalse(
            allowlist.suppresses(
                Finding("stripe-live-key", "config.py", 13, 1, "x")
            )
        )


class CliTests(unittest.TestCase):
    def _run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "secret_scan", *args],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_cli_reports_findings_redacted_and_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "config.py", f'aws_key = "{AWS_KEY}"\n')
            proc = self._run_cli(str(root))
            self.assertEqual(proc.returncode, 1)
            self.assertIn("config.py", proc.stdout)
            self.assertIn("1:12", proc.stdout)
            self.assertIn("aws-access-key", proc.stdout)
            self.assertIn("AKIA...MPLE", proc.stdout)
            self.assertNotIn(AWS_KEY, proc.stdout)

    def test_cli_clean_tree_exits_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "app.py", "print('hello')\n")
            proc = self._run_cli(str(root))
            self.assertEqual(proc.returncode, 0)
            self.assertIn("No findings.", proc.stdout)
            self.assertIn("Result: OK", proc.stdout)

    def test_cli_missing_path_exits_2(self):
        proc = self._run_cli("/definitely/not/a/real/path")
        self.assertEqual(proc.returncode, 2)

    def test_cli_single_file_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = _write(root, "token.txt", f"token {GITHUB_TOKEN}\n")
            proc = self._run_cli(str(path))
            self.assertEqual(proc.returncode, 1)
            self.assertIn("github-token", proc.stdout)

    def test_cli_allowlist_flag_suppresses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "config.py", f'aws_key = "{AWS_KEY}"\n')
            allow = _write(
                root, "my-allowlist.txt", "aws-access-key config.py\n"
            )
            proc = self._run_cli(str(root), "--allowlist", str(allow))
            self.assertEqual(proc.returncode, 0)
            self.assertIn("No findings.", proc.stdout)
            self.assertIn("Result: OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
