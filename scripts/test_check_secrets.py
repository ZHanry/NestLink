"""Bound public test exceptions without weakening new-secret detection."""

import base64
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_secrets_test", ROOT / "scripts/check-secrets.py")
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


class SecretScanTests(unittest.TestCase):
    @staticmethod
    def key(kind="PRIVATE KEY", line_width=64, ending=True):
        # A public, deterministic RFC 8410-shaped Ed25519 PKCS#8 fixture,
        # assembled in memory so the test source contains no embedded PEM key.
        der = bytes.fromhex("302e020100300506032b657004220420") + bytes(range(32))
        encoded = base64.b64encode(der).decode("ascii")
        body = "\n".join(encoded[index:index + line_width] for index in range(0, len(encoded), line_width))
        start = "-----" + "BEGIN " + kind + "-----\n"
        return start + body + ("\n-----" + "END " + kind + "-----\n" if ending else "")

    def test_private_key_formats_wrapping_escaped_lines_and_truncation(self):
        for kind in ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"):
            for width in (16, 64):
                with self.subTest(kind=kind, line_width=width):
                    text = self.key(kind, line_width=width)
                    for candidate in (text, text.replace("\n", "\r\n"), text.replace("\n", "\\n"), self.key(kind, width, ending=False)):
                        self.assertEqual(S.scan_text("new-source.txt", candidate)[0][2], "private-key-body")
        text = self.key("RSA PRIVATE KEY")
        first_line, rest = text.split("\n", 1)
        encrypted = first_line + "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0011223344556677\n\n" + rest
        self.assertTrue(S.scan_text("new-source.txt", encrypted))
        self.assertTrue(S.scan_text("new-source.txt", encrypted.replace("\n", "\\n")))
        marker, rest = self.key(ending=False).split("\n", 1)
        self.assertTrue(S.scan_text("new-source.txt", marker + "\n" + rest[:32]))

    def test_reviewed_invalid_pem_fixtures_still_detect_a_new_key(self):
        for relative in ("apps/desktop/src/services.rs", "apps/server/src/turn_node/tests.rs"):
            with self.subTest(path=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                self.assertEqual(S.scan_text(relative, source), [])
                self.assertTrue(any(item[2] == "private-key-body" for item in S.scan_text(relative, source + "\n" + self.key())))
        for invalid_body in ("", "invalid", "not-a-key", "AA=="):
            marker = "-----" + "BEGIN PRIVATE KEY-----\n"
            self.assertFalse(S.scan_text("parser.rs", marker + invalid_body + "\n-----" + "END PRIVATE KEY-----"))

    def test_every_public_assignment_exception_requires_exact_path_and_bytes(self):
        for relative, approved in S.PUBLIC_TEST_ASSIGNMENT_SHA256.items():
            source = (ROOT / relative).read_text(encoding="utf-8")
            reviewed = {hashlib.sha256(match.group().encode()).hexdigest(): match.group() for match in S.PATTERNS[5].finditer(source)}
            with self.subTest(path=relative):
                self.assertTrue(approved <= set(reviewed))
                self.assertEqual(S.scan_text(relative, source), [])
            for checksum in approved:
                assignment = reviewed[checksum]
                with self.subTest(path=relative, checksum=checksum):
                    self.assertEqual(S.scan_text(relative, assignment + '"'), [])
                    self.assertTrue(S.scan_text(relative + ".new", assignment + '"'))
                    self.assertTrue(S.scan_text(relative, assignment + 'changed"'))

    def test_new_provider_tokens_and_generic_credentials_fail_in_approved_paths(self):
        relative = next(iter(S.PUBLIC_TEST_ASSIGNMENT_SHA256))
        providers = (
            ("AK" + "IA" + "X" * 16, "aws-access-key"),
            ("gh" + "p_" + "X" * 24, "github-token"),
            ("github_" + "pat_" + "X" * 24, "github-fine-grained-token"),
            ("xox" + "b-" + "X" * 24, "slack-token"),
        )
        for value, rule in providers:
            with self.subTest(rule=rule):
                self.assertTrue(any(item[2] == rule for item in S.scan_text(relative, value)))
        assignment = "pass" + "word = '" + "new-unreviewed-value" + "'"
        self.assertTrue(any(item[2] == "credential-assignment" for item in S.scan_text(relative, assignment)))
        self.assertTrue(any(item[2] == "private-key-body" for item in S.scan_text(relative, self.key())))

    @staticmethod
    def git(root, *args):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, timeout=30)

    def test_git_sources_include_untracked_and_tracked_ignored_but_skip_caches(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.git(root, "init", "--quiet")
            (root / ".gitignore").write_text("/target/\n/artifacts/\n", encoding="utf-8")
            (root / "tracked source.py").write_text("print('public')\n", encoding="utf-8")
            (root / "deleted.txt").write_text("public\n", encoding="utf-8")
            self.git(root, "add", ".gitignore", "tracked source.py", "deleted.txt")
            (root / "deleted.txt").unlink()
            value = "gh" + "p_" + "Y" * 24
            for name in ("new 候选 file.py", "target/cache.py", "artifacts/untracked.py", "artifacts/tracked.py", "docs/8.0/evidence/public.txt"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value, encoding="utf-8")
            self.git(root, "add", "--force", "artifacts/tracked.py")
            (root / "image.bin").write_bytes(b"\xff\xfe\x00")
            paths = set(S.source_paths(root))
            self.assertIn("new 候选 file.py", paths)
            self.assertIn("artifacts/tracked.py", paths)
            self.assertNotIn("target/cache.py", paths)
            self.assertNotIn("artifacts/untracked.py", paths)
            with patch.object(Path, "rglob", side_effect=AssertionError("recursive scans are forbidden")):
                findings = S.scan_sources(root)
            self.assertEqual({item[0] for item in findings}, {"new 候选 file.py", "artifacts/tracked.py", "docs/8.0/evidence/public.txt"})

    def test_cli_reports_only_path_line_rule_without_secret_or_transport_output(self):
        value = "gh" + "p_" + "Z" * 24
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(S, "scan_sources", return_value=S.scan_text("new.py", "\n" + value)), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(S.main(), 1)
        output = stdout.getvalue() + stderr.getvalue()
        self.assertIn("new.py:2: github-token", output)
        self.assertNotIn(value, output)
        stdout, stderr = io.StringIO(), io.StringIO()
        error = subprocess.CalledProcessError(1, ["git"], stderr=value.encode())
        with patch.object(S, "scan_sources", side_effect=error), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(S.main(), 2)
        self.assertNotIn(value, stdout.getvalue() + stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
