"""Safety checks for the read-only signed-package acceptance gate."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("signatures", ROOT / "scripts/refactor-signatures.py")
SIGNATURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIGNATURES)
TOOLS = {"powershell": "powershell", "apksigner": "apksigner", "aapt2": "aapt2", "java": "java"}


class SignatureGateTests(unittest.TestCase):
    def plan(self, root):
        file = root / "package.exe"
        file.write_bytes(b"test fixture, not an actual executable")
        return {"schema_version": 1, "release_version": "15.0.0", "source_revision": "a" * 40,
                "identities": {"windows_certificate_sha256": "b" * 64},
                "artifacts": [{"platform": "windows", "path": "package.exe", "sha256": SIGNATURES.sha256(file)}]}

    def test_unconfigured_template_is_blocked_and_never_launches_tools(self):
        plan = json.loads((ROOT / "config/release-signatures.template.json").read_text(encoding="utf-8"))
        with patch.object(SIGNATURES, "run") as run:
            report = SIGNATURES.check_plan(plan, ROOT, TOOLS)
        run.assert_not_called()
        self.assertFalse(report["all_checks_passed"])
        self.assertTrue(all(c["status"] == "blocked" for c in report["checks"]))

    def test_changed_package_is_rejected_before_certificate_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.plan(root)
            (root / "package.exe").write_bytes(b"changed")
            with patch.object(SIGNATURES, "verify_source"), patch.object(SIGNATURES, "windows_signature") as verify:
                report = SIGNATURES.check_plan(plan, root, TOOLS)
            verify.assert_not_called()
            self.assertEqual(report["checks"][0]["status"], "failed")

    def test_change_during_verification_does_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.plan(root)
            def changed(*_):
                (root / "package.exe").write_bytes(b"changed during verification")
                return {"status": "Valid"}
            with patch.object(SIGNATURES, "verify_source"), patch.object(SIGNATURES, "windows_signature", side_effect=changed):
                report = SIGNATURES.check_plan(plan, root, TOOLS)
            self.assertFalse(report["all_checks_passed"])
            self.assertIn("changed during", report["checks"][0]["reason"])

    def test_paths_and_links_cannot_escape_the_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for value in ["../package.exe", "C:/package.exe", "C:package.exe", "/package.exe", "dir\\package.exe"]:
                with self.assertRaises(ValueError):
                    SIGNATURES.artifact_path(root, value)

    def test_untrusted_windows_result_wrong_signer_or_timestamp_is_rejected(self):
        expected = "b" * 64
        for changes in [{"status": "NotTrusted"}, {"certificate_sha256": "c" * 64}, {"timestamp_certificate_sha256": None}, {"code_signing_eku": False}]:
            value = {"status": "Valid", "certificate_sha256": expected, "timestamp_certificate_sha256": "d" * 64, "code_signing_eku": True}
            value.update(changes)
            with patch.object(SIGNATURES.sys, "platform", "win32"), patch.object(SIGNATURES, "run", return_value=(0, json.dumps(value))):
                with self.assertRaises(ValueError):
                    SIGNATURES.windows_signature(Path("test.exe"), expected, "powershell")

    def test_android_checks_signature_compatibility_range_identity_package_and_abi(self):
        expected = "b" * 64
        signature = "Verified using v2 scheme (APK Signature Scheme v2): true\nSigner #1 certificate SHA-256 digest: " + expected + "\n"
        for minimum_field in ("minSdkVersion", "sdkVersion"):
            with self.subTest(minimum_field=minimum_field):
                badging = f"package: name='io.example.nestlink' versionCode='150000' versionName='15.0.0'\n{minimum_field}:'30'\ntargetSdkVersion:'36'\nnative-code: 'arm64-v8a'\n"
                with patch.object(SIGNATURES, "run", side_effect=[(0, signature), (0, badging)]) as run:
                    result = SIGNATURES.android_signature(Path("test.apk"), expected, "io.example.nestlink", "15.0.0", ["arm64-v8a"], "apksigner.jar", "aapt2", "java")
                self.assertEqual(result["signature_compatibility_sdk_range"], [30, 36])
                self.assertEqual(result["minimum_sdk"], 30)
                command = run.call_args_list[0].args[0]
                self.assertEqual(command[:3], ["java", "-jar", "apksigner.jar"])
                self.assertEqual(command[command.index("--min-sdk-version") + 1], "30")
                self.assertIn("--max-sdk-version", command)
        badging = "package: name='io.example.nestlink' versionCode='150000' versionName='15.0.0'\nminSdkVersion:'30'\ntargetSdkVersion:'36'\nnative-code: 'arm64-v8a'\n"
        with patch.object(SIGNATURES, "run", side_effect=[(0, signature), (0, badging)]):
            with self.assertRaises(ValueError):
                SIGNATURES.android_signature(Path("test.apk"), expected, "io.example.nestlink", "15.0.0", ["x86_64"], "apksigner", "aapt2", "java")

    def test_fixed_commit_and_clean_tracked_tree_are_required(self):
        for replies in [[(0, "c" * 40)], [(0, "a" * 40), (0, " M Cargo.toml")]]:
            with patch.object(SIGNATURES, "run", side_effect=replies):
                with self.assertRaises(ValueError):
                    SIGNATURES.verify_source(ROOT, "a" * 40)


if __name__ == "__main__":
    unittest.main()
