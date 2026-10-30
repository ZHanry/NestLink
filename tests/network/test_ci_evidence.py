"""CI provenance and source-integrity regressions; run only in Actions."""

import hashlib
import importlib.util
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/network-rewrite-ci.py"
SPEC = importlib.util.spec_from_file_location("network_rewrite_ci", SCRIPT)
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.environment = {
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_REPOSITORY": "ZHanry/NestLink", "GITHUB_SHA": "a" * 40,
            "GITHUB_WORKFLOW_SHA": "b" * 40,
            "GITHUB_WORKFLOW_REF": "ZHanry/NestLink/.github/workflows/network-rewrite.yml@refs/heads/main",
            "GITHUB_WORKFLOW": "Network rewrite contract checks", "GITHUB_JOB": "contract",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
            "RUNNER_NAME": "GitHub Actions fixture", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
        }
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def test_refuses_local_and_self_hosted_execution(self):
        for updates in ({"GITHUB_ACTIONS": "false"}, {"GITHUB_ACTIONS": ""},
                        {"RUNNER_ENVIRONMENT": "self-hosted"}, {"RUNNER_ENVIRONMENT": ""}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                CI.validate_actions_environment({**self.environment, **updates})

    def test_identity_binds_source_workflow_attempt_and_runner(self):
        value = CI.validate_actions_environment(self.environment)
        self.assertEqual(value["source_revision"], "a" * 40)
        self.assertEqual(value["workflow_sha"], "b" * 40)
        self.assertEqual(value["run_attempt"], "2")
        self.assertEqual(value["runner"]["environment"], "github-hosted")
        self.assertEqual(value["run_url"], "https://github.com/ZHanry/NestLink/actions/runs/123")

    def test_refuses_wrong_repository_workflow_sha_and_missing_identity(self):
        mutations = (
            ("GITHUB_REPOSITORY", "other/NestLink"), ("GITHUB_SHA", "main"),
            ("GITHUB_WORKFLOW_SHA", "B" * 40), ("GITHUB_RUN_ATTEMPT", "0"),
            ("GITHUB_RUN_ID", "123\n456"), ("RUNNER_OS", "macOS"),
            ("GITHUB_WORKFLOW_REF", "ZHanry/NestLink/.github/workflows/unrelated.yml@refs/heads/main"),
            ("GITHUB_JOB", ""), ("RUNNER_NAME", "name\nspoof"),
        )
        for key, value in mutations:
            with self.subTest(key=key), self.assertRaises(ValueError):
                CI.validate_actions_environment({**self.environment, key: value})

    def test_evidence_must_be_new_and_outside_checkout_under_runner_temp(self):
        source = self.root / "source"
        runner_temp = self.root / "runner"
        source.mkdir()
        runner_temp.mkdir()
        expected = runner_temp / "owned"
        self.assertEqual(CI.validate_output_path(expected, source, runner_temp), expected)
        for output in (source / "hidden", self.root / "outside", runner_temp, Path("relative")):
            with self.subTest(output=str(output)), self.assertRaises(ValueError):
                CI.validate_output_path(output, source, runner_temp)
        expected.mkdir()
        with self.assertRaises(ValueError):
            CI.validate_output_path(expected, source, runner_temp)

    def test_source_snapshot_binds_actual_git_revision_status_and_lock_bytes(self):
        (self.root / "Cargo.lock").write_bytes(b"locked inputs\n")
        status = b" M Cargo.toml\0?? unexpected.txt\0"
        with patch.object(CI, "git_bytes", side_effect=[("a" * 40 + "\n").encode(), status]):
            snapshot = CI.source_snapshot(self.root, "a" * 40)
        self.assertTrue(snapshot["exact_source"])
        self.assertFalse(snapshot["clean"])
        self.assertEqual(snapshot["status_raw_sha256"], hashlib.sha256(status).hexdigest())
        self.assertEqual(snapshot["dependency_lock_sha256"], hashlib.sha256(b"locked inputs\n").hexdigest())

    def test_success_cannot_hide_dirty_source_different_sha_or_lock(self):
        before = {"exact_source": True, "clean": True, "dependency_lock_sha256": "a" * 64}
        CI.require_unchanged_source(before, dict(before))
        for changes in ({"exact_source": False}, {"clean": False}, {"dependency_lock_sha256": "b" * 64}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                CI.require_unchanged_source(before, {**before, **changes})
        with self.assertRaises(ValueError):
            CI.require_unchanged_source({**before, "clean": False}, before)

    def test_artifact_manifest_hashes_exact_bytes_and_excludes_receipt_self_hash(self):
        (self.root / "format-check.log").write_bytes(b"failure retained\n")
        (self.root / "rustfmt.patch").write_bytes(b"diff --git\n")
        (self.root / "network-rewrite-evidence.json").write_bytes(b"old receipt")
        files = CI.artifact_files(self.root)
        self.assertEqual([item["path"] for item in files], ["format-check.log", "rustfmt.patch"])
        self.assertEqual(files[0]["bytes"], len(b"failure retained\n"))
        self.assertEqual(files[0]["sha256"], hashlib.sha256(b"failure retained\n").hexdigest())
        (self.root / "format-check.log").write_bytes(b"changed")
        self.assertNotEqual(CI.artifact_files(self.root)[0]["sha256"], files[0]["sha256"])

    def test_receipt_retains_format_failure_even_when_patch_generation_succeeds(self):
        identity = CI.validate_actions_environment(self.environment)
        commands = [{"name": "format-check", "return_code": 1},
                    {"name": "format-patch-generate", "return_code": 0}]
        receipt = CI.evidence_receipt(identity, {"dependency_lock_sha256": "c" * 64}, None, commands, [], None)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["commands"][0]["return_code"], 1)
        self.assertFalse(receipt["execution_provenance"]["l2_network_experiment"])
        self.assertFalse(receipt["execution_provenance"]["target_device_acceptance"])
        self.assertEqual(receipt["acceptance_claims"], [])

    def test_receipt_never_converts_a_source_integrity_failure_into_success(self):
        identity = CI.validate_actions_environment(self.environment)
        receipt = CI.evidence_receipt(identity, None, None, [{"name": "tests", "return_code": 0}], [], "source changed")
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["failure"], "source changed")
        self.assertEqual(receipt["build_provenance"]["source_revision"], "a" * 40)
        self.assertEqual(receipt["execution_provenance"]["run_attempt"], "2")

    def test_incomplete_commands_or_missing_snapshot_cannot_generate_success(self):
        identity = CI.validate_actions_environment(self.environment)
        snapshot = {"exact_source": True, "clean": True, "dependency_lock_sha256": "a" * 64}
        complete = [{"name": name, "return_code": 0} for name in sorted(CI.REQUIRED_COMMANDS)]
        receipt = CI.evidence_receipt(identity, snapshot, dict(snapshot), complete, [], None)
        self.assertEqual(receipt["status"], "passed_l0_l1")
        for before, after, commands in ((snapshot, None, complete), (None, snapshot, complete),
                                        (snapshot, snapshot, []), (snapshot, snapshot, complete[:-1])):
            with self.subTest(before=before, after=after, commands=commands):
                receipt = CI.evidence_receipt(identity, before, after, commands, [], None)
                self.assertEqual(receipt["status"], "failed")

    def test_real_command_failure_and_success_both_keep_exact_log_digest(self):
        records = []
        for name, code in (("success", 0), ("failure", 23)):
            with self.subTest(code=code), contextlib.redirect_stdout(io.StringIO()):
                result = CI.run_command(
                    name, [sys.executable, "-B", "-c", "print('retained output'); raise SystemExit(" + str(code) + ")"],
                    self.root, self.root, records, timeout=30,
                )
            raw = (self.root / (name + ".log")).read_bytes()
            self.assertEqual(result["return_code"], code)
            self.assertIn(b"retained output", raw)
            self.assertEqual(result["log_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(result["log_bytes"], len(raw))
        self.assertEqual(len(records), 2)


if __name__ == "__main__":
    unittest.main()
