"""Final-source bundles are restored in an independent real local Git store."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("final_source_archive_test", ROOT / "scripts/refactor-final-source-archive.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
BASE_SPEC = importlib.util.spec_from_file_location("final_source_archive_api_fixture", ROOT / "tests/refactor/test_history_archive_publish.py")
BASE = importlib.util.module_from_spec(BASE_SPEC)
BASE_SPEC.loader.exec_module(BASE)


class FinalSourceArchiveTests(unittest.TestCase):
    def test_real_bundle_restore_preserves_all_refs_and_removes_owned_scratch(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            repo, out = root / "repo", root / "source-preservation"
            subprocess.run(["git", "init", "--initial-branch=main", str(repo)], check=True, capture_output=True)
            (repo / "source.txt").write_text("owned test source\n")
            for command in (("add", "source.txt"), ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture"), ("tag", "legacy-fixture")):
                subprocess.run(["git", "-C", str(repo), *command], check=True, capture_output=True)
            source = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            args = argparse.Namespace(directory=out, plan=out / "plan.json", expected_source=source)
            with patch.object(F, "ROOT", repo):
                result = F.prepare(args)
            self.assertEqual(result["refs"], 2)
            self.assertTrue(result["temporary_restore_removed"])
            self.assertFalse((out / "restore.git").exists())
            report = json.loads((out / "final-source-report.json").read_text())
            self.assertTrue(report["strict_fsck_passed"])
            self.assertTrue(report["bundle_standalone_verified"])
            self.assertEqual(report["source_revision"], source)
            self.assertEqual(subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain"]), b"")

    def test_candidate_archive_verification_reuses_digest_and_rejects_identity_drift(self):
        with tempfile.TemporaryDirectory() as scratch:
            test = BASE.ArchivePublishTests()
            args = test.fixture(Path(scratch))
            github = BASE.FakeGitHub()
            with patch.object(BASE.A, "source_check"):
                receipt = BASE.A.execute(args, github)
            plan = json.loads(args.plan.read_text())
            result = F.verify_published_plan(github, BASE.REPOSITORY, plan, receipt, BASE.A.digest(args.plan), args.plan.stat().st_size)
            self.assertEqual(result["files"], 2)
            self.assertEqual(github.downloads, 0)
            github.assets["legacy-hub-9-77.blob"]["id"] += 10000
            with self.assertRaises(ValueError):
                F.verify_published_plan(github, BASE.REPOSITORY, plan, receipt, BASE.A.digest(args.plan), args.plan.stat().st_size)


if __name__ == "__main__":
    unittest.main()
