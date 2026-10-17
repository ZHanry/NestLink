"""Candidate delivery keeps final acceptance pending and reuses remote archives."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


D = load("repository_delivery_test", "scripts/refactor-repository-delivery.py")
BASE = load("repository_delivery_api_fixture", "tests/refactor/test_release_publish.py")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class FakeGitHub(BASE.FakeGitHub):
    def request(self, method, path, **kwargs):
        if method == "GET" and "/releases/assets/" in path:
            self.calls.append((method, path))
            return dict(next(item for item in self.assets.values() if item["id"] == int(path.rsplit("/", 1)[1])))
        try:
            result = super().request(method, path.replace(D.TAG, "v15.0.0"), **kwargs)
        except BASE.P.Missing as error:
            # Each dynamically loaded publisher has its own exception class.
            raise D.PUBLISH.Missing() from error
        if method in ("POST", "PATCH") and path.endswith(("/releases", "/releases/15")):
            self.release.update(kwargs["value"])
            return dict(self.release)
        if method == "POST" and "/assets?name=" in path:
            self.assets[result["name"]]["digest"] = "sha256:" + digest(result["raw"])
            return dict(self.assets[result["name"]])
        return result


class RepositoryDeliveryTests(unittest.TestCase):
    def test_live_client_missing_tags_and_release_are_normal_first_delivery(self):
        github = D.ARCHIVE.A.GitHub("fixture-token")

        def read(method, path, **kwargs):
            self.assertEqual(method, "GET")
            if path == "/repos/" + BASE.REPOSITORY:
                return {"node_id": D.PUBLISH.REPOSITORY_ID, "full_name": BASE.REPOSITORY, "default_branch": "main"}
            if path.endswith("/git/ref/heads/main"):
                return {"object": {"type": "commit", "sha": BASE.REVISION}}
            raise D.ARCHIVE.A.P.Missing()

        with patch.object(github, "request", side_effect=read):
            self.assertEqual(D.remote_check(github, BASE.REPOSITORY, {"source_revision": BASE.REVISION}, []), (False, None))

    def fixture(self, root):
        revision = BASE.REVISION
        legacy = {"schema_version": 1, "purpose": "history-archive", "repository_node_id": D.PUBLISH.REPOSITORY_ID, "tag": "history-archive-test", "tag_target": "2" * 40, "preservation_review": "passed", "source_assets": [{"component": "client", "release_id": 9, "asset_id": 77, "bytes": 1965339189, "sha256": "a" * 64}], "files": [{"asset_name": "legacy-client-9-77.blob", "path": str(root / "absent-old-2gb.blob"), "bytes": 1965339189, "sha256": "a" * 64, "role": "legacy-release-asset", "original": {"component": "client", "release_id": 9, "asset_id": 77}}], "unavailable_historical_gitlinks": ["f" * 40], "final_product_source_preserved": False, "user_full_functional_acceptance": "pending"}
        final = {"schema_version": 1, "purpose": "final-source-archive", "repository_node_id": D.PUBLISH.REPOSITORY_ID, "source_revision": revision, "tag_target": revision, "tag": "history-archive-final-" + revision[:12], "files": [{"asset_name": role + ".bin", "path": str(root / (role + ".bin")), "bytes": 1, "sha256": "a" * 64, "role": role} for role in ("final-source-bundle", "final-source-report")], "final_product_source_preserved": True, "user_full_functional_acceptance": "pending"}
        for prefix, manifest in (("history", legacy), ("final-source", final)):
            raw = json.dumps(manifest).encode()
            (root / (prefix + "-archive-plan.json")).write_bytes(raw)
            receipt = {"purpose": "history-archive-receipt" if prefix == "history" else "final-source-archive-receipt", "repository_node_id": D.PUBLISH.REPOSITORY_ID, "source_revision": revision if prefix == "final-source" else None, "plan_sha256": digest(raw), "durable_remote_preservation_verified": True, "final_product_source_preserved": prefix == "final-source", "unavailable_historical_gitlinks": ["f" * 40]}
            (root / (prefix + "-archive-receipt.json")).write_text(json.dumps(receipt))
        artifacts = []
        for role in sorted(D.HANDOFF.CURRENT_ROLES | D.ARCHIVE_ROLES):
            path = root / (role + (".json" if role in D.ARCHIVE_ROLES else ".bin"))
            if not path.exists():
                path.write_bytes(role.encode())
            artifacts.append({"id": role, "role": role, "path": path.name, "bytes": path.stat().st_size, "sha256": digest(path.read_bytes()), "source_revision": revision if role in D.HANDOFF.CURRENT_ROLES else None})
        plan = {"schema_version": 1, "product": "NestLink-v15", "purpose": "repository-delivery", "version": "15.0.0", "source_revision": revision, "repository_node_id": D.PUBLISH.REPOSITORY_ID, "completion": {key: "pending" if key == "user_full_functional_acceptance" else "passed" for key in D.COMPLETION}, "signing": {key: "not-configured" for key in D.SIGNING}, "artifacts": artifacts, "acceptance_cases": [{"id": case, "status": "pending", "evidence_artifact_id": "acceptance"} for case in sorted(D.REQUIRED_CASES)]}
        file = root / "delivery.json"
        file.write_text(json.dumps(plan))
        return argparse.Namespace(plan=file, bundle=root, expected_source=revision, repository=BASE.REPOSITORY, action="publish"), plan

    def test_pending_states_are_kept_and_no_old_blob_is_read_or_uploaded(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, plan = self.fixture(Path(scratch))
            original = json.dumps(plan, sort_keys=True)
            with patch.object(D.HANDOFF.verify, "command", side_effect=[(BASE.REVISION + "\n").encode(), b""]):
                actual, uploads, archives = D.local_plan(args)
            self.assertEqual(json.dumps(actual, sort_keys=True), original)
            self.assertEqual(len(archives), 2)
            self.assertEqual(len(uploads), 23)
            self.assertFalse(any(item["role"] == "legacy-release-asset" for item in uploads))
            self.assertFalse((Path(scratch) / "absent-old-2gb.blob").exists())
            self.assertIn("90-minute-soak", D.REQUIRED_CASES)
            self.assertNotIn("72-hour-soak", D.REQUIRED_CASES)
            self.assertIn("72-hour-soak", D.HANDOFF.REQUIRED_CASES)

    def test_publishes_only_a_prerelease_and_checks_both_durable_archives(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, _ = self.fixture(Path(scratch))
            with patch.object(D.HANDOFF.verify, "command", side_effect=[(BASE.REVISION + "\n").encode(), b""]):
                local = D.local_plan(args)
            github = FakeGitHub()
            with patch.object(D, "local_plan", return_value=local), patch.object(D.ARCHIVE, "verify_published_plan") as archives:
                result = D.deliver(args, github)
            self.assertTrue(github.release["prerelease"])
            self.assertFalse(github.release["draft"])
            self.assertFalse(result["production_update_authorized"])
            self.assertEqual(result["user_full_functional_acceptance"], "pending")
            self.assertEqual(archives.call_count, 4)
            self.assertFalse(any(method == "DELETE" for method, _ in github.calls))

    def test_missing_archive_or_failed_case_prevents_any_remote_write(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, plan = self.fixture(Path(scratch))
            plan["acceptance_cases"][0]["status"] = "failed"
            with self.assertRaises(ValueError):
                D.validate(plan)
            plan["acceptance_cases"][0]["status"] = "pending"
            plan["completion"]["user_full_functional_acceptance"] = "passed"
            with self.assertRaises(ValueError):
                D.validate(plan)


if __name__ == "__main__":
    unittest.main()
