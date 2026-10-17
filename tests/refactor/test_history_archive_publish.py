"""Archive transfer protocol tests use local bytes and a fake GitHub API."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("archive_publish_test", ROOT / "scripts/refactor-history-archive-publish.py")
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)
REVISION = "1" * 40
REPOSITORY = "ZHanry/home-tunnel"
TAG = "history-archive-test"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class FakeGitHub:
    def __init__(self):
        self.calls, self.tag, self.release, self.assets = [], False, None, {}
        self.downloads = 0

    @property
    def writes(self):
        return [(method, path) for method, path in self.calls if method != "GET"]

    def request(self, method, path, **kwargs):
        self.calls.append((method, path))
        base = "/repos/" + REPOSITORY
        if method == "GET" and path == base:
            return {"node_id": A.P.REPOSITORY_ID, "full_name": REPOSITORY}
        if method == "GET" and path == base + "/git/ref/tags/" + TAG:
            if not self.tag:
                raise A.P.Missing()
            return {"object": {"type": "commit", "sha": REVISION}}
        if method == "POST" and path == base + "/git/refs":
            assert kwargs["value"] == {"ref": "refs/tags/" + TAG, "sha": REVISION}
            self.tag = True
            return {}
        if method == "GET" and path == base + "/releases/tags/" + TAG:
            if self.release is None:
                raise A.P.Missing()
            return dict(self.release)
        if method == "POST" and path == base + "/releases":
            self.release = {"id": 15, **kwargs["value"]}
            return dict(self.release)
        if method == "POST" and path.startswith(base + "/releases/15/assets?name="):
            name = path.split("?name=", 1)[1]
            raw = kwargs["stream"].read()
            assert len(raw) == kwargs["length"]
            self.assets[name] = {"id": 100 + len(self.assets), "name": name, "size": len(raw), "state": "uploaded", "digest": "sha256:" + sha(raw), "raw": raw}
            return dict(self.assets[name])
        if method == "GET" and path.startswith(base + "/releases/assets/"):
            return dict(next(item for item in self.assets.values() if item["id"] == int(path.rsplit("/", 1)[1])))
        if method == "PATCH" and path == base + "/releases/15":
            self.release.update(kwargs["value"])
            return dict(self.release)
        raise AssertionError((method, path))

    def pages(self, path):
        self.calls.append(("GET", path))
        assert path == "/repos/" + REPOSITORY + "/releases/15/assets"
        return [dict(item) for item in self.assets.values()]

    def download_digest(self, repository, asset_id, size):
        self.downloads += 1
        value = next(item for item in self.assets.values() if item["id"] == asset_id)
        assert len(value["raw"]) == size
        return sha(value["raw"])


class ArchivePublishTests(unittest.TestCase):
    def fixture(self, root):
        data = root / "legacy.blob"
        data.write_bytes(b"legacy")
        plan = {"schema_version": 1, "purpose": "history-archive", "repository_node_id": A.P.REPOSITORY_ID, "tag": TAG, "tag_target": REVISION, "preservation_review": "passed", "source_assets": [{"component": "hub", "release_id": 9, "asset_id": 77, "bytes": 6, "sha256": sha(b"legacy")}], "files": [{"asset_name": "legacy-hub-9-77.blob", "path": str(data), "bytes": 6, "sha256": sha(b"legacy"), "role": "legacy-release-asset", "original": {"component": "hub", "release_id": 9, "asset_id": 77}}], "unavailable_historical_gitlinks": ["f" * 40], "final_product_source_preserved": False, "user_full_functional_acceptance": "pending"}
        path = root / "plan.json"
        path.write_text(json.dumps(plan))
        return argparse.Namespace(plan=path, repository=REPOSITORY, action="publish", max_seconds=5400, max_files=None)

    def test_upload_resume_and_readonly_verify_use_digest_without_redundant_download(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, github = self.fixture(Path(scratch)), FakeGitHub()
            with patch.object(A, "source_check"):
                result = A.execute(args, github)
                self.assertTrue(result["durable_remote_preservation_verified"])
                self.assertFalse(result["final_product_source_preserved"])
                self.assertEqual(result["user_full_functional_acceptance"], "pending")
                self.assertEqual(len(result["uploads"]), 2)
                self.assertFalse(github.release["draft"])
                self.assertTrue(github.release["prerelease"])
                before = list(github.writes)
                A.execute(args, github)
                self.assertEqual(before, github.writes)
                args.action = "verify"
                self.assertTrue(A.execute(args, github)["durable_remote_preservation_verified"])
                self.assertEqual(before, github.writes)
            self.assertEqual(github.downloads, 0)
            self.assertFalse(any(method == "DELETE" for method, _ in github.calls))

    def test_conflicting_existing_bytes_are_never_replaced(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, github = self.fixture(Path(scratch)), FakeGitHub()
            with patch.object(A, "source_check"):
                A.execute(args, github)
                github.assets["legacy-hub-9-77.blob"]["digest"] = "sha256:" + "0" * 64
                before = list(github.writes)
                with self.assertRaises(ValueError):
                    A.execute(args, github)
                self.assertEqual(github.writes, before)

    def test_bounded_batch_retains_draft_and_can_resume(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, github = self.fixture(Path(scratch)), FakeGitHub()
            args.max_files = 1
            with patch.object(A, "source_check"):
                partial = A.execute(args, github)
                self.assertEqual(partial["status"], "draft-partial")
                self.assertFalse(partial["durable_remote_preservation_verified"])
                self.assertTrue(github.release["draft"])
                self.assertTrue(A.execute(args, github)["durable_remote_preservation_verified"])

    def test_missing_digest_streams_readback_instead(self):
        github = FakeGitHub()
        github.assets["item"] = {"id": 1, "size": 6, "state": "uploaded", "raw": b"legacy"}
        self.assertEqual(A.remote_digest(github, REPOSITORY, github.assets["item"], 6), (sha(b"legacy"), "streamed-readback"))
        self.assertEqual(github.downloads, 1)

    def test_changed_source_inventory_prevents_writes(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, github = self.fixture(Path(scratch)), FakeGitHub()
            with patch.object(A, "source_check", side_effect=ValueError("source changed")), self.assertRaises(ValueError):
                A.execute(args, github)
            self.assertFalse(github.writes)

    def test_429_and_secondary_rate_limits_retry_without_revealing_token(self):
        for status, headers, body in ((429, {"Retry-After": "0"}, b"limit"), (403, {}, b"secondary rate limit")):
            with self.subTest(status=status):
                github = A.GitHub("fixture-only")
                github.opener = Mock()
                github.opener.open.side_effect = [urllib.error.HTTPError("https://api.github.com/example", status, "limited", headers, io.BytesIO(body)), io.BytesIO(b'{"ok": true}')]
                with patch.object(A.time, "sleep") as sleep:
                    self.assertEqual(github.request("GET", "/example"), {"ok": True})
                    sleep.assert_called_once()
                    self.assertEqual(github.opener.open.call_count, 2)


if __name__ == "__main__":
    unittest.main()
