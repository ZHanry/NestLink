"""Preservation metadata must not turn incomplete observations into byte proof."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("remote_history", ROOT / "scripts/refactor-remote-history-inventory.py")
INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INVENTORY)

class RemoteHistoryInventoryTests(unittest.TestCase):
    def test_pages_keep_every_page_and_reject_duplicate_ids_or_non_arrays(self):
        first = [{"id": n} for n in range(1, 101)]
        self.assertEqual(len(INVENTORY.pages([first, [{"id": 101}]])), 101)
        for value in [[first, [{"id": 100}]], {"id": 1}, [[{"id": True}]], [[{"id": -1}]], [[{}]]]:
            with self.assertRaises(ValueError):
                INVENTORY.pages(value)

    def test_repository_rename_or_replacement_is_not_silently_accepted(self):
        value = {"node_id": "approved-id", "full_name": "ZHanry/home-tunnel"}
        INVENTORY.validate_repository(value, "ZHanry/home-tunnel", "approved-id")
        for changed in [dict(value, node_id="other-id"), dict(value, full_name="ZHanry/other")]:
            with self.assertRaises(ValueError):
                INVENTORY.validate_repository(changed, "ZHanry/home-tunnel", "approved-id")

    def test_ref_observation_retains_annotated_tag_objects_and_peeled_commits(self):
        content = ("a" * 40 + "\trefs/heads/main\n" + "b" * 40 + "\trefs/tags/v1\n" + "c" * 40 + "\trefs/tags/v1^{}\n").encode()
        self.assertEqual(len(INVENTORY.refs(content)), 3)
        for bad in [content + content, b"wrong\trefs/heads/main\n", ("a" * 40 + "\tHEAD\n").encode()]:
            with self.assertRaises(ValueError):
                INVENTORY.refs(bad)

    def test_size_only_is_unknown_and_a_changed_remote_digest_cannot_match(self):
        candidate = {"bytes": 4, "sha256": "a" * 64}
        asset = {"id": 1, "size": 4, "name": "asset.zip", "digest": None}
        self.assertIsNone(INVENTORY.match_local(asset, [candidate])[0]["matches_current_github_digest"])
        asset["digest"] = "sha256:" + "b" * 64
        self.assertFalse(INVENTORY.match_local(asset, [candidate])[0]["matches_current_github_digest"])
        asset["digest"] = "sha256:" + "a" * 64
        self.assertTrue(INVENTORY.match_local(asset, [candidate])[0]["matches_current_github_digest"])
        asset["size"] = 5
        self.assertFalse(INVENTORY.match_local(asset, [candidate])[0]["matches_current_github_digest"])
        for digest in ["sha256:invalid", "md5:" + "a" * 32]:
            with self.assertRaises(ValueError):
                INVENTORY.asset_digest(digest)

    def test_local_candidate_cannot_escape_the_named_integration_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "integration"
            root.mkdir()
            (root / "asset").write_bytes(b"local bytes")
            (Path(folder) / "outside").write_bytes(b"outside")
            self.assertEqual(INVENTORY.local_bytes(root.resolve(), "asset")["sha256"], hashlib.sha256(b"local bytes").hexdigest())
            with self.assertRaises(ValueError):
                INVENTORY.local_bytes(root.resolve(), "../outside")

    def test_actual_file_change_during_hashing_fails_the_byte_observation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            file = root / "asset"
            file.write_bytes(b"original")
            actual_hasher = hashlib.sha256
            class Changed:
                def __init__(self):
                    self.inner = actual_hasher()
                    self.once = False
                def update(self, chunk):
                    self.inner.update(chunk)
                    if not self.once:
                        self.once = True
                        with file.open("ab") as stream:
                            stream.write(b"changed")
                def hexdigest(self):
                    return self.inner.hexdigest()
            with patch.object(INVENTORY.hashlib, "sha256", Changed), self.assertRaises(ValueError):
                INVENTORY.local_bytes(root, "asset")

    def test_previous_evidence_is_never_overwritten_or_followed_by_remote_calls(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            report = root / "report.json"
            report.write_text("preserve me", encoding="utf-8")
            with patch.object(INVENTORY, "run") as run, self.assertRaises(ValueError):
                INVENTORY.collect(root, report, root / "artifacts")
            run.assert_not_called()
            self.assertEqual(report.read_text(encoding="utf-8"), "preserve me")

if __name__ == "__main__":
    unittest.main()
