"""An archival copy is complete only when its actual bytes match fixed metadata."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_archive", ROOT / "scripts/refactor-release-archive.py")
ARCHIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARCHIVE)

class ReleaseArchiveTests(unittest.TestCase):
    def asset(self, data=b"archived bytes"):
        return {"release_id": 1, "tag": "v1", "asset_id": 2, "filename": "../../untrusted.exe",
            "bytes": len(data), "github_sha256": hashlib.sha256(data).hexdigest(), "state": "uploaded"}

    def test_untrusted_filename_never_selects_an_archive_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            asset = self.asset()
            destination = ARCHIVE.asset_path(root, "hub", asset)
            self.assertTrue(destination.is_relative_to(root / "hub"))
            self.assertEqual(destination.suffix, ".blob")
            for changed in [dict(asset, asset_id="../../escape"), dict(asset, github_sha256=None), dict(asset, state="starter")]:
                with self.assertRaises(ValueError):
                    ARCHIVE.asset_path(root, "hub", changed)

    def test_corrupted_download_is_retained_without_promoting_a_verified_blob(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            asset = self.asset()
            def bad_download(_repo, _asset, destination):
                destination.write_bytes(b"corrupted")
            with patch.object(ARCHIVE, "metadata", return_value={}), patch.object(ARCHIVE, "download", side_effect=bad_download):
                record = ARCHIVE.preserve(root, root, "hub", asset)
            self.assertFalse(record["verified"])
            self.assertTrue((root / record["retained_partial_path"]).is_file())
            self.assertFalse(ARCHIVE.asset_path(root, "hub", asset).exists())

    def test_remote_change_after_download_cannot_become_a_complete_archive(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            asset = self.asset()
            with patch.object(ARCHIVE, "metadata", side_effect=[{}, ValueError("metadata changed")]), patch.object(ARCHIVE, "download", side_effect=lambda _r, _a, path: path.write_bytes(b"archived bytes")):
                record = ARCHIVE.preserve(root, root, "hub", asset)
            self.assertFalse(record["verified"])
            self.assertFalse(ARCHIVE.asset_path(root, "hub", asset).exists())
            self.assertTrue((root / record["retained_partial_path"]).exists())

    def test_existing_invalid_archive_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            asset = self.asset()
            target = ARCHIVE.asset_path(root, "hub", asset)
            target.parent.mkdir(parents=True)
            target.write_bytes(b"preserve existing bad copy")
            with patch.object(ARCHIVE, "metadata", return_value={}), patch.object(ARCHIVE, "download") as download:
                record = ARCHIVE.preserve(root, root, "hub", asset)
            self.assertFalse(record["verified"])
            download.assert_not_called()
            self.assertEqual(target.read_bytes(), b"preserve existing bad copy")

    def test_a_competing_writer_after_the_last_existence_check_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            asset = self.asset()
            target = ARCHIVE.asset_path(root, "hub", asset)
            original_link = ARCHIVE.os.link
            def compete(source, destination):
                target.write_bytes(b"keep the competing writer bytes")
                return original_link(source, destination)
            with patch.object(ARCHIVE, "metadata", return_value={}), patch.object(ARCHIVE, "download", side_effect=lambda _r, _a, path: path.write_bytes(b"archived bytes")), patch.object(ARCHIVE.os, "link", side_effect=compete):
                record = ARCHIVE.preserve(root, root, "hub", asset)
            self.assertFalse(record["verified"])
            self.assertEqual(target.read_bytes(), b"keep the competing writer bytes")
            self.assertEqual((root / record["retained_partial_path"]).read_bytes(), b"archived bytes")

    def test_existing_verified_bytes_still_require_final_current_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            asset = self.asset()
            target = ARCHIVE.asset_path(root, "hub", asset)
            target.parent.mkdir(parents=True)
            target.write_bytes(b"archived bytes")
            with patch.object(ARCHIVE, "metadata", side_effect=[{}, ValueError("metadata changed")]):
                record = ARCHIVE.preserve(root, root, "hub", asset)
            self.assertFalse(record["verified"])
            self.assertEqual(target.read_bytes(), b"archived bytes")

    def test_reverified_local_bytes_are_copied_independently_and_keep_the_original(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            root, integration = base / "archive", base / "old"
            root.mkdir()
            integration.mkdir()
            source = integration / "asset"
            source.write_bytes(b"archived bytes")
            asset = self.asset()
            asset["local_candidates"] = [{"matches_current_github_digest": True, "path_relative_to_integration_root": "asset"}]
            with patch.object(ARCHIVE, "metadata", return_value={}), patch.object(ARCHIVE, "download") as download:
                record = ARCHIVE.preserve(root, integration, "hub", asset)
            self.assertTrue(record["verified"])
            download.assert_not_called()
            self.assertEqual(source.read_bytes(), b"archived bytes")
            self.assertEqual((root / record["archive_path"]).read_bytes(), b"archived bytes")

    def test_actual_archive_mutation_during_hashing_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "asset"
            file.write_bytes(b"archived bytes")
            asset = self.asset()
            def changed(path):
                previous = hashlib.sha256(path.read_bytes()).hexdigest()
                path.write_bytes(b"changed")
                return previous
            with patch.object(ARCHIVE, "digest", side_effect=changed), self.assertRaises(ValueError):
                ARCHIVE.verify_bytes(file, asset)

if __name__ == "__main__":
    unittest.main()
