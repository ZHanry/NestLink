"""Installation-generation policies and owned-file transaction fixtures.

No product is signed, installed, removed or started. Root ownership is modeled
only for the two temporary fixture roots; real symlink and mode checks remain.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
FIRST = "147eb612-b6c7-4a75-ae12-a91fe7df36fd"


@unittest.skipUnless(sys.platform == "linux", "Linux lifecycle uses fcntl")
class InstallInstanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("nestlink_instance_lifecycle", ROOT / "packaging/linux/lifecycle.py")
        cls.lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.lifecycle)

    def marker(self, active=True):
        return {"schema_version":1,"namespace":"NestLink-v15","instance_id":FIRST,"active":active}

    def accepted(self):
        return {"id":"linux-x64-server","manifest_sha256":"a"*64,"package_sha256":"b"*64,"update_certificate_sha256":"c"*64,"version":"15.0.0","sequence":5,"source_revision":"d"*40,"state_compatibility":"schema19-epoch1"}

    def record(self):
        accepted = self.accepted()
        return {"schema_version":1,"role":"server","current":accepted,"previous":None,"maximum_sequence":5,"maximum_accepted":accepted,"instance":self.marker()}

    def test_upgrade_and_rollback_keep_generation_reinstall_always_changes_it(self):
        record = self.record()
        self.assertEqual(self.lifecycle.next_instance(record), self.marker())
        record.update(current=None, instance=self.marker(False))
        next_instance = self.lifecycle.next_instance(record)
        self.assertNotEqual(next_instance["instance_id"], FIRST)
        self.assertTrue(next_instance["active"])
        self.assertFalse(record["instance"]["active"])
        self.assertNotEqual(self.lifecycle.next_instance(record)["instance_id"], next_instance["instance_id"])

    def test_exact_latest_reinstall_preserves_pin_and_monotonic_acceptance(self):
        record = self.record()
        with self.assertRaises(ValueError): self.lifecycle.accepted_update(record, self.accepted())
        record.update(current=None, instance=self.marker(False))
        self.lifecycle.accepted_update(record, self.accepted())
        for key, value in (("source_revision","e"*40),("package_sha256","f"*64),("manifest_sha256","e"*64),("update_certificate_sha256","e"*64),("sequence",4)):
            proposed = self.accepted(); proposed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.lifecycle.accepted_update(record, proposed)
        proposed = self.accepted(); proposed["sequence"] = 6
        self.lifecycle.accepted_update(record, proposed)
        proposed["update_certificate_sha256"] = "e"*64
        with self.assertRaises(ValueError): self.lifecycle.accepted_update(record, proposed)

    def test_missing_active_or_ambiguous_instance_refused(self):
        for instance in (None, self.marker(False)):
            record = self.record(); record["instance"] = instance
            with self.assertRaises(ValueError): self.lifecycle.next_instance(record)
        record = self.record(); record["current"] = None
        with self.assertRaises(ValueError): self.lifecycle.next_instance(record)
        for value in ("../escape", "147EB612-b6c7-4a75-ae12-a91fe7df36fd", "00000000-0000-0000-0000-000000000000"):
            marker = self.marker(); marker["instance_id"] = value
            with self.assertRaises(ValueError): self.lifecycle.validate_instance(marker)

    def test_process_state_resolution_matches_child_entry_and_refuses_retired_id(self):
        with mock.patch.object(self.lifecycle, "public_instance", return_value=self.marker()):
            base = Path("/fixture/user/NestLink-v15")
            expected = base / "instances" / FIRST
            self.assertEqual(self.lifecycle.instance_state(Path("/fixture/install"), base), expected)
            self.assertEqual(self.lifecycle.instance_state(Path("/fixture/install"), expected), expected)
            with self.assertRaises(ValueError): self.lifecycle.instance_state(Path("/fixture/install"), base / "instances/292b8868-d739-4273-a556-65b7fe82c32c")
        with mock.patch.object(self.lifecycle, "public_instance", return_value=self.marker(False)):
            with self.assertRaises(ValueError): self.lifecycle.instance_state(Path("/fixture/install"), base)

    def root_fixture(self, path):
        actual = self.original_regular(path)
        return SimpleNamespace(st_uid=0, st_mode=actual.st_mode, st_size=actual.st_size)

    def test_power_loss_between_marker_and_receipt_restores_prior_under_retained_fence(self):
        with tempfile.TemporaryDirectory(prefix="nestlink-instance-transaction-") as temporary:
            base = Path(temporary) / "install"; root = base / "server"; root.mkdir(parents=True)
            receipts = Path(temporary) / "receipts"; receipts.mkdir()
            prior = self.record(); after = copy.deepcopy(prior)
            after["current"]["sequence"] = 6; after["maximum_sequence"] = 6
            self.lifecycle.write_new(root / "installation-incomplete.json", {"fixture":"retained"})
            self.lifecycle.write_new(root / "installation-instance.json", prior["instance"], 0o644)
            self.lifecycle.write_new(receipts / "server.json", prior)
            untouched = root / "retained-user-data"; untouched.write_bytes(b"exact old private state")
            original_atomic = self.lifecycle.atomic_json
            self.original_regular = self.lifecycle.verify.regular
            def fail_before_receipt(path, value, mode=0o600):
                if path == receipts / "server.json": raise OSError("owned fixture crash before receipt")
                original_atomic(path, value, mode)
            with mock.patch.object(self.lifecycle, "BASE", base), mock.patch.object(self.lifecycle, "RECEIPTS", receipts), mock.patch.object(self.lifecycle.verify, "regular", side_effect=self.root_fixture):
                with mock.patch.object(self.lifecycle, "atomic_json", side_effect=fail_before_receipt):
                    with self.assertRaises(OSError): self.lifecycle.commit_instance(root, "server", prior, after)
                self.assertTrue((root / "installation-instance-pending.json").is_file())
                self.assertEqual(self.lifecycle.read_receipt("server"), prior)
                self.lifecycle.recover_instance(root, "server")
                self.assertEqual(json.loads((receipts / "server.json").read_text(encoding="utf-8")), prior)
                self.assertEqual(json.loads((root / "installation-instance.json").read_text(encoding="utf-8")), prior["instance"])
                self.assertFalse((root / "installation-instance-pending.json").exists())
                self.assertTrue((root / "installation-incomplete.json").is_file())
                self.assertEqual(untouched.read_bytes(), b"exact old private state")
                self.lifecycle.commit_instance(root, "server", prior, after)
                self.assertEqual(json.loads((receipts / "server.json").read_text(encoding="utf-8")), after)
                self.assertFalse((root / "installation-instance-pending.json").exists())

    def test_public_instance_rejects_writable_marker_and_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory(prefix="nestlink-instance-marker-") as temporary:
            root = Path(temporary)
            marker = root / "installation-instance.json"
            self.lifecycle.write_new(marker, self.marker(), 0o644)
            self.original_regular = self.lifecycle.verify.regular
            with mock.patch.object(self.lifecycle.verify, "regular", side_effect=self.root_fixture):
                self.assertEqual(self.lifecycle.public_instance(root), self.marker())
                marker.chmod(0o666)
                with self.assertRaises(ValueError): self.lifecycle.public_instance(root)
                marker.chmod(0o644)
                target = root / "untouched.json"; marker.rename(target)
                original = target.read_bytes(); marker.symlink_to(target)
                with self.assertRaises(ValueError): self.lifecycle.public_instance(root)
                self.assertEqual(target.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
