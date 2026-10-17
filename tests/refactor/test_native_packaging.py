"""Pure fixed-byte/boundary tests. They do not sign or install a product."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packaging/native"))
import release_verify as verify


class FreezeSourceTests(unittest.TestCase):
    def test_freeze_requires_exact_clean_commit_including_untracked_source(self):
        git = shutil.which("git")
        if git is None:
            self.skipTest("Git is required by the native freeze command")
        spec = importlib.util.spec_from_file_location("nestlink_native_packaging", ROOT / "scripts/refactor-native-packaging.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_COUNT="0")
        with tempfile.TemporaryDirectory(prefix="nestlink-freeze-source-") as temporary, mock.patch.dict(os.environ, environment, clear=True):
            directory = Path(temporary)

            def command(*arguments):
                return subprocess.run([git, "-C", str(directory), *arguments], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout

            command("init", "--quiet", "--template=")
            cargo = directory / "Cargo.toml"
            cargo.write_text('[workspace.package]\nversion="15.0.0"\n', encoding="utf-8")
            command("-c", "core.autocrlf=false", "add", "Cargo.toml")
            command("-c", "user.name=NestLink test fixture", "-c", "user.email=fixture@invalid.example", "-c", "core.hooksPath=" + str(directory / "no-hooks"), "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "owned test fixture")
            statement = {"version": "15.0.0", "source_revision": command("rev-parse", "HEAD").decode().strip()}
            with mock.patch.object(builder, "ROOT", directory):
                builder.source_matches(statement)
                (directory / "uncommitted-source.rs").write_text("fn uncommitted() {}\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    builder.source_matches(statement)
                (directory / "uncommitted-source.rs").unlink()
                cargo.write_text('[workspace.package]\nversion="15.0.1"\n', encoding="utf-8")
                with self.assertRaises(ValueError):
                    builder.source_matches(statement)


def statement(purpose="native-payload"):
    item = {"id": "linux-x64-desktop", "platform": "linux", "architecture": "x86_64", "role": "desktop",
            "format": "executable" if purpose == "native-payload" else "deb", "path": "linux/nestlink-desktop",
            "bytes": 1, "sha256": "a" * 64, "state_compatibility": "v15-user-state-1"}
    if purpose == "native-packages":
        item["payload_manifest_sha256"] = "b" * 64
    return {"schema_version": 1, "product": "NestLink-v15", "purpose": purpose, "version": "15.0.0",
            "release_sequence": 1, "source_revision": "c" * 40, "artifacts": [item]}


class ManifestTests(unittest.TestCase):
    def test_fixed_identity_and_separate_payload_package_statements(self):
        verify.validate_manifest(statement())
        verify.validate_manifest(statement("native-packages"))
        for field, value in (("source_revision", None), ("release_sequence", 0), ("release_sequence", True),
                             ("release_sequence", 2**53), ("product", "home-tunnel"), ("version", "14.1.0"), ("version", "15.0.0-dev.1")):
            with self.subTest(field=field, value=value):
                data = statement(); data[field] = value
                with self.assertRaises(ValueError): verify.validate_manifest(data)
        data = statement(); data["artifacts"][0]["format"] = "deb"
        with self.assertRaises(ValueError): verify.validate_manifest(data)

    def test_paths_reject_both_os_escape_and_ambiguous_windows_names(self):
        for path in ("../outside", "/absolute", "C:/absolute", "C:relative", "\\\\host\\share", "a/../b", "a/./b", "a//b", "a\\b", "a/CON.txt", "a/nul", "file. ", "a\nnext"):
            with self.subTest(path=path), self.assertRaises(ValueError): verify.relative(path)
        self.assertEqual(str(verify.relative("linux-aarch64/nestlink-daemon")), "linux-aarch64/nestlink-daemon")

    def test_duplicate_ids_case_collisions_and_unknown_fields_refused(self):
        for mutate in (lambda x: x.update(extra=True), lambda x: x["artifacts"].append(copy.deepcopy(x["artifacts"][0]))):
            data = statement(); mutate(data)
            with self.assertRaises(ValueError): verify.validate_manifest(data)
        data = statement(); duplicate = copy.deepcopy(data["artifacts"][0]); duplicate["id"] += "-second"; duplicate["path"] = duplicate["path"].upper(); data["artifacts"].append(duplicate)
        with self.assertRaises(ValueError): verify.validate_manifest(data)

    def test_manifest_size_duplicate_json_fields_and_null_template_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="nestlink-metadata-") as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaises(ValueError): verify.bounded_json(path)
            path.write_bytes(b" " * (verify.MAX_MANIFEST + 1))
            with self.assertRaises(ValueError): verify.bounded_json(path)
        template = json.loads((ROOT / "config/native-payload.template.json").read_text(encoding="utf-8"))
        with self.assertRaises(ValueError): verify.validate_manifest(template)

    def test_fixed_bytes_reject_mutation_and_selected_rollback_cache_is_self_contained(self):
        with tempfile.TemporaryDirectory(prefix="nestlink-package-bytes-") as temporary:
            root = Path(temporary)
            (root / "linux").mkdir(); product = root / "linux/nestlink-desktop"; product.write_bytes(b"x")
            data = statement("native-packages"); data["artifacts"][0]["sha256"] = verify.sha256(product)
            other = copy.deepcopy(data["artifacts"][0]); other["id"] = "linux-arm64-desktop"; other["architecture"] = "aarch64"; other["path"] = "missing-other-platform.deb"; data["artifacts"].append(other)
            manifest = root / "manifest.json"; manifest.write_text(json.dumps(data), encoding="utf-8")
            with mock.patch.object(verify, "verify_cms"):
                result = verify.verify_selected(root, manifest, root / "signature", root / "certificate", "e" * 64, "linux-x64-desktop")
                self.assertEqual(result[2], product)
                product.write_bytes(b"y")
                with self.assertRaises(ValueError): verify.verify_selected(root, manifest, root / "signature", root / "certificate", "e" * 64, "linux-x64-desktop")

    def test_linked_artifacts_are_never_read_as_fixed_payload(self):
        with tempfile.TemporaryDirectory(prefix="nestlink-artifact-link-") as temporary:
            root = Path(temporary); outside = root / "outside"; outside.write_bytes(b"unchanged")
            try: (root / "linked").symlink_to(outside)
            except OSError as error: self.skipTest("OS did not allow a test-only symbolic link: " + str(error))
            with self.assertRaises(ValueError): verify.artifact_path(root, "linked")
            self.assertEqual(outside.read_bytes(), b"unchanged")

    def test_missing_platform_signer_and_package_payload_binding_refused(self):
        data = statement(); item = data["artifacts"][0]; item["platform"] = "windows"
        with self.assertRaises(ValueError): verify.validate_manifest(data)
        item["windows_certificate_sha256"] = "d" * 64
        verify.validate_manifest(data)
        item["architecture"] = "aarch64"
        with self.assertRaises(ValueError): verify.validate_manifest(data)
        data = statement("native-packages"); del data["artifacts"][0]["payload_manifest_sha256"]
        with self.assertRaises(ValueError): verify.validate_manifest(data)


@unittest.skipUnless(sys.platform == "linux", "Linux owner uses fcntl; run these pure tests on Ubuntu")
class LifecyclePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("nestlink_linux_lifecycle", ROOT / "packaging/linux/lifecycle.py")
        cls.lifecycle = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.lifecycle)

    def test_binary_rollback_refuses_incompatible_state_without_a_database_restore(self):
        self.lifecycle.compatible({"state_compatibility": "schema18-epoch1"}, {"state_compatibility": "schema18-epoch1"})
        with self.assertRaises(ValueError): self.lifecycle.compatible({"state_compatibility": "schema18-epoch1"}, {"state_compatibility": "schema19-epoch1"})

    def test_foreign_architecture_is_rejected_before_any_package_operation(self):
        data = statement("native-packages"); item = data["artifacts"][0]
        with mock.patch.object(self.lifecycle, "run", side_effect=[b"nestlink-v15-desktop\n", b"amd64\n", b"15.0.0-1\n"]), mock.patch.object(self.lifecycle.platform, "machine", return_value="aarch64"):
            with self.assertRaises(ValueError): self.lifecycle.package_metadata(Path("fixed.deb"), data, item, "desktop")

    def test_install_executes_only_reverified_root_cache_not_mutable_download(self):
        owner = SimpleNamespace(root=Path("/private/install"), owner="a" * 32, finish=mock.Mock())
        transaction = mock.MagicMock(); transaction.__enter__.return_value = owner
        data = statement("native-packages"); item = data["artifacts"][0]
        incoming = {"state_compatibility": item["state_compatibility"], "update_certificate_sha256": "b" * 64}
        receipt = {"schema_version": 1, "role": "desktop", "current": None, "previous": None, "maximum_sequence": 0, "maximum_accepted": None, "instance": None}
        args = SimpleNamespace(role="desktop", recover_incomplete=False, action="install", bundle=Path("/user/download"), manifest=Path("manifest"), signature=Path("signature"), certificate=Path("cert"), certificate_sha256="b" * 64, artifact_id=item["id"])
        with mock.patch.object(self.lifecycle, "Transaction", return_value=transaction), mock.patch.object(self.lifecycle, "read_receipt", return_value=receipt), mock.patch.object(self.lifecycle, "installed_processes", return_value=[]), mock.patch.object(self.lifecycle.verify, "verify_selected", return_value=(data,item,Path("/user/download/mutable.deb"))), mock.patch.object(self.lifecycle, "cache_release", return_value=incoming), mock.patch.object(self.lifecycle, "select_cached", return_value=(data,item,Path("/private/cache/fixed.deb"))), mock.patch.object(self.lifecycle, "package_metadata"), mock.patch.object(self.lifecycle, "verify_installed_payload"), mock.patch.object(self.lifecycle, "activate"), mock.patch.object(self.lifecycle, "release_record", return_value={"sequence":1,"update_certificate_sha256":"b"*64}), mock.patch.object(self.lifecycle, "commit_instance"), mock.patch.object(self.lifecycle, "recover_instance"), mock.patch.object(self.lifecycle, "atomic_json"), mock.patch.object(self.lifecycle, "run") as run:
            self.lifecycle.lifecycle(args)
        self.assertEqual(len(run.call_args_list), 1)
        self.assertEqual(run.call_args.args[0][-1], Path("/private/cache/fixed.deb"))
        owner.finish.assert_called_once()

    def test_replayed_signed_release_is_refused_before_cache_or_apt_mutation(self):
        owner = SimpleNamespace(root=Path("/private/install"), owner="a" * 32)
        transaction = mock.MagicMock(); transaction.__enter__.return_value = owner
        data = statement("native-packages"); item = data["artifacts"][0]
        receipt = {"schema_version": 1, "role": "desktop", "current": None, "previous": None, "maximum_sequence": 1}
        args = SimpleNamespace(role="desktop", recover_incomplete=False, action="install", bundle=Path("bundle"), manifest=Path("manifest"), signature=Path("signature"), certificate=Path("cert"), certificate_sha256="b" * 64, artifact_id=item["id"])
        with mock.patch.object(self.lifecycle, "Transaction", return_value=transaction), mock.patch.object(self.lifecycle, "read_receipt", return_value=receipt), mock.patch.object(self.lifecycle, "installed_processes", return_value=[]), mock.patch.object(self.lifecycle.verify, "verify_selected", return_value=(data,item,Path("old.deb"))), mock.patch.object(self.lifecycle, "release_record", return_value={"sequence":1,"update_certificate_sha256":"b"*64}), mock.patch.object(self.lifecycle, "recover_instance"), mock.patch.object(self.lifecycle, "cache_release") as cache, mock.patch.object(self.lifecycle, "run") as run:
            with self.assertRaises(ValueError): self.lifecycle.lifecycle(args)
        cache.assert_not_called(); run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
