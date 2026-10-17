"""Adversarial archive/install inputs must never reach native build/link steps."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("native_supplier", ROOT / "scripts/refactor-native-codecs.py")
SUPPLY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUPPLY)
TARGET = "x86_64-unknown-linux-gnu"


def elf64(machine):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    header[16:18] = (1).to_bytes(2, "little")
    header[18:20] = machine.to_bytes(2, "little")
    return bytes(header)


def ar_member(name, payload):
    name = (name + "/")[:16].ljust(16)
    header = (name + "0".ljust(12) + "0".ljust(6) + "0".ljust(6) + "100644".ljust(8)
              + str(len(payload)).ljust(10) + "`\n")
    return header.encode("ascii") + payload + (b"\n" if len(payload) & 1 else b"")


def static_archive(*machines):
    return b"!<arch>\n" + b"".join(ar_member(f"obj{index}.o", elf64(machine)) for index, machine in enumerate(machines))


class NativeSupplyTests(unittest.TestCase):
    def test_linux_arm64_requires_a_real_matching_host_and_compiler(self):
        target = "aarch64-unknown-linux-gnu"
        SUPPLY.verify_build_host(target, "aarch64", "Linux", "posix")
        SUPPLY.verify_native_compiler(target, "aarch64-linux-gnu")
        SUPPLY.verify_native_compiler(target, "aarch64-unknown-linux-gnu")
        for machine, system, os_name in (("x86_64", "Linux", "posix"), ("arm64", "Windows", "nt")):
            with self.subTest(machine=machine), self.assertRaises(SUPPLY.SupplyError):
                SUPPLY.verify_build_host(target, machine, system, os_name)
        with self.assertRaises(SUPPLY.SupplyError):
            SUPPLY.verify_native_compiler(target, "x86_64-linux-gnu")
        with self.assertRaises(SUPPLY.SupplyError):
            SUPPLY.verify_native_compiler(TARGET, "aarch64-linux-gnu")
        with self.assertRaises(SUPPLY.SupplyError):
            SUPPLY.verify_build_host("aarch64-linux-android", "aarch64", "Linux", "posix")

    def test_native_arm64_receipt_and_each_archive_object_bind_the_architecture(self):
        target = "aarch64-unknown-linux-gnu"
        with tempfile.TemporaryDirectory() as scratch:
            prefix = Path(scratch)
            receipt = self.make_prefix(prefix, target)
            SUPPLY.verify_receipt(prefix, target, SUPPLY.DEFAULT_LOCK)
            self.assertEqual(SUPPLY.target_machine(target), 183)
            (prefix / "lib/libopus.a").write_bytes(static_archive(183, 62))
            with self.assertRaises(SUPPLY.SupplyError):
                SUPPLY.verify_receipt(prefix, target, SUPPLY.DEFAULT_LOCK)
            # Rewriting a whole receipt cannot make the mixed archive valid.
            with self.assertRaises(SUPPLY.SupplyError):
                SUPPLY.install_manifest(prefix, receipt["libraries"], target)

    def test_android_sdk_roots_resolve_only_the_pinned_ndk_revision(self):
        with tempfile.TemporaryDirectory() as scratch:
            sdk = Path(scratch) / "Android" / "Sdk"
            ndk = sdk / "ndk" / SUPPLY.ANDROID_NDK["revision"]
            ndk.mkdir(parents=True)
            (ndk / "source.properties").write_text("Pkg.Revision = " + SUPPLY.ANDROID_NDK["revision"], encoding="utf-8")
            self.assertEqual(SUPPLY.resolve_ndk_path(sdk), ndk)
            self.assertEqual(SUPPLY.resolve_ndk_path(ndk.parent), ndk)
            self.assertEqual(SUPPLY.resolve_ndk_path(ndk), ndk)

    def test_archive_architecture_is_checked_for_every_elf_member(self):
        with tempfile.TemporaryDirectory() as scratch:
            archive = Path(scratch) / "libfixture.a"
            archive.write_bytes(static_archive(62, 62))
            self.assertEqual(SUPPLY.inspect_elf_archive(archive, 62)["object_count"], 2)
            archive.write_bytes(static_archive(62, 183))
            with self.assertRaises(SUPPLY.SupplyError):
                SUPPLY.inspect_elf_archive(archive, 62)

    def archive(self, directory, entries):
        archive = directory / "fixture.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for name, kind, payload in entries:
                item = tarfile.TarInfo(name)
                item.type = kind
                if kind == tarfile.SYMTYPE:
                    item.linkname = payload
                    tar.addfile(item)
                else:
                    item.size = len(payload) if kind == tarfile.REGTYPE else 0
                    tar.addfile(item, io.BytesIO(payload) if item.size else None)
        spec = {"name": "fixture", "commit": "fixed", "archive_prefix": "fixture-fixed",
                "archive_bytes": archive.stat().st_size, "archive_sha256": SUPPLY.file_sha256(archive),
                "max_unpacked_bytes": 128, "max_members": 10}
        return archive, spec

    def test_archive_traversal_links_collisions_and_budget_are_rejected(self):
        cases = [
            [("fixture-fixed/../escape", tarfile.REGTYPE, b"outside")],
            [("fixture-fixed/link", tarfile.SYMTYPE, "../../outside")],
            [("fixture-fixed/A", tarfile.REGTYPE, b"a"), ("fixture-fixed/a", tarfile.REGTYPE, b"b")],
            [("fixture-fixed/parent", tarfile.REGTYPE, b"file"), ("fixture-fixed/parent/child", tarfile.REGTYPE, b"child")],
            [("fixture-fixed/CON", tarfile.REGTYPE, b"reserved")],
            [("fixture-fixed/large", tarfile.REGTYPE, b"x" * 129)],
        ]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as scratch:
                directory = Path(scratch)
                archive, spec = self.archive(directory, entries)
                with self.assertRaises(SUPPLY.SupplyError):
                    SUPPLY.extract_fresh(archive, spec, directory / "source")
                self.assertFalse((directory / "source").exists())
                self.assertFalse((directory / "escape").exists())

    def test_fresh_extraction_hashes_bytes_and_never_reuses_source(self):
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch)
            archive, spec = self.archive(directory, [("fixture-fixed/header.h", tarfile.REGTYPE, b"header")])
            source = directory / "source"
            original = SUPPLY.extract_fresh(archive, spec, source)
            self.assertEqual(original[0]["sha256"], hashlib.sha256(b"header").hexdigest())
            (source / "header.h").write_bytes(b"edited")
            self.assertNotEqual(SUPPLY.tree_digest(original), SUPPLY.tree_digest(SUPPLY.tree_manifest(source)))
            with self.assertRaises(SUPPLY.SupplyError):
                SUPPLY.extract_fresh(archive, spec, source)
            self.assertEqual((source / "header.h").read_bytes(), b"edited")

    def test_offline_missing_or_tampered_archive_never_falls_back_to_download(self):
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch)
            archive, spec = self.archive(directory, [("fixture-fixed/header.h", tarfile.REGTYPE, b"header")])
            cache = directory / "cache"
            with patch.object(SUPPLY.urllib.request, "urlopen", side_effect=AssertionError("unexpected network")):
                with self.assertRaises(SUPPLY.SupplyError):
                    SUPPLY.get_archive(cache, spec, offline=True)
                pinned = cache / "fixture-fixed.tar.gz"
                pinned.write_bytes(archive.read_bytes())
                self.assertEqual(SUPPLY.get_archive(cache, spec, offline=True), pinned)
                pinned.write_bytes(b"modified")
                with self.assertRaises(SUPPLY.SupplyError):
                    SUPPLY.get_archive(cache, spec, offline=False)

    def prefix(self, prefix):
        return self.make_prefix(prefix, TARGET)

    def make_prefix(self, prefix, target):
        lock = SUPPLY.load_lock(SUPPLY.DEFAULT_LOCK)
        target_spec = lock["targets"][target]
        libraries = target_spec["libraries"]
        machine = SUPPLY.target_machine(target)
        for relative in libraries.values():
            file = prefix / relative
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(static_archive(machine or 62))
        for relative in ("include/vpx/vpx_encoder.h", "include/vpx/vpx_decoder.h", "include/opus/opus.h", "include/opus/opus_defines.h"):
            file = prefix / relative
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b"fixture-header")
        receipt = {"schema_version": 1, "kind": "nestlink-native-codecs", "target": target,
                   "profile": "release", "linkage": "static", "crt": target_spec["crt"],
                   "lock_sha256": SUPPLY.file_sha256(SUPPLY.DEFAULT_LOCK), "features": lock["features"],
                   "libraries": libraries, "sources": [],
                   "validation": {"archive_architectures": {
                       name: SUPPLY.inspect_elf_archive(prefix / relative, machine)
                       for name, relative in libraries.items()
                   }}, "files": SUPPLY.install_manifest(prefix, libraries, target)}
        if target in SUPPLY.ANDROID_TARGETS:
            ndk = SUPPLY.ANDROID_NDK
            archive = {key: ndk[key] for key in ("linux_archive_url", "linux_archive_bytes", "linux_archive_sha1", "linux_archive_sha256")}
            compiler_arch = "aarch64" if target == "aarch64-linux-android" else "x86_64"
            receipt["validation"]["android_ndk"] = {
                "abi": target_spec["android_abi"], "target": target, "expected_elf_machine": machine,
                "compiler_target": f"{compiler_arch}-unknown-linux-android{ndk['api_level']}",
                "ndk_revision": ndk["revision"], "ndk_host_tag": ndk["host_tag"], "api_level": ndk["api_level"],
                "source_properties_sha256": "a" * 64, "ndk_archive": archive,
                "page_size_bytes": ndk["page_size_bytes"], "final_shared_object_linker_flag": ndk["final_shared_object_linker_flag"],
            }
        for source in lock["sources"]:
            record = {key: source[key] for key in ("name", "version", "commit", "archive_sha256", "archive_bytes")}
            record["source_tree_sha256"] = "1" * 64
            receipt["sources"].append(record)
        SUPPLY.write_json(prefix / SUPPLY.RECEIPT, receipt)
        return receipt

    def test_receipt_wrong_target_features_source_and_installed_bytes_are_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            prefix = Path(scratch)
            receipt = self.prefix(prefix)
            SUPPLY.verify_receipt(prefix, TARGET, SUPPLY.DEFAULT_LOCK)
            for field, value in [("target", "x86_64-pc-windows-msvc"), ("crt", "static"), ("lock_sha256", "0" * 64)]:
                changed = {**receipt, field: value}
                SUPPLY.write_json(prefix / SUPPLY.RECEIPT, changed)
                with self.subTest(field=field), self.assertRaises(SUPPLY.SupplyError):
                    SUPPLY.verify_receipt(prefix, TARGET, SUPPLY.DEFAULT_LOCK)
            for field, value in [("vp9", True), ("vp8", 1)]:
                changed = json.loads(json.dumps(receipt))
                changed["features"][field] = value
                SUPPLY.write_json(prefix / SUPPLY.RECEIPT, changed)
                with self.assertRaises(SUPPLY.SupplyError):
                    SUPPLY.verify_receipt(prefix, TARGET, SUPPLY.DEFAULT_LOCK)
            changed = json.loads(json.dumps(receipt))
            changed["sources"][0]["commit"] = "0" * 40
            SUPPLY.write_json(prefix / SUPPLY.RECEIPT, changed)
            with self.assertRaises(SUPPLY.SupplyError):
                SUPPLY.verify_receipt(prefix, TARGET, SUPPLY.DEFAULT_LOCK)
            SUPPLY.write_json(prefix / SUPPLY.RECEIPT, receipt)
            (prefix / "lib/libvpx.a").write_bytes(static_archive(183))
            with self.assertRaises(SUPPLY.SupplyError):
                SUPPLY.verify_receipt(prefix, TARGET, SUPPLY.DEFAULT_LOCK)

    def test_receipt_cannot_relabel_foreign_architecture_objects(self):
        with tempfile.TemporaryDirectory() as scratch:
            prefix = Path(scratch)
            receipt = self.prefix(prefix)
            (prefix / "lib/libvpx.a").write_bytes(static_archive(183))
            SUPPLY.write_json(prefix / SUPPLY.RECEIPT, receipt)
            with self.assertRaises(SUPPLY.SupplyError):
                SUPPLY.verify_receipt(prefix, TARGET, SUPPLY.DEFAULT_LOCK)

    def test_android_receipt_binds_the_ndk_revision_api_and_page_size(self):
        target = "aarch64-linux-android"
        with tempfile.TemporaryDirectory() as scratch:
            prefix = Path(scratch)
            receipt = self.make_prefix(prefix, target)
            SUPPLY.verify_receipt(prefix, target, SUPPLY.DEFAULT_LOCK)
            for field, value in [("ndk_revision", "26.3.11579264"), ("api_level", 29), ("page_size_bytes", 4096)]:
                changed = json.loads(json.dumps(receipt))
                changed["validation"]["android_ndk"][field] = value
                SUPPLY.write_json(prefix / SUPPLY.RECEIPT, changed)
                with self.subTest(field=field), self.assertRaises(SUPPLY.SupplyError):
                    SUPPLY.verify_receipt(prefix, target, SUPPLY.DEFAULT_LOCK)

    def test_existing_work_is_preserved_before_any_tool_or_network_call(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            marker = work / "keep.txt"
            marker.write_bytes(b"existing work")
            args = SimpleNamespace(target=TARGET, work_dir=work)
            with patch.object(SUPPLY, "prepare_tools", side_effect=AssertionError("must not run")), \
                    patch.object(SUPPLY, "get_archive", side_effect=AssertionError("must not run")):
                with self.assertRaises(SUPPLY.SupplyError):
                    SUPPLY.build(args, SUPPLY.load_lock(SUPPLY.DEFAULT_LOCK))
            self.assertEqual(marker.read_bytes(), b"existing work")


if __name__ == "__main__":
    unittest.main()
