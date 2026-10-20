"""Development candidate integrity and separation from production release trust."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("candidate_producer_test", ROOT / "scripts/refactor-candidate-producer.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
SOURCE = "1" * 40


class CandidateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="candidate-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.original_clean = P.clean_source
        self.clean = patch.object(P, "clean_source").start()
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}).start()
        self.cohort_path = self.root / "cohort/candidate-cohort.json"
        index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
            {"digest": "sha256:" + digit * 64, "size": 100, "platform": {"os": "linux", "architecture": architecture}}
            for digit, architecture in (("2", "amd64"), ("3", "arm64"))]}
        P.write_json(self.cohort_path.parent / "oci-base-index.json", index)
        self.value = {"schema_version": 1, "kind": "nestlink-development-candidate",
                      "repository_node_id": P.REPOSITORY_ID, "version": P.VERSION,
                      "product": "NestLink", "repository": P.REPOSITORY,
                      "configuration_sha256": P.digest(ROOT / "config/candidate-producer.json"),
                      "source_revision": SOURCE, "sequence": 1, "run_id": 123, "run_attempt": 2,
                      "source_epoch": 1700000000, "android_version_code": 700001,
                      "android_application_id": "com.zhanry.nestlink.candidate", "android_version_name": P.VERSION,
                      "android_api_range": [30, 36], "oci_base": "ubuntu:24.04@sha256:" + P.digest(self.cohort_path.parent / "oci-base-index.json"),
                      "signing": P.SIGNING, "production_update_eligible": False,
                      "final_user_acceptance": "pending", "required_parts": sorted(P.EXPECTED),
                      "required_roles": sorted(P.CURRENT_ROLES)}
        P.write_json(self.cohort_path, self.value)
        self.bundle = self.root / "parts-bundle"

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        return path

    def make_part(self, name):
        artifacts = []
        for role in sorted(P.EXPECTED[name]):
            raw = {"packages": []} if role == "sbom-input" else (role + " fixture").encode()
            path = self.write(self.bundle / "files" / (role + ".bin"), raw)
            artifacts.append(P.record(self.bundle, path, role, SOURCE))
        payload = []
        if name in P.NATIVE:
            for role in P.NATIVE[name][2]:
                path = self.write(self.bundle / "native" / name / ("nestlink-" + role), (name + role).encode())
                payload.append(P.record(self.bundle, path, "native-" + name + "-" + role, SOURCE))
        evidence = []
        for filename in sorted(P.EVIDENCE[name]):
            raw = {"fixture": name}
            if filename == name + "-readback.json" and name.startswith("oci-"):
                raw = {"manifest_digest": "sha256:" + "4" * 64,
                       "os_packages": [{"name": "libc6", "version": "2.39-fixture", "source": "glibc"}]}
            path = self.write(self.bundle / "evidence" / filename, raw)
            evidence.append(P.record(self.bundle, path, "evidence-" + filename.replace(".", "-"), SOURCE))
        receipt = {"schema_version": 1, "kind": "nestlink-development-candidate-part", "part": name,
                   "cohort_sha256": P.digest(self.cohort_path), "source_revision": SOURCE,
                   "artifacts": artifacts, "payload": payload, "evidence": evidence}
        self.write(self.bundle / "parts" / (name + ".json"), receipt)
        return receipt

    def parts(self):
        return {name: self.make_part(name) for name in P.EXPECTED}

    def test_preflight_needs_no_production_secret_and_preserves_base_index(self):
        output = self.root / "preflight"
        args = argparse.Namespace(source=SOURCE, sequence=1, run_id=123, run_attempt=2,
                                  oci_base=self.value["oci_base"], oci_index=self.cohort_path.parent / "oci-base-index.json", output=output)
        with patch.object(P.TOOLS, "run", return_value=b"1700000000\n"), patch.dict(os.environ, {}, clear=True):
            P.preflight(args)
        actual = P.cohort(output / "candidate-cohort.json")
        self.assertEqual(actual, self.value)
        self.assertEqual(P.digest(output / "oci-base-index.json"), args.oci_base.rsplit(":", 1)[1])
        self.assertFalse(actual["production_update_eligible"])
        self.assertEqual(actual["signing"]["android"], "development-only")

    def test_cohort_rejects_production_claims_missing_platforms_or_other_ci_execution(self):
        for field, invalid in (("signing", {**P.SIGNING, "windows": "passed"}),
                               ("production_update_eligible", True), ("android_api_range", [31, 36]),
                               ("required_parts", ["windows-x64"]), ("required_roles", []),
                               ("android_application_id", "com.zhanry.nestlink"),
                               ("repository_node_id", "R_kgDOTz-mRQ"),
                               ("version", "15.0.0"),
                               ("final_user_acceptance", "passed"), ("run_id", 999)):
            self.write(self.cohort_path, {**self.value, field: invalid})
            with self.subTest(field=field), self.assertRaises(ValueError):
                P.cohort(self.cohort_path)

    def test_base_proof_rejects_tamper_and_single_architecture(self):
        index = self.cohort_path.parent / "oci-base-index.json"
        index.write_bytes(index.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "digest"):
            P.cohort(self.cohort_path)
        data = json.loads(index.read_bytes())
        data["manifests"] = data["manifests"][:1]
        self.write(index, data)
        with self.assertRaises(ValueError):
            P.oci_index(index, "ubuntu:24.04@sha256:" + P.digest(index))

    def test_no_part_or_android_abi_can_be_omitted(self):
        self.parts()
        android = self.bundle / "parts/android.json"
        saved = android.read_bytes()
        android.unlink()
        with self.assertRaises(OSError):
            P.read_parts(self.cohort_path, self.bundle)
        android.write_bytes(saved)
        receipt = json.loads(saved)
        receipt["artifacts"] = receipt["artifacts"][:1]
        self.write(android, receipt)
        with self.assertRaisesRegex(ValueError, "platform/ABI"):
            P.read_parts(self.cohort_path, self.bundle)

    def test_cross_source_and_changed_bytes_are_rejected(self):
        receipt = self.make_part("web")
        part_path = self.bundle / "parts/web.json"
        for changed in ({**receipt, "source_revision": "2" * 40},
                        {**receipt, "cohort_sha256": "3" * 64}):
            self.write(part_path, changed)
            with self.assertRaisesRegex(ValueError, "source/cohort"):
                P.read_parts(self.cohort_path, self.bundle, {"web"})
        self.write(part_path, receipt)
        artifact = self.bundle / receipt["artifacts"][0]["path"]
        artifact.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            P.read_parts(self.cohort_path, self.bundle, {"web"})

    def test_native_payload_missing_executable_is_rejected(self):
        receipt = self.make_part("linux-arm64")
        receipt["payload"].pop()
        self.write(self.bundle / "parts/linux-arm64.json", receipt)
        with self.assertRaisesRegex(ValueError, "executable matrix"):
            P.read_parts(self.cohort_path, self.bundle, {"linux-arm64"})

    def test_collision_traversal_and_unrecorded_oci_provenance_are_rejected(self):
        receipt = self.make_part("android")
        first, second = receipt["artifacts"]
        receipt["artifacts"][1] = {**first, "id": second["id"], "role": second["role"]}
        self.write(self.bundle / "parts/android.json", receipt)
        with self.assertRaisesRegex(ValueError, "collide"):
            P.read_parts(self.cohort_path, self.bundle, {"android"})
        receipt["artifacts"][1] = {**second, "path": "../escape.apk"}
        self.write(self.bundle / "parts/android.json", receipt)
        with self.assertRaises(ValueError):
            P.read_parts(self.cohort_path, self.bundle, {"android"})
        oci = self.make_part("oci-x64")
        oci["evidence"] = [item for item in oci["evidence"] if not item["path"].endswith("-readback.json")]
        self.write(self.bundle / "parts/oci-x64.json", oci)
        with self.assertRaisesRegex(ValueError, "provenance"):
            P.read_parts(self.cohort_path, self.bundle, {"oci-x64"})

    def test_source_must_match_head_and_remain_clean(self):
        for head, status in (("2" * 40, b""), (SOURCE, b" M Cargo.toml\n"), (SOURCE, b"?? unknown.txt\n")):
            with self.subTest(head=head, status=status), patch.object(P.TOOLS, "run", side_effect=[head.encode(), status]), self.assertRaises(ValueError):
                self.original_clean(SOURCE, P.VERSION)

    def test_new_rc_source_version_is_unified_and_protocol_namespace_is_independent(self):
        source = self.root / "source-fixture"
        source.mkdir()
        (source / "Cargo.toml").write_text('[workspace.package]\nversion="0.7.0-rc.1"\n[workspace.dependencies]\nnestlink-fixture={path="crates/fixture",version="=0.7.0-rc.1"}\n', encoding="utf-8")
        self.write(source / "compatibility.json", {"version": P.VERSION, "namespace": "v15"})
        self.write(source / "protocol-spec/contract.json", {"product_version": P.VERSION, "namespace": "v15"})
        metadata = source / "protocol-spec/openapi.json"
        self.write(metadata, {"info": {"version": P.VERSION}})
        with patch.object(P, "ROOT", source), patch.object(P.TOOLS, "run", side_effect=[SOURCE.encode(), b""]):
            self.original_clean(SOURCE, P.VERSION)
        self.write(metadata, {"info": {"version": "15.0.0"}})
        with patch.object(P, "ROOT", source), patch.object(P.TOOLS, "run", side_effect=[SOURCE.encode(), b""]), self.assertRaisesRegex(ValueError, "version metadata"):
            self.original_clean(SOURCE, P.VERSION)

    def test_zip_readback(self):
        inputs = self.root / "archive-input"
        self.write(inputs / "nested/run", b"executable fixture")
        self.write(inputs / "readme.txt", b"candidate")
        output = self.root / "material.zip"
        P.zip_tree(inputs, output, self.value["source_epoch"])
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.read("nested/run"), b"executable fixture")
            self.assertEqual(set(archive.namelist()), {"nested/run", "readme.txt"})

    def pe_fixture(self, machine=0x014c, magic=0x010b, subsystem=2, characteristics=0x0102):
        raw = bytearray(64 + 24 + 224)
        raw[:2] = b"MZ"
        raw[60:64] = (64).to_bytes(4, "little")
        raw[64:68] = b"PE\0\0"
        raw[68:70] = machine.to_bytes(2, "little")
        raw[84:86] = (224).to_bytes(2, "little")
        raw[86:88] = characteristics.to_bytes(2, "little")
        raw[88:90] = magic.to_bytes(2, "little")
        raw[156:158] = subsystem.to_bytes(2, "little")
        return bytes(raw)

    def test_inno6_bootstrap_requires_x86_pe32_gui_and_payload_checker_stays_x64(self):
        path = self.write(self.root / "bootstrap.exe", self.pe_fixture())
        P.inno6_bootstrap_x86(path)
        with self.assertRaisesRegex(ValueError, "not x64"):
            P.TOOLS.pe_x64(path)
        for raw in (b"MZ", b"not a PE" + bytes(320), self.pe_fixture(machine=0x8664, magic=0x020b),
                    self.pe_fixture(machine=0xaa64), self.pe_fixture(magic=0x020b),
                    self.pe_fixture(subsystem=3), self.pe_fixture(characteristics=0x2102),
                    self.pe_fixture(characteristics=0), self.pe_fixture()[:-1]):
            with self.subTest(header=raw[:90]):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    P.inno6_bootstrap_x86(path)
        for position, raw in ((60, (32).to_bytes(4, "little")), (60, (1024 * 1024 + 1).to_bytes(4, "little")),
                              (64, b"NOPE"), (84, (240).to_bytes(2, "little"))):
            mutated = bytearray(self.pe_fixture())
            mutated[position:position + len(raw)] = raw
            path.write_bytes(mutated)
            with self.subTest(position=position), self.assertRaises(ValueError):
                P.inno6_bootstrap_x86(path)

    def test_both_setup_roles_check_the_inno_bootstrap_after_compilation(self):
        payload = self.root / "payload"
        payload.mkdir()
        for role, privileged in (("desktop", "0"), ("privileged", "1")):
            output = self.root / (role + ".exe")
            def compile_fixture(command):
                self.assertIn("/DPrivileged=" + privileged, command)
                output.write_bytes(self.pe_fixture())
            with self.subTest(role=role), patch.object(P, "execute", side_effect=compile_fixture):
                P.setup_candidate(payload, output, role, P.VERSION, "owned-fixture-ISCC")
            with patch.object(P, "execute", side_effect=lambda command: output.write_bytes(self.pe_fixture(machine=0x8664, magic=0x020b))):
                with self.assertRaisesRegex(ValueError, "x86 PE32"):
                    P.setup_candidate(payload, output, role, P.VERSION, "owned-fixture-ISCC")

    def test_each_native_windows_payload_still_rejects_x86_before_packaging(self):
        inputs = self.root / "windows-input"
        roles = P.NATIVE["windows-x64"][2]
        supplier = SimpleNamespace(verify_receipt=lambda *args: None)
        for rejected_role in roles:
            for role in roles:
                self.write(inputs / ("nestlink-" + role + ".exe"),
                           self.pe_fixture() if role == rejected_role else self.pe_fixture(machine=0x8664, magic=0x020b))
            args = argparse.Namespace(cohort=self.cohort_path, input=inputs, output=self.root / ("wrong-payload-" + rejected_role),
                                      target="windows-x64", codec_prefix=self.root / "unused-codec", iscc="must-not-run")
            with self.subTest(role=rejected_role), patch.object(P, "module", return_value=supplier), patch.object(P, "setup_candidate") as setup:
                with self.assertRaisesRegex(ValueError, "not x64"):
                    P.collect_native(args)
                setup.assert_not_called()

    def elf_fixture(self, abi, alignment=16384):
        raw = bytearray(256)
        raw[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", raw, 18, 183 if abi == "arm64-v8a" else 62)
        struct.pack_into("<Q", raw, 32, 64)
        struct.pack_into("<HH", raw, 54, 56, 1)
        struct.pack_into("<IIQQQQQQ", raw, 64, 1, 5, 0, 0, 0, len(raw), len(raw), alignment)
        return bytes(raw)

    def native_zip(self, abi, *, libraries=None, aligned=True, compressed=False, path=None):
        path = path or self.root / (abi + "-native.zip")
        path.parent.mkdir(parents=True, exist_ok=True)
        libraries = libraries if libraries is not None else [("lib/" + abi + "/" + name, self.elf_fixture(abi))
                     for name in ("libandroidx.graphics.path.so", "libnestlink_android.so")]
        with zipfile.ZipFile(path, "w") as archive:
            for name, raw in libraries:
                info = zipfile.ZipInfo(name)
                info.compress_type = zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
                if aligned:
                    padding = (-archive.fp.tell() - 30 - len(name.encode("utf-8"))) % 16384
                    if padding:
                        if padding < 4:
                            padding += 16384
                        info.extra = struct.pack("<HH", 0xcafe, padding - 4) + bytes(padding - 4)
                archive.writestr(info, raw)
        return path

    def verify_android_fixture(self, command, *, timeout=60):
        self.assertEqual(timeout, 60)
        self.assertEqual(Path(command[1]), ROOT / "scripts/verify-android-binary.py")
        spec = importlib.util.spec_from_file_location("candidate_android_elf_test", command[1])
        binary = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(binary)
        binary.verify(Path(command[command.index("--library") + 1]), command[command.index("--abi") + 1])

    def graphics_fixture_pins(self):
        return {abi: {"bytes": len(self.elf_fixture(abi)), "sha256": hashlib.sha256(self.elf_fixture(abi)).hexdigest()}
                for abi in ("arm64-v8a", "x86_64")}

    def test_graphics_native_source_requires_the_locked_coordinate_and_aar_hash(self):
        self.assertEqual(P.android_graphics_dependency()["aar_sha256"], P.ANDROID_GRAPHICS_PATH_AAR_SHA256)
        source = self.root / "graphics-source"
        lock = source / "apps/android/app/gradle.lockfile"
        metadata = source / "apps/android/gradle/verification-metadata.xml"
        self.write(lock, (ROOT / "apps/android/app/gradle.lockfile").read_bytes())
        self.write(metadata, (ROOT / "apps/android/gradle/verification-metadata.xml").read_bytes())
        original = lock.read_text(encoding="utf-8")
        lock.write_text(original.replace("androidx.graphics:graphics-path:1.0.1=", "androidx.graphics:graphics-path:1.0.2="), encoding="utf-8")
        with patch.object(P, "ROOT", source), self.assertRaisesRegex(ValueError, "dependency lock"):
            P.android_graphics_dependency()
        lock.write_text(original, encoding="utf-8")
        metadata.write_text(metadata.read_text(encoding="utf-8").replace(P.ANDROID_GRAPHICS_PATH_AAR_SHA256, "0" * 64), encoding="utf-8")
        with patch.object(P, "ROOT", source), self.assertRaisesRegex(ValueError, "AAR verification pin"):
            P.android_graphics_dependency()

    def test_android_allows_exact_two_library_set_in_either_zip_order_for_both_abis(self):
        for abi in ("arm64-v8a", "x86_64"):
            for reverse in (False, True):
                libraries = [("lib/" + abi + "/" + name, self.elf_fixture(abi))
                             for name in ("libandroidx.graphics.path.so", "libnestlink_android.so")]
                if reverse:
                    libraries.reverse()
                path = self.native_zip(abi, libraries=libraries)
                with zipfile.ZipFile(path) as archive, patch.object(P, "ANDROID_GRAPHICS_PATH_LIBRARIES", self.graphics_fixture_pins()), \
                        patch.object(P, "execute", side_effect=self.verify_android_fixture) as execute:
                    facts = P.android_native_libraries(archive, abi)
                self.assertEqual(execute.call_count, 2)
                self.assertEqual(len(facts), 2)
                self.assertTrue(all(item["zip_data_offset"] % 16384 == 0 and item["elf_16k_verification"] == "passed" for item in facts))
                dependency = next(item for item in facts if item.get("dependency"))
                self.assertEqual(dependency["aar_sha256"], P.ANDROID_GRAPHICS_PATH_AAR_SHA256)

    def test_android_missing_extra_duplicate_or_other_abi_library_is_refused(self):
        abi = "arm64-v8a"
        valid = [("lib/" + abi + "/" + name, self.elf_fixture(abi))
                 for name in ("libandroidx.graphics.path.so", "libnestlink_android.so")]
        inventories = [valid[:1], valid + [("lib/" + abi + "/libunreviewed.so", self.elf_fixture(abi))],
                       valid + [("lib/x86_64/libnestlink_android.so", self.elf_fixture("x86_64"))]]
        for libraries in inventories:
            path = self.native_zip(abi, libraries=libraries)
            with zipfile.ZipFile(path) as archive, self.assertRaisesRegex(ValueError, "JNI set differs"):
                P.android_native_libraries(archive, abi)
        path = self.native_zip(abi)
        with zipfile.ZipFile(path) as archive, patch.object(archive, "namelist", return_value=archive.namelist() * 2), \
                self.assertRaisesRegex(ValueError, "inventory"):
            P.android_native_libraries(archive, abi)

    def test_android_fixed_graphics_bytes_zip_alignment_and_storage_cannot_be_bypassed(self):
        abi = "x86_64"
        for aligned, compressed, message in ((False, False, "16 KiB aligned"), (True, True, "uncompressed")):
            path = self.native_zip(abi, aligned=aligned, compressed=compressed)
            with zipfile.ZipFile(path) as archive, self.assertRaisesRegex(ValueError, message):
                P.android_native_libraries(archive, abi)
        path = self.native_zip(abi)
        with zipfile.ZipFile(path) as archive, self.assertRaisesRegex(ValueError, "fixed AAR bytes"):
            P.android_native_libraries(archive, abi)

    def test_each_android_library_retains_elf_machine_and_16k_load_checks(self):
        abi = "arm64-v8a"
        for library in ("libandroidx.graphics.path.so", "libnestlink_android.so"):
            for invalid in (self.elf_fixture("x86_64"), self.elf_fixture(abi, alignment=4096)):
                libraries = [("lib/" + abi + "/" + name, invalid if name == library else self.elf_fixture(abi))
                             for name in ("libandroidx.graphics.path.so", "libnestlink_android.so")]
                path = self.native_zip(abi, libraries=libraries)
                pins = self.graphics_fixture_pins()
                if library == "libandroidx.graphics.path.so":
                    pins[abi] = {"bytes": len(invalid), "sha256": hashlib.sha256(invalid).hexdigest()}
                with zipfile.ZipFile(path) as archive, patch.object(P, "ANDROID_GRAPHICS_PATH_LIBRARIES", pins), \
                        patch.object(P, "execute", side_effect=self.verify_android_fixture), self.assertRaises(ValueError):
                    P.android_native_libraries(archive, abi)

    def test_android_collector_completes_both_abis_through_signature_evidence_codec_copy_and_part_readback(self):
        inputs = self.root / "android-apks"
        for abi in ("arm64-v8a", "x86_64"):
            self.native_zip(abi, path=inputs / (abi + ".apk"))
        pin = "a" * 64
        def run(command):
            if command[0] == "fixture-apksigner":
                return ("Signer #1 certificate SHA-256 digest: " + pin + "\n").encode()
            if command[0] == "fixture-aapt2":
                abi = Path(command[-1]).stem
                return ("native-code: '" + abi + "'\napplication-debuggable\n").encode()
            self.assertEqual(command[0], "fixture-zipalign")
            self.assertEqual(command[1:7], ["-c", "-P", "16", "-v", "4", command[-1]])
            return b"Verification successful"
        def signature(path, actual_pin, app_id, version, abis, *tools):
            self.assertEqual((actual_pin, app_id, version), (pin, self.value["android_application_id"], P.VERSION))
            self.assertEqual(abis, [path.stem])
            return {"version_code": str(self.value["android_version_code"]), "certificate_sha256": pin,
                    "application_id": app_id, "version_name": version, "abis": abis,
                    "signature_compatibility_sdk_range": [30, 36]}
        signatures = SimpleNamespace(android_signature=signature)
        supplier = SimpleNamespace(RECEIPT="nestlink-codecs.json", verify_receipt=lambda *args: None)
        args = argparse.Namespace(cohort=self.cohort_path, input=inputs, output=self.root / "android-output",
                                  java="fixture-java", apksigner="fixture-apksigner", aapt2="fixture-aapt2", zipalign="fixture-zipalign",
                                  codec_arm64=self.root / "codec-arm64", codec_x64=self.root / "codec-x64")
        self.write(args.codec_arm64 / supplier.RECEIPT, b"owned codec receipt fixture")
        self.write(args.codec_x64 / supplier.RECEIPT, b"owned codec receipt fixture")
        def modules(name, path):
            return signatures if path.endswith("signatures.py") else supplier
        with patch.object(P, "module", side_effect=modules), patch.object(P.TOOLS, "run", side_effect=run), \
                patch.object(P.TOOLS, "tool_facts", return_value=[{"tool": "fixture"}]), \
                patch.object(P, "ANDROID_GRAPHICS_PATH_LIBRARIES", self.graphics_fixture_pins()), \
                patch.object(P, "execute", side_effect=self.verify_android_fixture) as execute:
            P.collect_android(args)
        self.assertEqual(execute.call_count, 4)
        _, parts = P.read_parts(self.cohort_path, args.output, {"android"})
        self.assertEqual({item["role"] for item in parts["android"]["artifacts"]}, {"android-arm64", "android-x86_64"})
        self.assertEqual(len(parts["android"]["evidence"]), 5)
        for role in ("android-arm64", "android-x86_64"):
            identity = P.read_json(args.output / "evidence" / (role + "-development-signature.json"))
            self.assertEqual(identity["status"], "development-only")
            self.assertFalse(identity["fixed_release_identity_configured"])
            self.assertEqual(len(identity["native_libraries"]), 2)

    def test_real_symlink_cannot_be_archived(self):
        inputs = self.root / "linked-input"
        self.write(inputs / "target", b"must not duplicate")
        try:
            (inputs / "link").symlink_to(inputs / "target")
        except OSError:
            self.skipTest("Host lacks symbolic-link creation permission")
        with self.assertRaises(ValueError):
            P.zip_tree(inputs, self.root / "linked.zip", self.value["source_epoch"])

    @unittest.skipUnless(shutil.which("dpkg-deb"), "Requires native Debian packaging tools")
    def test_actual_deb_rc_version_and_isolated_files(self):
        inputs = self.root / "linux-input"
        self.write(inputs / "nestlink-desktop", b"desktop fixture bytes")
        self.write(inputs / "nestlink-daemon", b"daemon fixture bytes")
        output = self.root / "candidate.deb"
        P.deb_candidate(inputs, output, "desktop", "arm64", self.value)
        fields = P.TOOLS.run(["dpkg-deb", "--field", output, "Version", "Architecture", "Package"]).decode()
        self.assertIn("Version: 0.7.0~rc.1", fields)
        self.assertIn("Architecture: arm64", fields)
        self.assertIn("Package: nestlink-rc-desktop", fields)
        extracted = self.root / "installed"
        P.TOOLS.run(["dpkg-deb", "--extract", output, extracted])
        self.assertEqual((extracted / "opt/nestlink-rc/desktop/nestlink-desktop").read_bytes(), b"desktop fixture bytes")
        self.assertTrue((extracted / "usr/bin/nestlink-rc").stat().st_mode & 0o111)
        self.assertFalse((extracted / "etc/systemd").exists())

    def test_hashed_trunk_stylesheets_are_accepted_and_missing_references_rejected(self):
        inputs = self.root / "web"
        self.write(inputs / "index.html", b'<link rel="stylesheet" href="/nestlink-cafef00d.css"><script type="module">import "./app.js";</script>')
        css = self.write(inputs / "nestlink-cafef00d.css", b"body{color:black}")
        self.write(inputs / "app.js", b"// bootstrap")
        self.write(inputs / "app.wasm", b"\x00asm")
        args = argparse.Namespace(cohort=self.cohort_path, input=inputs, output=self.root / "web-output")
        with patch.object(P.TOOLS, "tool_facts", return_value=[{"tool": "fixture"}]):
            P.collect_web(args)
        self.assertIn("web", P.read_parts(self.cohort_path, args.output, {"web"})[1])
        css.unlink()
        args.output = self.root / "web-missing-css"
        with self.assertRaises(OSError):
            P.collect_web(args)

    def test_freeze_keeps_every_role_and_all_user_acceptance_pending(self):
        self.parts()
        output = self.root / "frozen"
        P.freeze(argparse.Namespace(cohort=self.cohort_path, bundle=self.bundle, output=output, acceptance_evidence=None))
        manifest = P.read_json(output / "candidate-build-manifest.json")
        self.assertEqual({item["role"] for item in manifest["artifacts"]}, P.CURRENT_ROLES)
        self.assertEqual(len(manifest["artifacts"]), 18)
        self.assertFalse(manifest["production_update_eligible"])
        self.assertEqual(manifest["user_full_functional_acceptance"], "pending")
        for artifact in manifest["artifacts"]:
            self.assertEqual(artifact["source_revision"], SOURCE)
            P.verify_record(output, artifact, SOURCE)
        self.assertEqual(manifest["repository_node_id"], "R_kgDOVNHMvg")
        self.assertEqual(manifest["version"], "0.7.0-rc.1")
        self.assertEqual(manifest["product"], "NestLink")
        self.assertEqual({path.name for path in output.iterdir()}, {"files", "candidate-build-manifest.json"})
        self.assertEqual(len(manifest["acceptance_cases"]), 30)
        self.assertTrue(all(item["status"] == "pending" for item in manifest["acceptance_cases"]))
        self.assertIn("90-minute-soak", {item["id"] for item in manifest["acceptance_cases"]})
        self.assertNotIn("72-hour-soak", {item["id"] for item in manifest["acceptance_cases"]})
        with zipfile.ZipFile(output / "files/NestLink-candidate-materials.zip") as archive:
            self.assertEqual(P.digest(self.cohort_path.parent / "oci-base-index.json"), hashlib.sha256(archive.read("oci-base-index.json")).hexdigest())
            self.assertTrue(any(name.startswith("native/linux-arm64/") for name in archive.namelist()))
        payload = P.read_json(output / "files/NestLink-candidate-native-payload.json")
        self.assertEqual(payload["purpose"], "development-candidate-native-payload")
        self.assertFalse(payload["production_update_eligible"])

    def test_freeze_refuses_existing_or_source_tree_outputs(self):
        self.parts()
        for output in (self.bundle, ROOT / "candidate-output-forbidden"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                P.freeze(argparse.Namespace(cohort=self.cohort_path, bundle=self.bundle, output=output, acceptance_evidence=None))

    def test_workflow_preserves_matrix_bounds_and_has_no_publication_or_secrets(self):
        workflow = (ROOT / ".github/workflows/v15-candidate-build.yml").read_text(encoding="utf-8")
        for platform in ("windows-2022", "ubuntu-24.04", "ubuntu-24.04-arm", "aarch64-linux-android,x86_64-linux-android"):
            self.assertIn(platform, workflow)
        limits = re.findall(r"timeout-minutes: ([0-9]+)", workflow)
        self.assertEqual(len(limits), 6)
        self.assertTrue(all(0 < int(limit) <= 90 for limit in limits))
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("cargo test", workflow)
        self.assertNotIn("refactor-release-publish.py", workflow)
        self.assertNotIn("R_kgDOTz-mRQ", workflow)
        self.assertNotIn("ZHanry/home-tunnel", workflow)
        self.assertIn("R_kgDOVNHMvg", workflow)
        self.assertIn('"--locked=true"', workflow)
        self.assertIn(":app:assembleDebug", workflow)
        self.assertIn("--project-cache-dir", workflow)
        for reference in re.findall(r"uses: ([^\s]+)", workflow):
            self.assertRegex(reference, r"@[0-9a-f]{40}$")
        # Compile every embedded Python action without executing CI commands.
        lines, blocks = workflow.splitlines(), []
        for index, line in enumerate(lines):
            if line.strip() != "shell: python":
                continue
            cursor = index + 1
            while lines[cursor] != "        run: |":
                cursor += 1
            cursor += 1
            block = []
            while cursor < len(lines) and (lines[cursor].startswith("          ") or not lines[cursor]):
                block.append(lines[cursor])
                cursor += 1
            blocks.append("\n".join(block) + "\n")
        self.assertGreaterEqual(len(blocks), 8)
        for index, block in enumerate(blocks):
            compile(textwrap.dedent(block), "candidate-workflow-python-" + str(index), "exec")


if __name__ == "__main__":
    unittest.main()
