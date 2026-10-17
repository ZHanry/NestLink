"""Fixed candidate boundaries: hostile archives, mixed jobs and architecture lies."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_producer_test", ROOT / "scripts/refactor-release-producer.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return json.dumps(value, sort_keys=True).encode()


def tar_bytes(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for name, raw, kind in entries:
            item = tarfile.TarInfo(name)
            item.type = kind
            if kind == tarfile.REGTYPE:
                item.size = len(raw)
                archive.addfile(item, io.BytesIO(raw))
            else:
                item.linkname = raw.decode()
                archive.addfile(item)
    return out.getvalue()


def oci_image(path, cohort, architecture="arm64", payload=b"server", *, duplicate=False, bad_blob=False, later=None):
    labels = {"org.opencontainers.image.revision": cohort["source_revision"], "org.opencontainers.image.version": cohort["version"]}
    config = json_bytes({"architecture": architecture, "os": "linux", "config": {"User": "65532:65532", "Entrypoint": ["/usr/local/bin/nestlink-server"], "Labels": labels}})
    status = ("Package: libc6\nVersion: 2.39-fixture\nArchitecture: " + architecture + "\nStatus: install ok installed\n\n").encode()
    layers = [tar_bytes([("usr/local/bin/nestlink-server", payload, tarfile.REGTYPE), ("usr/share/nestlink/web/index.html", b"index", tarfile.REGTYPE),
                        ("var/lib/dpkg/status", status, tarfile.REGTYPE), ("usr/share/doc/libc6/copyright", b"fixture-copyright", tarfile.REGTYPE)])]
    if later is not None:
        layers.append(tar_bytes(later))
    def desc(raw, media):
        return {"mediaType": media, "size": len(raw), "digest": "sha256:" + sha(raw)}
    manifest = json_bytes({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": desc(config, "application/vnd.oci.image.config.v1+json"), "layers": [desc(raw, "application/vnd.oci.image.layer.v1.tar") for raw in layers]})
    index = json_bytes({"schemaVersion": 2, "manifests": [desc(manifest, "application/vnd.oci.image.manifest.v1+json")]})
    entries = [("oci-layout", json_bytes({"imageLayoutVersion": "1.0.0"}), tarfile.REGTYPE), ("index.json", index, tarfile.REGTYPE),
               ("blobs/sha256/" + sha(config), config, tarfile.REGTYPE), ("blobs/sha256/" + sha(manifest), manifest, tarfile.REGTYPE)]
    entries += [("blobs/sha256/" + sha(raw), raw + (b"tampered" if bad_blob else b""), tarfile.REGTYPE) for raw in layers]
    if duplicate:
        entries.append(entries[0])
    path.write_bytes(tar_bytes(entries))


class ProducerTests(unittest.TestCase):
    def cohort(self):
        return {"schema_version": 1, "kind": "nestlink-release-cohort", "repository_node_id": P.REPOSITORY_ID,
                "version": "15.0.0", "source_revision": "1" * 40, "release_sequence": 1,
                "android_version_code": 150000001, "run_id": 123, "run_attempt": 2,
                "source_epoch": 1700000000, "configuration_sha256": "a" * 64}

    def policy(self):
        value = json.loads((ROOT / "config/release-producer.json").read_text())
        value.update(update_certificate_sha256="1" * 64, windows_certificate_sha256="2" * 64,
                     android_certificate_sha256="3" * 64, windows_timestamp_url="https://timestamp.example.test/rfc3161",
                     debian_maintainer="Maintainer <releases@example.test>", oci_base="ubuntu:24.04@sha256:" + "4" * 64)
        return value

    def test_unconfigured_release_blocks_without_source_build_or_output_candidate(self):
        with tempfile.TemporaryDirectory() as scratch:
            output = Path(scratch) / "output"
            policy = self.policy()
            policy["update_certificate_sha256"] = None
            config = Path(scratch) / "unconfigured.json"
            P.create_json(config, policy)
            args = argparse.Namespace(config=config, output=output)
            with patch.object(P, "clean_source", side_effect=AssertionError("must not build")), self.assertRaises(P.Blocked):
                P.preflight(args)
            report = json.loads((output / "readiness.json").read_text())
            self.assertEqual(report["status"], "blocked")
            self.assertFalse((output / "cohort.json").exists())

    def test_public_policy_rejects_reused_update_key_api29_and_floating_oci_base(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "policy.json"
            valid = self.policy()
            P.create_json(path, valid)
            self.assertEqual(P.configuration(path), valid)
            for field, value in (("update_certificate_sha256", valid["windows_certificate_sha256"]),
                                 ("minimum_android_api", 29), ("oci_base", "ubuntu:24.04"),
                                 ("windows_timestamp_url", "https://good.test/\nmalformed")):
                path.write_text(json.dumps({**valid, field: value}))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    P.configuration(path)

    def test_version_sequence_and_execution_identity_are_bound(self):
        value = self.cohort()
        P.validate_cohort(value)
        for field, invalid in (("version", "15.0.0-dev.1"), ("release_sequence", 0),
                               ("android_version_code", 150000), ("run_id", True), ("source_revision", "main")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                P.validate_cohort({**value, field: invalid})

    @unittest.skipUnless(shutil.which("git"), "git is unavailable")
    def test_clean_source_uses_real_git_and_rejects_untracked_changes(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "protocol-spec").mkdir()
            (root / "Cargo.toml").write_text('[workspace.package]\nversion="15.0.0"\n[workspace.dependencies]\nnestlink-core={version="=15.0.0",path="core"}\n')
            for name, value in (("compatibility.json", {"version": "15.0.0"}),
                                ("protocol-spec/contract.json", {"product_version": "15.0.0"}),
                                ("protocol-spec/openapi.json", {"info": {"version": "15.0.0"}})):
                (root / name).write_text(json.dumps(value))
            def git(*args):
                result = subprocess.run(["git", "-C", str(root), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
                return result.stdout.decode().strip()
            git("init", "--quiet", "--template=")
            git("add", ".")
            git("-c", "user.name=Release Fixture", "-c", "user.email=fixture@example.test", "-c", "core.hooksPath=", "commit", "--quiet", "--no-gpg-sign", "-m", "fixture")
            revision = git("rev-parse", "HEAD")
            with patch.object(P, "ROOT", root), patch.object(P, "run", side_effect=lambda command, **kw: subprocess.check_output([str(item) for item in command], cwd=root)):
                P.clean_source(revision, "15.0.0")
                (root / "untracked.txt").write_bytes(b"dirty")
                with self.assertRaises(ValueError):
                    P.clean_source(revision, "15.0.0")

    def test_create_new_and_before_after_hashes_reject_overwrite_and_tampering(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            path = root / "fixed.bin"
            path.write_bytes(b"fixed")
            item = P.file_record(root, path, "fixture")
            P.verify_record(root, item)
            path.write_bytes(b"edited")
            with self.assertRaises(ValueError):
                P.verify_record(root, item)
            with self.assertRaises(FileExistsError):
                P.create_json(path, {})

    def test_duplicate_json_fields_and_portable_path_aliases_are_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "duplicate.json"
            path.write_text('{"a":1,"a":2}')
            with self.assertRaises(ValueError):
                P.json_read(path)
        for path in ("../escape", "/absolute", "x/../y", "a\\b", "a//b", "CON.txt", "file.", "a:stream"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                P.relative(path)

    def parts(self, root):
        cohort = root / "cohort.json"
        P.create_json(cohort, self.cohort())
        for part in P.PARTS:
            if part in P.NATIVE:
                _, folder, roles = P.NATIVE[part]
                paths = [(folder + "/nestlink-" + role + (".exe" if part == "windows-x64" else ""), "native-" + part + "-" + role) for role in roles]
            else:
                paths = [("NestLink-android-arm64.apk", "android-arm64"), ("NestLink-android-x86_64.apk", "android-x86_64")] if part == "android" else [("NestLink-web-static.tar.gz", "web-static")]
            records = []
            for name, role in paths:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(role.encode())
                records.append(P.file_record(root, path, role))
            P.create_json(root / "parts" / (part + ".json"), {"schema_version": 1, "kind": "nestlink-release-part", "part": part,
                          "cohort_sha256": P.digest(cohort), "artifacts": records, "evidence": []})
        return cohort

    def test_mixed_source_run_part_is_rejected_before_cms_or_packaging(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            cohort = self.parts(root)
            P.verify_parts(cohort, root)
            path = root / "parts/android.json"
            value = json.loads(path.read_text())
            value["cohort_sha256"] = "0" * 64
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                P.verify_parts(cohort, root)

    def test_native_relabelled_architecture_and_web_overlapping_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            cohort = self.parts(root)
            path = root / "parts/web.json"
            value = json.loads(path.read_text())
            native = root / "linux-x86_64/nestlink-server"
            value["artifacts"][0] = P.file_record(root, native, "web-static")
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                P.verify_parts(cohort, root)
            raw = bytearray(64)
            raw[:6] = b"\x7fELF\x02\x01"
            raw[18:20] = (62).to_bytes(2, "little")
            native.write_bytes(raw)
            P.elf(native, 62)
            with self.assertRaises(ValueError):
                P.elf(native, 183)

    def test_archive_roundtrip_is_deterministic_and_rejects_case_collisions(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            tree = root / "tree"
            tree.mkdir()
            (tree / "index.html").write_bytes(b"index")
            one, two = root / "one.tar.gz", root / "two.tar.gz"
            P.pack_tree(tree, one, 1700000000)
            P.pack_tree(tree, two, 1700000000)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            (tree / "INDEX.HTML").write_bytes(b"different")
            if len(list(tree.iterdir())) == 2:
                with self.assertRaises(ValueError):
                    P.pack_tree(tree, root / "case.tar.gz", 1700000000)

    def test_untrusted_web_tar_is_validated_fully_before_extraction(self):
        cases = [("../escape", b"outside", tarfile.REGTYPE), ("link", b"../../outside", tarfile.SYMTYPE)]
        for entry in cases:
            with self.subTest(path=entry[0]), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                path = root / "input.tar.gz"
                with tarfile.open(path, "w:gz") as archive:
                    first = tarfile.TarInfo("normal")
                    first.size = 1
                    archive.addfile(first, io.BytesIO(b"a"))
                    bad = tarfile.TarInfo(entry[0])
                    bad.type = entry[2]
                    bad.size = len(entry[1]) if bad.isfile() else 0
                    bad.linkname = entry[1].decode() if bad.issym() else ""
                    archive.addfile(bad, io.BytesIO(entry[1]) if bad.isfile() else None)
                with self.assertRaises(ValueError):
                    P.unpack_web(path, root / "output")
                self.assertFalse((root / "output/normal").exists())
                self.assertFalse((root / "escape").exists())

    def test_oci_checks_actual_layer_product_bytes_not_just_architecture_labels(self):
        cohort = self.cohort()
        expected = {"usr/local/bin/nestlink-server": sha(b"server"), "usr/share/nestlink/web/index.html": sha(b"index")}
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "image.tar"
            oci_image(path, cohort)
            self.assertTrue(P.inspect_oci(path, "arm64", cohort, expected)["product_bytes_verified"])
            for kwargs in ({"architecture": "amd64"}, {"payload": b"foreign-server"}, {"bad_blob": True}, {"duplicate": True}):
                oci_image(path, cohort, **kwargs)
                with self.subTest(case=kwargs), self.assertRaises(ValueError):
                    P.inspect_oci(path, "arm64", cohort, expected)

    def test_oci_later_whiteout_parent_link_extra_web_and_overwrite_are_rejected(self):
        cohort = self.cohort()
        expected = {"usr/local/bin/nestlink-server": sha(b"server"), "usr/share/nestlink/web/index.html": sha(b"index")}
        for later in (
            [("usr/local/bin/.wh.nestlink-server", b"", tarfile.REGTYPE)],
            [("usr/local/bin", b"/outside", tarfile.SYMTYPE)],
            [("usr/share/nestlink/web/extra.js", b"unexpected", tarfile.REGTYPE)],
            [("usr/local/bin/nestlink-server", b"substituted", tarfile.REGTYPE)],
            [(".wh..wh..opq", b"", tarfile.REGTYPE)],
        ):
            with self.subTest(later=later), tempfile.TemporaryDirectory() as scratch:
                path = Path(scratch) / "image.tar"
                oci_image(path, cohort, later=later)
                with self.assertRaises(ValueError):
                    P.inspect_oci(path, "arm64", cohort, expected)

    def test_os_sbom_comes_from_installed_image_packages_and_rejects_duplicate_records(self):
        status = "Package: libc6\nVersion: 2.39-test\nArchitecture: arm64\nStatus: install ok installed\n\nPackage: removed\nVersion: 1\nArchitecture: all\nStatus: deinstall ok config-files\n"
        value = P.debian_packages(status)
        self.assertEqual([item["name"] for item in value], ["libc6"])
        with self.assertRaises(ValueError):
            P.debian_packages(status + "\n\n" + status)
        with self.assertRaises(ValueError):
            P.debian_packages("Package: libc6\nVersion: 2\nStatus: install ok installed\n")

    def test_signer_refuses_wrong_public_certificate_before_any_private_key_command(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            for name in ("metadata.json", "update.crt", "update.key"):
                (root / name).write_bytes(b"fixture")
            commands = []
            def fake_run(command, **kw):
                commands.append(command)
                return b"wrong-der"
            with patch.dict(os.environ, {"NESTLINK_UPDATE_KEY_PASSWORD": "fixture-only"}), patch.object(P, "run", side_effect=fake_run), self.assertRaises(ValueError):
                P.sign_metadata(root / "metadata.json", root / "metadata.p7s", root / "update.crt", root / "update.key", "0" * 64)
            self.assertEqual(len(commands), 1)
            self.assertEqual(commands[0][1], "x509")
            self.assertFalse((root / "metadata.p7s").exists())

    def test_finalize_preserves_part_bytes_and_adds_image_bound_sbom_and_notices(self):
        # This is a protocol fixture, with the CMS boundary explicitly mocked.
        # It exercises the real readback/parts/OCI/SBOM/license assembly without
        # generating a certificate or pretending fixture bytes are installable.
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            cohort_path = self.parts(root)
            cohort, config = self.cohort(), self.policy()
            web_tree = root / "web-input"
            web_tree.mkdir()
            (web_tree / "index.html").write_bytes(b"index")
            web_file = root / "NestLink-web-static.tar.gz"
            web_file.unlink()
            P.pack_tree(web_tree, web_file, cohort["source_epoch"])
            web_part = json.loads((root / "parts/web.json").read_text())
            web_part["artifacts"] = [P.file_record(root, web_file, "web-static")]
            (root / "parts/web.json").write_text(json.dumps(web_part))
            build_license = root / "license-input"
            build_license.mkdir()
            (build_license / "LICENSE").write_bytes(b"fixture-product-license")
            P.pack_tree(build_license, root / "build-licenses.tar.gz", cohort["source_epoch"])
            P.create_json(root / "build-sbom.json", {"packages": []})
            (root / "source.tar").write_bytes(b"fixture-source")
            metadata_items = [P.file_record(root, root / path, role) for path, role in (("source.tar", "source"), ("build-sbom.json", "sbom-input"), ("build-licenses.tar.gz", "licenses-input"))]
            P.create_json(root / "parts/metadata.json", {"schema_version": 1, "kind": "nestlink-release-part", "part": "metadata", "cohort_sha256": P.digest(cohort_path), "artifacts": metadata_items, "evidence": []})
            for part, target, architecture in (("oci-x64", "linux-x64", "amd64"), ("oci-arm64", "linux-arm64", "arm64")):
                source = root / (part + ".tar")
                oci_image(source, cohort, architecture=architecture, payload=("native-" + target + "-server").encode())
                expected = {"usr/local/bin/nestlink-server": sha(("native-" + target + "-server").encode()), "usr/share/nestlink/web/index.html": sha(b"index")}
                proof = P.inspect_oci(source, architecture, cohort, expected)
                system_files = proof.pop("system_files")
                proof.update(cohort_sha256=P.digest(cohort_path), base=config["oci_base"])
                proof_path = root / "evidence" / (part + ".json")
                P.create_json(proof_path, proof)
                notices = root / (part + "-notice-input")
                notices.mkdir()
                for name, raw in system_files.items():
                    destination = notices / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(raw)
                P.create_json(notices / "notice-link-index.json", proof["system_notice_links"])
                notice_file = root / "evidence" / (part + "-system-notices.tar.gz")
                P.pack_tree(notices, notice_file, cohort["source_epoch"])
                P.create_json(root / "parts" / (part + ".json"), {"schema_version": 1, "kind": "nestlink-release-part", "part": part, "cohort_sha256": P.digest(cohort_path), "artifacts": [P.file_record(root, source, part)], "evidence": [P.file_record(root, proof_path, "oci-descriptor-readback"), P.file_record(root, notice_file, "oci-system-notices")]})
            for name in P.PACKAGE_PATHS.values():
                (root / name).write_bytes(b"fixture-package")
            native_common = {"source_revision": cohort["source_revision"], "version": cohort["version"], "release_sequence": cohort["release_sequence"]}
            P.create_json(root / "native-payload.json", {**native_common, "purpose": "native-payload"})
            P.create_json(root / "native-packages.json", {**native_common, "purpose": "native-packages", "artifacts": [{"payload_manifest_sha256": P.digest(root / "native-payload.json")} for _ in P.PACKAGE_PATHS]})
            for name in ("native-payload.p7s", "native-packages.p7s", "update.crt", "update.key"):
                (root / name).write_bytes(b"explicit-fixture")
            args = argparse.Namespace(cohort=cohort_path, bundle=root, output=root, certificate=root / "update.crt", key=root / "update.key", openssl="openssl")
            before = {path.relative_to(root).as_posix(): P.digest(path) for path in (root / "parts").glob("*.json")}
            before.update({item["path"]: item["sha256"] for item in metadata_items})
            fake_verify = SimpleNamespace(verify_bundle=lambda bundle, manifest, *args, **kwargs: json.loads(manifest.read_text()))
            def fixture_sign(path, signature, *args):
                signature.write_bytes(b"mock-CMS-" + P.digest(path).encode())
            with patch.object(P, "load_cohort", return_value=(cohort, config)), patch.object(P, "module", return_value=fake_verify), patch.object(P, "sign_metadata", side_effect=fixture_sign):
                P.finalize(args)
            self.assertTrue(all(P.digest(root / path) == expected for path, expected in before.items()))
            final = json.loads((root / "release-cohort.json").read_text())
            self.assertEqual(len(final["artifacts"]), len(P.FINAL_ROLES))
            self.assertEqual({item["role"] for item in final["artifacts"]}, P.FINAL_ROLES)
            self.assertEqual(final["installed_product_acceptance"], "pending")
            sbom = json.loads((root / "NestLink-sbom.spdx.json").read_text())
            self.assertEqual(len(sbom["packages"]), 2)
            self.assertEqual({entry["name"] for entry in sbom["packages"]}, {"libc6"})
            with tarfile.open(root / "NestLink-licenses.tar.gz") as archive:
                names = archive.getnames()
            self.assertIn("oci-x64/usr/share/doc/libc6/copyright", names)
            self.assertIn("oci-arm64/usr/share/doc/libc6/copyright", names)


if __name__ == "__main__":
    unittest.main()
