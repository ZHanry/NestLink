"""RC publication tests use owned temporary files and a local GitHub model."""
import argparse
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("rc_publish_test", ROOT / "scripts/refactor-rc-publish.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
REVISION = "1" * 40
BASE = "/repos/" + P.REPOSITORY


def checksum(raw):
    return hashlib.sha256(raw).hexdigest()


class FakeGitHub:
    def __init__(self):
        self.calls, self.payloads, self.downloads = [], [], []
        self.node_id, self.full_name, self.default_branch = P.REPOSITORY_ID, P.REPOSITORY, "main"
        self.source, self.tag_source, self.release = REVISION, None, None
        self.assets, self.digest_mode = {}, "sha256"
        self.upload_hook, self.read_hook, self.readback_hook = None, None, None
        self.corrupt_digest = False

    @property
    def writes(self):
        return [(method, path) for method, path in self.calls if method != "GET"]

    def metadata(self, value):
        result = {key: item for key, item in value.items() if key != "raw"}
        if self.digest_mode == "sha256":
            result["digest"] = "sha256:" + ("0" * 64 if self.corrupt_digest else checksum(value["raw"]))
        elif self.digest_mode == "invalid":
            result["digest"] = "sha512:unsupported"
        return result

    def request(self, method, path, **kwargs):
        self.calls.append((method, path))
        if method == "GET" and path == BASE:
            return {"node_id": self.node_id, "full_name": self.full_name, "default_branch": self.default_branch}
        if method == "GET" and path == BASE + "/git/ref/heads/main":
            return {"object": {"type": "commit", "sha": self.source}}
        if method == "GET" and path == BASE + "/git/ref/tags/" + P.TAG:
            if self.tag_source is None:
                raise P.Missing()
            return {"object": {"type": "commit", "sha": self.tag_source}}
        if method == "POST" and path == BASE + "/git/refs":
            assert kwargs["value"] == {"ref": "refs/tags/" + P.TAG, "sha": REVISION}
            assert self.tag_source is None
            self.tag_source = kwargs["value"]["sha"]
            return {"object": {"type": "commit", "sha": self.tag_source}}
        if method == "GET" and path == BASE + "/releases/tags/" + P.TAG:
            if self.release is None or self.release["draft"]:
                raise P.Missing()
            return dict(self.release)
        if method == "POST" and path == BASE + "/releases":
            value = kwargs["value"]
            assert value["draft"] is True and value["prerelease"] is True and value["make_latest"] == "false"
            self.payloads.append(copy.deepcopy(value))
            self.release = {**value, "id": 17}
            return dict(self.release)
        if method == "POST" and path.startswith(BASE + "/releases/17/assets?name="):
            name = urllib.parse.unquote(path.split("?name=", 1)[1])
            assert name not in self.assets and self.release["draft"] is True
            raw = kwargs["stream"].read()
            assert kwargs["length"] == len(raw) and kwargs["upload"] is True
            value = {"id": 1000 + len(self.assets), "name": name, "size": len(raw), "state": "uploaded", "raw": raw}
            self.assets[name] = value
            if self.upload_hook:
                self.upload_hook(self, value)
            return self.metadata(value)
        if method == "GET" and path.startswith(BASE + "/releases/assets/"):
            asset_id = int(path.rsplit("/", 1)[1])
            value = next(item for item in self.assets.values() if item["id"] == asset_id)
            if self.readback_hook:
                self.readback_hook(self, value)
            return self.metadata(value)
        if method == "PATCH" and path == BASE + "/releases/17":
            value = kwargs["value"]
            assert value == {"draft": False, "prerelease": True, "make_latest": "false"}
            self.payloads.append(copy.deepcopy(value))
            self.release.update(value)
            return dict(self.release)
        if method == "GET" and path == BASE + "/releases/17":
            if self.read_hook:
                self.read_hook(self)
            return dict(self.release)
        raise AssertionError((method, path))

    def pages(self, path):
        self.calls.append(("GET", path))
        if path == BASE + "/releases":
            return [dict(self.release)] if self.release else []
        assert path == BASE + "/releases/17/assets"
        return [self.metadata(value) for value in self.assets.values()]

    def download_digest(self, repository, asset_id, expected_bytes):
        assert repository == P.REPOSITORY
        self.downloads.append(asset_id)
        self.calls.append(("GET", "download-by-id:" + str(asset_id)))
        value = next(item for item in self.assets.values() if item["id"] == asset_id)
        assert len(value["raw"]) == expected_bytes
        return "0" * 64 if self.corrupt_digest else checksum(value["raw"])


class RCPublicationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="rc-publish-test-")
        self.addCleanup(self.scratch.cleanup)
        root = Path(self.scratch.name)
        source, bundle = root / "source", root / "bundle"
        source.mkdir()
        (source / "Cargo.toml").write_text('[workspace.package]\nversion = "' + P.VERSION + '"\n', encoding="utf-8")
        (bundle / "files").mkdir(parents=True)
        self.args = argparse.Namespace(action="publish", repository=P.REPOSITORY, source_root=source,
                                       bundle=bundle, manifest=bundle / P.MANIFEST_NAME, output=root / "receipt.json")
        products = []
        for role in sorted(P.CURRENT_ROLES):
            path = "files/" + role + ".bin"
            raw = ("fixture:" + role).encode()
            (bundle / path).write_bytes(raw)
            products.append({"id": role, "role": role, "path": path, "bytes": len(raw),
                             "sha256": checksum(raw), "source_revision": REVISION})
        self.manifest = {"schema_version": 1, "kind": "nestlink-development-candidate-build", "product": "NestLink",
                         "repository": P.REPOSITORY, "repository_node_id": P.REPOSITORY_ID, "version": P.VERSION,
                         "source_revision": REVISION, "cohort_sha256": "a" * 64, "signing": dict(P.SIGNING),
                         "production_update_eligible": False, "user_full_functional_acceptance": "pending",
                         "acceptance_cases": [{"id": name, "status": "pending", "evidence_artifact_id": "acceptance"}
                                              for name in sorted(P.REQUIRED_CASES)], "artifacts": products}
        self.write_manifest()
        self.write_report_acceptance()
        self.clean = patch.object(P, "clean_source")
        self.clean.start()
        self.addCleanup(self.clean.stop)
        self.github = FakeGitHub()

    def write_manifest(self):
        self.args.manifest.write_text(json.dumps(self.manifest, indent=2) + "\n", encoding="utf-8")

    def write_report_acceptance(self, mutate=None, entries=None):
        # Synthetic fixture only: these bytes never qualify a real product.
        raw = b"Synthetic publication protocol fixture, not real measurements."
        self.report = {"schema_version": 1, "kind": "nestlink-remediation-acceptance", "repository": P.REPOSITORY,
                       "version": P.VERSION, "source_revision": REVISION,
                       "manifest_sha256": checksum(self.args.manifest.read_bytes()), "report_sha256": P.REPORT_SHA256,
                       "status": "passed", "reviewer": "Synthetic test fixture", "reviewed_at": "2026-10-20T00:00:00Z",
                       "cases": [{"id": name, "status": "passed", "evidence": ["evidence/fixture.txt"]}
                                 for name in sorted(P.REMEDIATION_CASES)],
                       "evidence": [{"path": "evidence/fixture.txt", "bytes": len(raw), "sha256": checksum(raw)}]}
        if mutate:
            mutate(self.report)
        with zipfile.ZipFile(self.args.bundle / P.REMEDIATION_NAME, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("remediation-acceptance.json", json.dumps(self.report))
            archive.writestr("evidence/fixture.txt", raw)
            for name, content in entries or []:
                archive.writestr(name, content)

    def upload_draft(self):
        self.args.action = "upload-draft"
        return P.promote(self.args, self.github)

    def test_policy_matches_the_separate_rc_producer_without_relaxing_formal_release(self):
        spec = importlib.util.spec_from_file_location("candidate_rc_policy_test", ROOT / "scripts/refactor-candidate-producer.py")
        producer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(producer)
        self.assertEqual((P.REPOSITORY, P.REPOSITORY_ID, P.VERSION, P.SIGNING),
                         (producer.REPOSITORY, producer.REPOSITORY_ID, producer.VERSION, producer.SIGNING))
        self.assertEqual(P.CURRENT_ROLES, producer.CURRENT_ROLES)
        self.assertEqual(P.REQUIRED_CASES, producer.REQUIRED_CASES)
        self.assertEqual((len(P.CURRENT_ROLES), len(P.REQUIRED_CASES)), (18, 30))
        old_spec = importlib.util.spec_from_file_location("formal_release_policy_test", ROOT / "scripts/refactor-release-publish.py")
        old = importlib.util.module_from_spec(old_spec)
        old_spec.loader.exec_module(old)
        self.assertEqual(old.REPOSITORY_ID, "R_kgDOTz-mRQ")
        self.assertNotIn(P.TAG, old.CURRENT_RELEASE_TAGS)

    def test_verify_is_read_only_and_accepts_a_missing_tag_and_release(self):
        self.args.action = "verify"
        result = P.promote(self.args, self.github)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["expected_assets"], 20)
        self.assertEqual(result["existing_assets_verified"], 0)
        self.assertFalse(self.github.writes)

    def test_upload_then_publish_reuses_every_verified_asset(self):
        draft = self.upload_draft()
        self.assertEqual(draft["status"], "draft-uploaded")
        self.assertEqual(len(self.github.assets), 20)
        self.assertFalse(any(method == "PATCH" for method, _ in self.github.calls))
        before = len(self.github.writes)
        self.args.action = "publish"
        result = P.promote(self.args, self.github)
        self.assertEqual(result["status"], "published-prerelease")
        self.assertEqual(len(self.github.writes), before + 1)
        self.assertEqual(len(result["uploads"]), 20)
        self.assertTrue(all(item["readback"] == "github-asset-id-sha256" for item in result["uploads"]))
        self.assertFalse(self.github.downloads)
        self.assertEqual(self.github.writes[-1], ("PATCH", BASE + "/releases/17"))
        self.assertFalse(any(method == "DELETE" for method, _ in self.github.calls))

    def test_draft_tag_404_is_discovered_and_read_back_by_id_without_writes(self):
        self.upload_draft()
        before = list(self.github.writes)
        self.github.calls.clear()
        self.args.action = "verify"
        result = P.promote(self.args, self.github)
        self.assertEqual(result["release_id"], 17)
        self.assertEqual(result["existing_assets_verified"], 20)
        self.assertIn(("GET", BASE + "/releases"), self.github.calls)
        self.assertIn(("GET", BASE + "/releases/17"), self.github.calls)
        self.assertEqual(self.github.writes, [])
        self.assertTrue(before)

    def test_ambiguous_draft_discovery_is_refused_without_writes(self):
        self.upload_draft()
        before = list(self.github.writes)
        pages = self.github.pages
        def duplicate(path):
            result = pages(path)
            return result + copy.deepcopy(result) if path == BASE + "/releases" else result
        with patch.object(self.github, "pages", side_effect=duplicate), self.assertRaisesRegex(ValueError, "ambiguous"):
            P.promote(self.args, self.github)
        self.assertEqual(self.github.writes, before)

    def test_draft_id_or_state_changing_after_listing_blocks_every_write(self):
        self.upload_draft()
        before = list(self.github.writes)
        original = dict(self.github.release)
        for field, value in (("id", 18), ("draft", False)):
            with self.subTest(field=field):
                self.github.release = dict(original)
                self.github.read_hook = lambda gh, field=field, value=value: gh.release.update({field: value})
                with self.assertRaisesRegex(ValueError, "draft identity or state"):
                    P.promote(self.args, self.github)
                self.assertEqual(self.github.writes, before)

    def test_published_release_missing_from_tag_lookup_is_refused(self):
        P.promote(self.args, self.github)
        before = list(self.github.writes)
        request = self.github.request
        def missing_tag(method, path, **kwargs):
            if path == BASE + "/releases/tags/" + P.TAG:
                raise P.Missing()
            return request(method, path, **kwargs)
        with patch.object(self.github, "request", side_effect=missing_tag), self.assertRaisesRegex(ValueError, "absent from its tag lookup"):
            P.promote(self.args, self.github)
        self.assertEqual(self.github.writes, before)

    def test_publish_is_idempotent_and_preserves_explicit_pending_signing(self):
        result = P.promote(self.args, self.github)
        before = list(self.github.writes)
        again = P.promote(self.args, self.github)
        self.assertEqual(again["status"], "published-prerelease")
        self.assertFalse(again["remote_mutation_performed"])
        self.assertEqual(self.github.writes, before)
        self.assertEqual(result["signing"], P.SIGNING)
        self.assertFalse(result["production_update_eligible"])
        self.assertEqual(result["pending_acceptance_cases"], 30)
        self.assertEqual(result["report_remediation_acceptance"], "passed")
        self.assertEqual(result["report_acceptance_cases"], 25)
        self.assertIn("30 pending", self.github.release["body"])
        self.assertIn("pending", self.github.release["body"])
        self.assertTrue(self.github.release["prerelease"])

    def test_asset_id_metadata_is_read_even_when_upload_response_has_a_digest(self):
        result = P.promote(self.args, self.github)
        metadata_reads = [path for method, path in self.github.calls if path.startswith(BASE + "/releases/assets/")]
        self.assertGreaterEqual(len(metadata_reads), 38)
        self.assertTrue(result["remote_asset_readback_verified"])

    def test_missing_api_digest_uses_download_by_asset_id_only(self):
        self.github.digest_mode = "absent"
        result = P.promote(self.args, self.github)
        self.assertEqual(len(set(self.github.downloads)), 20)
        self.assertTrue(all(item["readback"] == "download-sha256" for item in result["uploads"]))

    def test_malformed_or_wrong_api_digest_keeps_release_draft(self):
        for mode in ("invalid", "sha256"):
            with self.subTest(mode=mode):
                github = FakeGitHub()
                github.digest_mode, github.corrupt_digest = mode, True
                with self.assertRaises(ValueError):
                    P.promote(self.args, github)
                self.assertTrue(github.release["draft"])
                self.assertFalse(github.downloads)
                self.assertFalse(any(method in ("PATCH", "DELETE") for method, _ in github.calls))

    def test_corrupt_fallback_download_cannot_publish(self):
        self.github.digest_mode, self.github.corrupt_digest = "absent", True
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.assertTrue(self.github.release["draft"])
        self.assertFalse(any(method == "PATCH" for method, _ in self.github.calls))

    def test_partial_upload_resumes_without_reupload_or_delete(self):
        def interrupt(github, value):
            if len(github.assets) == 4:
                raise OSError("simulated connection interruption")
        self.github.upload_hook = interrupt
        with self.assertRaises(OSError):
            P.promote(self.args, self.github)
        first_ids = {name: item["id"] for name, item in self.github.assets.items()}
        self.github.upload_hook = None
        result = P.promote(self.args, self.github)
        self.assertEqual(result["status"], "published-prerelease")
        self.assertEqual(first_ids, {name: self.github.assets[name]["id"] for name in first_ids})
        posts = [path for method, path in self.github.calls if method == "POST" and "/assets?name=" in path]
        self.assertEqual(len(posts), 20)
        self.assertFalse(any(method == "DELETE" for method, _ in self.github.calls))

    def test_wrong_repository_node_main_or_tag_blocks_every_write(self):
        for field, value in (("node_id", "R_kgDOTz-mRQ"), ("full_name", "ZHanry/home-tunnel"),
                             ("default_branch", "master"), ("source", "2" * 40), ("tag_source", "2" * 40)):
            with self.subTest(field=field):
                github = FakeGitHub()
                setattr(github, field, value)
                with self.assertRaises(ValueError):
                    P.promote(self.args, github)
                self.assertFalse(github.writes)

    def test_wrong_existing_bytes_or_extra_asset_is_never_overwritten(self):
        self.upload_draft()
        before = list(self.github.writes)
        first = next(iter(self.github.assets.values()))
        first["raw"] = b"x" * first["size"]
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.assertEqual(self.github.writes, before)
        first["raw"] = ("fixture:" + first["name"].removesuffix(".bin")).encode()
        self.github.assets["unreviewed.bin"] = {"id": 5000, "name": "unreviewed.bin", "size": 1, "state": "uploaded", "raw": b"x"}
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.assertEqual(self.github.writes, before)

    def test_duplicate_names_ids_and_wrong_asset_id_metadata_are_refused(self):
        self.upload_draft()
        before = list(self.github.writes)
        original = copy.deepcopy(self.github.assets)
        first = next(iter(self.github.assets.values()))
        duplicate = copy.deepcopy(first)
        duplicate["name"] = duplicate["name"].upper()
        self.github.assets["collision"] = duplicate
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.github.assets = copy.deepcopy(original)
        one, two = list(self.github.assets.values())[:2]
        two["id"] = one["id"]
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.github.assets = copy.deepcopy(original)
        self.github.readback_hook = lambda github, value: value.update(name="different.bin")
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.assertEqual(self.github.writes, before)

    def test_existing_release_cannot_claim_formal_acceptance_or_be_non_prerelease(self):
        self.upload_draft()
        before = list(self.github.writes)
        original = dict(self.github.release)
        for changes in ({"body": "All formal signing and user acceptance passed."}, {"prerelease": False},
                        {"tag_name": "v15.0.0"}, {"name": "Official stable release"}, {"id": True}):
            with self.subTest(changes=changes):
                self.github.read_hook = None
                self.github.release = {**original, **changes}
                if "tag_name" in changes:
                    # An unrelated tag in the list is a different release.
                    # Reject our selected draft changing tag at ID readback.
                    self.github.release = dict(original)
                    self.github.read_hook = lambda gh, changes=changes: gh.release.update(changes)
                with self.assertRaises(ValueError):
                    P.promote(self.args, self.github)
        self.assertEqual(self.github.writes, before)

    def test_missing_published_asset_cannot_be_appended(self):
        P.promote(self.args, self.github)
        self.github.assets.pop(next(iter(self.github.assets)))
        before = list(self.github.writes)
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.assertEqual(self.github.writes, before)

    def test_main_tag_repository_or_release_change_during_upload_blocks_publication(self):
        for field, value in (("source", "2" * 40), ("tag_source", "2" * 40), ("node_id", "wrong-node")):
            with self.subTest(field=field):
                github = FakeGitHub()
                github.upload_hook = lambda gh, item, field=field, value=value: setattr(gh, field, value)
                with self.assertRaises(ValueError):
                    P.promote(self.args, github)
                self.assertTrue(github.release["draft"])
                self.assertFalse(any(method == "PATCH" for method, _ in github.calls))
        self.github.upload_hook = lambda gh, item: gh.release.update(body="Changed declaration")
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.assertTrue(self.github.release["draft"])

    def test_manifest_or_uploaded_local_bytes_change_during_upload_blocks_publication(self):
        original_manifest = self.args.manifest.read_bytes()
        first = self.manifest["artifacts"][0]
        path = self.args.bundle / first["path"]
        original_product = path.read_bytes()
        evidence = self.args.bundle / P.REMEDIATION_NAME
        original_evidence = evidence.read_bytes()
        for target, raw in ((path, b"x" * len(original_product)), (self.args.manifest, original_manifest + b" "),
                            (evidence, b"x" * len(original_evidence))):
            with self.subTest(target=target.name):
                path.write_bytes(original_product)
                self.args.manifest.write_bytes(original_manifest)
                evidence.write_bytes(original_evidence)
                github = FakeGitHub()
                github.upload_hook = lambda gh, item, target=target, raw=raw: target.write_bytes(raw)
                with self.assertRaises(ValueError):
                    P.promote(self.args, github)
                self.assertTrue(github.release["draft"])
                self.assertFalse(any(method == "PATCH" for method, _ in github.calls))

    def test_changed_source_after_initial_check_blocks_all_remote_writes(self):
        P.clean_source.side_effect = [None, ValueError("source became dirty")]
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.assertFalse(self.github.writes)

    def test_changed_source_after_upload_keeps_draft(self):
        P.clean_source.side_effect = [None, None, ValueError("source became dirty")]
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.assertTrue(self.github.release["draft"])
        self.assertFalse(any(method == "PATCH" for method, _ in self.github.calls))

    def test_report_changed_during_final_remote_readback_keeps_draft(self):
        evidence = self.args.bundle / P.REMEDIATION_NAME
        # Initial inventory has no release. The hook runs on final draft readback,
        # after the first post-upload local check and before public promotion.
        self.github.read_hook = lambda gh: evidence.write_bytes(b"changed after local check")
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.assertTrue(self.github.release["draft"])
        self.assertFalse(any(method == "PATCH" for method, _ in self.github.calls))

    def test_invalid_manifest_identity_signing_or_acceptance_never_reaches_github(self):
        original = copy.deepcopy(self.manifest)
        mutations = [lambda value: value.update(repository_node_id="R_kgDOTz-mRQ"),
                     lambda value: value.update(repository="ZHanry/home-tunnel"),
                     lambda value: value.update(version="15.0.0"), lambda value: value.update(product="Other"),
                     lambda value: value.update(schema_version=True), lambda value: value.update(source_revision="main"),
                     lambda value: value.update(cohort_sha256="invalid"),
                     lambda value: value.update(production_update_eligible=True),
                     lambda value: value["signing"].update(windows="signed"),
                     lambda value: value.update(user_full_functional_acceptance="passed"),
                     lambda value: value["acceptance_cases"][0].update(status="passed"),
                     lambda value: value["acceptance_cases"].pop(),
                     lambda value: value["acceptance_cases"][0].update(id="android-api-29"),
                     lambda value: value["acceptance_cases"][0].update(evidence_artifact_id="missing"),
                     lambda value: value.update(unreviewed_field=True)]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.manifest = copy.deepcopy(original)
                mutate(self.manifest)
                self.write_manifest()
                with self.assertRaises(ValueError):
                    P.promote(self.args, self.github)
                self.assertFalse(self.github.calls)

    def test_missing_duplicate_or_mixed_source_artifact_roles_are_refused(self):
        original = copy.deepcopy(self.manifest)
        mutations = [lambda value: value["artifacts"].pop(),
                     lambda value: value["artifacts"].__setitem__(0, copy.deepcopy(value["artifacts"][1])),
                     lambda value: value["artifacts"][0].update(source_revision="2" * 40),
                     lambda value: value["artifacts"][0].update(id="other"),
                     lambda value: value["artifacts"][0].update(extra=True)]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.manifest = copy.deepcopy(original)
                mutate(self.manifest)
                self.write_manifest()
                with self.assertRaises(ValueError):
                    P.promote(self.args, self.github)
                self.assertFalse(self.github.calls)

    def test_duplicate_manifest_json_fields_and_wrong_filename_are_refused(self):
        raw = self.args.manifest.read_text(encoding="utf-8")
        self.args.manifest.write_text(raw.replace('"schema_version": 1,', '"schema_version": 1, "schema_version": 1,'), encoding="utf-8")
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.write_manifest()
        self.args.manifest = self.args.bundle / "renamed.json"
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.assertFalse(self.github.calls)

    def test_unsafe_traversal_reserved_ads_colliding_names_are_refused(self):
        first = self.manifest["artifacts"][0]
        paths = ("../outside.bin", "/absolute.bin", "files/../outside.bin", "files\\bad.bin", "files/CON.txt",
                 "files/bad:stream", "files/has space.bin", "files/name.", "files//name.bin", "files/bad\x7f.bin",
                 "files/" + P.MANIFEST_NAME, self.manifest["artifacts"][1]["path"].upper())
        for value in paths:
            with self.subTest(value=value):
                first["path"] = value
                self.write_manifest()
                with self.assertRaises(ValueError):
                    P.promote(self.args, self.github)
                self.assertFalse(self.github.calls)

    def test_zero_bool_negative_and_over_2gib_sizes_are_rejected_before_api(self):
        first = self.manifest["artifacts"][0]
        for size in (0, False, -1, P.MAX_ASSET_BYTES + 1, "1024"):
            with self.subTest(size=size):
                first["bytes"] = size
                self.write_manifest()
                with self.assertRaises(ValueError):
                    P.promote(self.args, self.github)
                self.assertFalse(self.github.calls)
        first["bytes"] = P.MAX_ASSET_BYTES
        self.write_manifest()
        self.write_report_acceptance()
        with patch.object(P, "fixed_file"):
            self.assertEqual(P.local_plan(self.args)["uploads"][0]["bytes"], P.MAX_ASSET_BYTES)

    def test_missing_report_evidence_blocks_every_action_before_github(self):
        (self.args.bundle / P.REMEDIATION_NAME).unlink()
        for action in ("verify", "upload-draft", "publish"):
            with self.subTest(action=action):
                self.args.action = action
                with self.assertRaises(OSError):
                    P.promote(self.args, self.github)
                self.assertFalse(self.github.calls)

    def test_report_pending_failed_incomplete_or_unbound_cannot_reach_github(self):
        mutations = [lambda v: v.update(status="pending"), lambda v: v.update(status="failed"),
                     lambda v: v.update(source_revision="2" * 40), lambda v: v.update(manifest_sha256="0" * 64),
                     lambda v: v.update(report_sha256="0" * 64), lambda v: v.update(version="0.6.0-rc.1"),
                     lambda v: v.update(repository="ZHanry/other"), lambda v: v.update(schema_version=True),
                     lambda v: v.update(reviewer=" "), lambda v: v.update(reviewer="bad\nreviewer"),
                     lambda v: v.update(reviewed_at="2099-01-01T00:00:00Z"),
                     lambda v: v.update(reviewed_at="2026-10-20"),
                     lambda v: v["cases"].pop(), lambda v: v["cases"][0].update(id="unknown"),
                     lambda v: v["cases"][0].update(status="pending"),
                     lambda v: v["cases"][0].update(status="failed"),
                     lambda v: v["cases"][0].update(evidence=[]),
                     lambda v: v["cases"][0].update(evidence=["evidence/missing.txt"]),
                     lambda v: v["cases"].__setitem__(0, copy.deepcopy(v["cases"][1])),
                     lambda v: v["evidence"][0].update(sha256="0" * 64),
                     lambda v: v["evidence"][0].update(bytes=True),
                     lambda v: v["evidence"][0].update(path="../outside.txt"),
                     lambda v: v.update(evidence=[]), lambda v: v.update(extra=True)]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.write_report_acceptance(mutate)
                with self.assertRaises(ValueError):
                    P.promote(self.args, self.github)
                self.assertFalse(self.github.calls)

    def test_evidence_archive_rejects_unlisted_duplicate_traversal_and_links(self):
        link = zipfile.ZipInfo("evidence/link")
        link.create_system, link.external_attr = 3, 0o120777 << 16
        entries = [("evidence/unlisted.txt", b"extra"), ("EVIDENCE/FIXTURE.TXT", b"collision"),
                   ("../outside.txt", b"traversal"), ("evidence/dir/", b"directory"),
                   (link, b"fixture.txt")]
        for entry in entries:
            with self.subTest(entry=entry[0]):
                self.write_report_acceptance(entries=[entry])
                with self.assertRaises(ValueError):
                    P.promote(self.args, self.github)
                self.assertFalse(self.github.calls)

    def test_compressed_oversize_or_invalid_evidence_cannot_reach_github(self):
        self.write_report_acceptance(entries=[("evidence/large.bin", b"x" * (16 * 1024**2 + 1))])
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        (self.args.bundle / P.REMEDIATION_NAME).write_bytes(b"not a zip")
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.assertFalse(self.github.calls)

    def test_symlinks_and_reparse_metadata_are_refused(self):
        first = self.manifest["artifacts"][0]
        path = self.args.bundle / first["path"]
        actual = path.lstat()
        class Reparse:
            st_mode, st_size, st_file_attributes = actual.st_mode, actual.st_size, 0x400
        with patch.object(Path, "lstat", return_value=Reparse()), self.assertRaises(ValueError):
            P.regular(path)
        target = self.args.bundle / "link.bin"
        try:
            target.symlink_to(path)
        except OSError:
            # The simulated Windows reparse test above still runs without
            # Developer Mode/SeCreateSymbolicLinkPrivilege on the test host.
            return
        with self.assertRaises(ValueError):
            P.regular(target)

    def test_wrong_local_bytes_or_size_never_reaches_github(self):
        first = self.manifest["artifacts"][0]
        path = self.args.bundle / first["path"]
        for raw in (b"x", b"x" * first["bytes"]):
            with self.subTest(size=len(raw)):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    P.promote(self.args, self.github)
                self.assertFalse(self.github.calls)

    def test_existing_missing_tag_release_is_refused_without_repair(self):
        self.upload_draft()
        self.github.tag_source = None
        before = list(self.github.writes)
        with self.assertRaises(ValueError):
            P.promote(self.args, self.github)
        self.assertEqual(self.github.writes, before)

    def test_real_clean_git_source_requires_main_revision_version_and_no_untracked_files(self):
        self.clean.stop()
        source = self.args.source_root
        subprocess.run(["git", "init", "--initial-branch=main", str(source)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "add", "Cargo.toml"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "-c", "user.name=RC Test", "-c", "user.email=rc-test@example.invalid",
                        "commit", "-m", "Owned publication fixture"], check=True, capture_output=True)
        revision = P.git(source, "rev-parse", "HEAD")
        P.clean_source(source, revision)
        with self.assertRaises(ValueError):
            P.clean_source(source, REVISION)
        (source / "untracked.txt").write_bytes(b"untracked")
        with self.assertRaises(ValueError):
            P.clean_source(source, revision)
        (source / "untracked.txt").unlink()
        subprocess.run(["git", "-C", str(source), "switch", "-c", "other"], check=True, capture_output=True)
        with self.assertRaises(ValueError):
            P.clean_source(source, revision)
        subprocess.run(["git", "-C", str(source), "switch", "main"], check=True, capture_output=True)
        (source / "Cargo.toml").write_text('[workspace.package]\nversion="15.0.0"\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            P.clean_source(source, revision)


class ClientTests(unittest.TestCase):
    def test_http_404_uses_the_exact_publication_missing_class(self):
        github = P.GitHub("fixture-token")
        error = urllib.error.HTTPError("https://api.github.com/missing", 404, "absent", {}, None)
        with patch.object(github.opener, "open", side_effect=error):
            with self.assertRaises(P.Missing):
                github.request("GET", "/missing")

    def test_download_digest_enforces_exact_byte_count(self):
        github = P.GitHub("fixture-token")
        for raw in (b"too-long", b"x"):
            with self.subTest(raw=raw), patch.object(github, "request", return_value=io.BytesIO(raw)), self.assertRaises(ValueError):
                github.download_digest(P.REPOSITORY, 1, 3)
        with patch.object(github, "request", return_value=io.BytesIO(b"abc")):
            self.assertEqual(github.download_digest(P.REPOSITORY, 1, 3), checksum(b"abc"))

    def test_transport_errors_never_echo_credential_query_urls(self):
        github = P.GitHub("fixture-token")
        with patch.object(github.opener, "open", side_effect=urllib.error.URLError("https://example.invalid/?secret=hidden")):
            with self.assertRaisesRegex(ValueError, "^GitHub transport failed$"):
                github.request("GET", "/missing")

    def test_redirect_strips_authorization_and_refuses_unexpected_hosts(self):
        policy = P.RedirectPolicy()
        request = urllib.request.Request("https://api.github.com/repos/example/repo/releases/assets/1",
                                         headers={"Authorization": "Bearer fixture-token"})
        redirected = policy.redirect_request(request, None, 302, "Found", {},
                                             "https://release-assets.githubusercontent.com/asset?token=fixture")
        self.assertFalse(redirected.has_header("Authorization"))
        for url in ("http://objects.githubusercontent.com/asset", "https://attacker.example/asset",
                    "https://user:password@objects.githubusercontent.com/asset", "https://objects.githubusercontent.com:444/asset"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                policy.redirect_request(request, None, 302, "Found", {}, url)

    def test_invalid_token_and_size_are_refused(self):
        for token in (None, "", "bad\ntoken", "bad\rtoken"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                P.GitHub(token)
        github = P.GitHub("fixture-token")
        for size in (0, True, P.MAX_ASSET_BYTES + 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                github.request("POST", "/uploads", stream=io.BytesIO(b"x"), upload=True, length=size)


if __name__ == "__main__":
    unittest.main()
