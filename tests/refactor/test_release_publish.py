"""Promotion protocol tests use a local GitHub model, never a live token/API."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_publish_test", ROOT / "scripts/refactor-release-publish.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
PRODUCER_SPEC = importlib.util.spec_from_file_location("release_producer_publish_test", ROOT / "scripts/refactor-release-producer.py")
PRODUCER = importlib.util.module_from_spec(PRODUCER_SPEC)
PRODUCER_SPEC.loader.exec_module(PRODUCER)

REVISION = "1" * 40
REPOSITORY = "ZHanry/home-tunnel"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class FakeGitHub:
    def __init__(self):
        self.calls, self.tag, self.release = [], False, None
        self.source = REVISION
        self.node_id = P.REPOSITORY_ID
        self.assets, self.legacy_changed, self.corrupt_download = {}, False, False
        self.change_during_upload = False

    @property
    def writes(self):
        return [(method, path) for method, path in self.calls if method != "GET"]

    def request(self, method, path, **kwargs):
        self.calls.append((method, path))
        base = "/repos/" + REPOSITORY
        if method == "GET" and path == base:
            return {"node_id": self.node_id, "full_name": REPOSITORY, "default_branch": "main"}
        if method == "GET" and path == base + "/git/ref/heads/main":
            return {"object": {"type": "commit", "sha": self.source}}
        if method == "GET" and path == base + "/git/ref/tags/v15.0.0":
            if not self.tag:
                raise P.Missing()
            return {"object": {"type": "commit", "sha": self.source}}
        if method == "POST" and path == base + "/git/refs":
            if kwargs["value"]["sha"] != self.source:
                raise AssertionError("wrong source")
            self.tag = True
            return {}
        if method == "GET" and path == base + "/releases/tags/v15.0.0":
            if self.release is None:
                raise P.Missing()
            return dict(self.release)
        if method == "POST" and path == base + "/releases":
            assert kwargs["value"]["draft"] is True
            self.release = {"id": 15, "tag_name": "v15.0.0", "draft": True, "prerelease": False}
            return dict(self.release)
        if method == "POST" and path.startswith(base + "/releases/15/assets?name="):
            name = path.split("?name=", 1)[1]
            raw = kwargs["stream"].read()
            assert kwargs["length"] == len(raw)
            value = {"id": 1000 + len(self.assets), "name": name, "size": len(raw), "state": "uploaded", "raw": raw}
            self.assets[name] = value
            if self.change_during_upload:
                self.legacy_changed = True
            return dict(value)
        if method == "PATCH" and path == base + "/releases/15":
            assert kwargs["value"]["draft"] is False
            self.release["draft"] = False
            return dict(self.release)
        if method == "GET" and path == base + "/releases/15":
            return dict(self.release)
        raise AssertionError((method, path))

    def pages(self, path):
        self.calls.append(("GET", path))
        base = "/repos/" + REPOSITORY
        if path == base + "/releases":
            return [{"id": 9, "tag_name": "v14.9.0"}] + ([dict(self.release)] if self.release else [])
        if path == base + "/releases/9/assets":
            result = [{"id": 77, "size": 6, "state": "uploaded", "digest": "sha256:" + digest(b"legacy")}]
            if self.legacy_changed:
                result.append({"id": 78, "size": 5, "state": "uploaded", "digest": "sha256:" + digest(b"extra")})
            return result
        if path == base + "/releases/15/assets":
            return [dict(value) for value in self.assets.values()]
        raise AssertionError(path)

    def download_digest(self, repository, asset_id, expected_bytes):
        self.calls.append(("GET", "asset-readback:" + str(asset_id)))
        if self.corrupt_download:
            return "0" * 64
        value = next(value for value in self.assets.values() if value["id"] == asset_id)
        assert len(value["raw"]) == expected_bytes
        return digest(value["raw"])


class PublishTests(unittest.TestCase):
    def test_signed_acceptance_handoff_must_preserve_every_fixed_candidate_byte(self):
        handoff_spec = importlib.util.spec_from_file_location("handoff_publish_binding_test", ROOT / "scripts/refactor-release-handoff.py")
        handoff_module = importlib.util.module_from_spec(handoff_spec)
        handoff_spec.loader.exec_module(handoff_module)
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            artifacts = []
            accepted = []
            for index, role in enumerate(sorted(handoff_module.CURRENT_ROLES | handoff_module.PRESERVATION_ROLES)):
                name = "file-" + str(index) + ".bin"
                (root / name).write_bytes(role.encode())
                record = PRODUCER.file_record(root, root / name, role)
                accepted.append(record)
                if role in handoff_module.CURRENT_ROLES - {"acceptance"}:
                    artifacts.append(record)
            cohort = {"kind": "nestlink-fixed-release", "version": "15.0.0", "repository_node_id": P.REPOSITORY_ID, "source_revision": REVISION, "artifacts": artifacts}
            PRODUCER.create_json(root / "cohort.json", cohort)
            PRODUCER.create_json(root / "handoff.json", {"artifacts": accepted})
            for name in ("cohort.p7s", "handoff.p7s", "update.crt"):
                (root / name).write_bytes(b"public-fixture")
            args = argparse.Namespace(bundle=root, cohort=root / "cohort.json", cohort_signature=root / "cohort.p7s",
                handoff=root / "handoff.json", handoff_signature=root / "handoff.p7s", certificate=root / "update.crt", certificate_sha256="a" * 64, openssl="openssl")
            fake_producer = SimpleNamespace(FINAL_ROLES=PRODUCER.FINAL_ROLES, json_read=PRODUCER.json_read, verify_record=PRODUCER.verify_record,
                regular=PRODUCER.regular, digest=PRODUCER.digest, configuration=lambda path: {"update_certificate_sha256": "a" * 64})
            fake_handoff = SimpleNamespace(CURRENT_ROLES=handoff_module.CURRENT_ROLES, PRESERVATION_ROLES=handoff_module.PRESERVATION_ROLES,
                prepare=Mock(side_effect=lambda args: {"source_revision": REVISION, "handoff_sha256": PRODUCER.digest(args.plan), "uploads": []}))
            fake_verify = SimpleNamespace(verify_cms=Mock())
            def modules(name, relative):
                return fake_producer if relative.endswith("producer.py") else fake_handoff if relative.endswith("handoff.py") else fake_verify
            with patch.object(P, "module", side_effect=modules):
                P.local_plan(args)
                fake_verify.verify_cms.assert_called_once()
                self.assertEqual(fake_handoff.prepare.call_args.args[0].expected_source, REVISION)
                changed = next(index for index, item in enumerate(accepted) if item["role"] in handoff_module.CURRENT_ROLES - {"acceptance"})
                accepted[changed] = {**accepted[changed], "sha256": "0" * 64}
                (root / "handoff.json").write_text(json.dumps({"artifacts": accepted}))
                with self.assertRaises(ValueError):
                    P.local_plan(args)

    def fixture(self, root):
        product, legacy = root / "product.bin", root / "legacy.blob"
        product.write_bytes(b"product")
        legacy.write_bytes(b"legacy")
        handoff_file = root / "handoff.json"
        handoff_file.write_text("{}")
        args = argparse.Namespace(action="publish", repository=REPOSITORY, bundle=root, handoff=handoff_file)
        handoff = {"legacy_assets": [{"component": "hub", "release_id": 9, "asset_id": 77, "bytes": 6, "sha256": digest(b"legacy")} ]}
        upload = {"source_revision": REVISION, "handoff_sha256": digest(b"{}"), "uploads": [
            {"asset_name": "product.bin", "local_path": "product.bin", "bytes": 7, "sha256": digest(b"product"), "role": "fixture-product"},
            {"asset_name": "legacy.blob", "local_path": "legacy.blob", "bytes": 6, "sha256": digest(b"legacy"), "role": "legacy-release-asset"},
        ]}
        handoff_module = SimpleNamespace(REPOSITORIES={"hub": (REPOSITORY, P.REPOSITORY_ID)})
        return args, (PRODUCER, handoff_module, handoff, upload)

    def test_real_mutation_protocol_uploads_draft_reads_every_asset_then_publishes(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, local = self.fixture(Path(scratch))
            github = FakeGitHub()
            with patch.object(P, "local_plan", return_value=local):
                result = P.promote(args, github)
            self.assertEqual(result["status"], "published")
            self.assertTrue(result["durable_remote_preservation_verified"])
            self.assertEqual(len(result["uploads"]), 2)
            last_write = github.writes[-1]
            self.assertEqual(last_write, ("PATCH", "/repos/" + REPOSITORY + "/releases/15"))
            self.assertTrue(all(method != "DELETE" for method, _ in github.calls))

    def test_verify_is_read_only_and_upload_draft_does_not_publish(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, local = self.fixture(Path(scratch))
            github = FakeGitHub()
            with patch.object(P, "local_plan", return_value=local):
                args.action = "verify"
                self.assertEqual(P.promote(args, github)["status"], "verified")
                self.assertFalse(github.writes)
                args.action = "upload-draft"
                self.assertEqual(P.promote(args, github)["status"], "draft-uploaded")
                self.assertTrue(github.release["draft"])
                self.assertFalse(any(method == "PATCH" for method, _ in github.calls))

    def test_publishing_is_idempotent_and_never_overwrites_an_uploaded_asset(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, local = self.fixture(Path(scratch))
            github = FakeGitHub()
            with patch.object(P, "local_plan", return_value=local):
                P.promote(args, github)
                before = len(github.writes)
                result = P.promote(args, github)
                self.assertEqual(result["status"], "published")
                self.assertEqual(len(github.writes), before)

    def test_changed_main_wrong_repository_or_changed_legacy_inventory_prevent_every_write(self):
        for field, value in (("source", "2" * 40), ("node_id", "wrong-node"), ("legacy_changed", True)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as scratch:
                args, local = self.fixture(Path(scratch))
                github = FakeGitHub()
                setattr(github, field, value)
                with patch.object(P, "local_plan", return_value=local), self.assertRaises(ValueError):
                    P.promote(args, github)
                self.assertFalse(github.writes)

    def test_failed_remote_readback_keeps_release_draft_and_preserves_source_releases(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, local = self.fixture(Path(scratch))
            github = FakeGitHub()
            github.corrupt_download = True
            with patch.object(P, "local_plan", return_value=local), self.assertRaises(ValueError):
                P.promote(args, github)
            self.assertTrue(github.release["draft"])
            self.assertFalse(any(method in ("PATCH", "DELETE") for method, _ in github.calls))

    def test_legacy_inventory_change_during_upload_blocks_publish(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, local = self.fixture(Path(scratch))
            github = FakeGitHub()
            github.change_during_upload = True
            with patch.object(P, "local_plan", return_value=local), self.assertRaises(ValueError):
                P.promote(args, github)
            self.assertTrue(github.release["draft"])
            self.assertFalse(any(method == "PATCH" for method, _ in github.calls))

    def test_existing_wrong_bytes_or_extra_assets_cannot_be_clobbered(self):
        for extra in (False, True):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as scratch:
                args, local = self.fixture(Path(scratch))
                github = FakeGitHub()
                github.tag = True
                github.release = {"id": 15, "tag_name": "v15.0.0", "draft": True, "prerelease": False}
                name = "unreviewed.bin" if extra else "product.bin"
                github.assets[name] = {"name": name, "id": 1000, "size": 3, "state": "uploaded", "raw": b"bad"}
                with patch.object(P, "local_plan", return_value=local), self.assertRaises(ValueError):
                    P.promote(args, github)
                self.assertFalse(github.writes)

    def test_failed_local_signed_acceptance_gate_cannot_reach_a_remote_api(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, _ = self.fixture(Path(scratch))
            github = FakeGitHub()
            with patch.object(P, "local_plan", side_effect=ValueError("pending installed-product acceptance")), self.assertRaises(ValueError):
                P.promote(args, github)
            self.assertFalse(github.calls)

    def test_cross_host_asset_redirect_removes_authorization_and_rejects_other_hosts(self):
        policy = P.RedirectPolicy()
        request = urllib.request.Request("https://api.github.com/repos/example/repo/releases/assets/1", headers={"Authorization": "Bearer fixture-only"})
        redirect = policy.redirect_request(request, None, 302, "Found", {}, "https://release-assets.githubusercontent.com/asset?token=fixture")
        self.assertFalse(redirect.has_header("Authorization"))
        for url in ("https://attacker.example/asset", "http://release-assets.githubusercontent.com/asset", "https://user:password@objects.githubusercontent.com/asset"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                policy.redirect_request(request, None, 302, "Found", {}, url)


class PublicationCompletionTests(unittest.TestCase):
    def local_fixture(self, root):
        handoff_spec = importlib.util.spec_from_file_location("completion_handoff", ROOT / "scripts/refactor-release-handoff.py")
        handoff_module = importlib.util.module_from_spec(handoff_spec)
        handoff_spec.loader.exec_module(handoff_module)
        artifacts, accepted = [], []
        for index, role in enumerate(sorted(handoff_module.CURRENT_ROLES | handoff_module.PRESERVATION_ROLES)):
            path = root / ("file-" + str(index) + ".bin")
            path.write_bytes(role.encode())
            record = PRODUCER.file_record(root, path, role)
            accepted.append(record)
            if role in handoff_module.CURRENT_ROLES - {"acceptance"}:
                artifacts.append(record)
        PRODUCER.create_json(root / "cohort.json", {"kind": "nestlink-fixed-release", "version": "15.0.0", "repository_node_id": P.REPOSITORY_ID, "source_revision": REVISION, "artifacts": artifacts})
        PRODUCER.create_json(root / "handoff.json", {"artifacts": accepted, "legacy_assets": []})
        for name in ("cohort.p7s", "handoff.p7s", "update.crt"):
            (root / name).write_bytes(b"public-fixture-only")
        args = argparse.Namespace(bundle=root, cohort=root / "cohort.json", cohort_signature=root / "cohort.p7s", handoff=root / "handoff.json", handoff_signature=root / "handoff.p7s", certificate=root / "update.crt", certificate_sha256="a" * 64, openssl="not-invoked")
        producer = SimpleNamespace(FINAL_ROLES=PRODUCER.FINAL_ROLES, json_read=PRODUCER.json_read, verify_record=PRODUCER.verify_record, regular=PRODUCER.regular, digest=PRODUCER.digest, configuration=lambda path: {"update_certificate_sha256": "a" * 64})
        handoff = SimpleNamespace(CURRENT_ROLES=handoff_module.CURRENT_ROLES, PRESERVATION_ROLES=handoff_module.PRESERVATION_ROLES, prepare=Mock(return_value={"source_revision": REVISION, "handoff_sha256": PRODUCER.digest(args.handoff), "uploads": []}))
        verifier = SimpleNamespace(verify_cms=Mock())
        def modules(name, relative):
            return producer if relative.endswith("producer.py") else handoff if relative.endswith("handoff.py") else verifier
        return args, modules, handoff, verifier

    def test_cohort_changed_between_parse_and_signature_cannot_be_accepted(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, modules, handoff, verifier = self.local_fixture(Path(scratch))
            def change_after_parse(*unused, **keywords):
                data = json.loads(args.cohort.read_text())
                data["source_revision"] = "2" * 40
                args.cohort.write_text(json.dumps(data))
            verifier.verify_cms.side_effect = change_after_parse
            with patch.object(P, "module", side_effect=modules), self.assertRaises(ValueError):
                P.local_plan(args)

    def test_statement_inputs_cannot_change_after_handoff_signature_check(self):
        for field in ("handoff", "cohort_signature", "handoff_signature", "certificate"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as scratch:
                args, modules, handoff, verifier = self.local_fixture(Path(scratch))
                verified_upload = handoff.prepare.return_value
                def change_after_handoff(*unused, **keywords):
                    source = getattr(args, field)
                    if field == "handoff":
                        data = json.loads(source.read_text())
                        data["legacy_assets"].append({"component": "unreviewed"})
                        source.write_text(json.dumps(data))
                    else:
                        source.write_bytes(b"changed-after-signature-check")
                    return verified_upload
                handoff.prepare.side_effect = change_after_handoff
                with patch.object(P, "module", side_effect=modules), self.assertRaises(ValueError):
                    P.local_plan(args)

    def test_deleted_tag_during_upload_keeps_the_release_draft(self):
        class DeletedTagGitHub(FakeGitHub):
            def request(self, method, path, **kwargs):
                value = super().request(method, path, **kwargs)
                if method == "POST" and kwargs.get("stream") is not None:
                    self.tag = False
                return value
        with tempfile.TemporaryDirectory() as scratch:
            args, local = PublishTests().fixture(Path(scratch))
            github = DeletedTagGitHub()
            with patch.object(P, "local_plan", return_value=local), self.assertRaises(ValueError):
                P.promote(args, github)
            self.assertTrue(github.release["draft"])
            self.assertFalse(any(method == "PATCH" for method, _ in github.calls))

    def test_promotion_receipt_keeps_the_reviewed_handoff_digest(self):
        with tempfile.TemporaryDirectory() as scratch:
            args, local = PublishTests().fixture(Path(scratch))
            local[3]["handoff_sha256"] = PRODUCER.digest(args.handoff)
            expected = local[3]["handoff_sha256"]
            class ChangedLocalHandoffGitHub(FakeGitHub):
                def request(self, method, path, **kwargs):
                    value = super().request(method, path, **kwargs)
                    if method == "POST" and kwargs.get("stream") is not None:
                        args.handoff.write_bytes(b"changed after remote input review")
                    return value
            with patch.object(P, "local_plan", return_value=local):
                result = P.promote(args, ChangedLocalHandoffGitHub())
            self.assertEqual(result["handoff_sha256"], expected)

    def test_tag_disappearing_after_final_asset_list_cannot_be_published(self):
        class DeletedTagAfterAssetListGitHub(FakeGitHub):
            def pages(self, path):
                value = super().pages(path)
                if path.endswith("/releases/15/assets") and self.assets:
                    self.tag = False
                return value
        with tempfile.TemporaryDirectory() as scratch:
            args, local = PublishTests().fixture(Path(scratch))
            github = DeletedTagAfterAssetListGitHub()
            with patch.object(P, "local_plan", return_value=local), self.assertRaises(ValueError):
                P.promote(args, github)
            self.assertTrue(github.release["draft"])
            self.assertFalse(any(method == "PATCH" for method, _ in github.calls))

    def test_tag_disappearing_at_publication_cannot_produce_success_receipt(self):
        class DeletedTagAtPublishGitHub(FakeGitHub):
            def request(self, method, path, **kwargs):
                value = super().request(method, path, **kwargs)
                if method == "PATCH":
                    self.tag = False
                return value
        with tempfile.TemporaryDirectory() as scratch:
            args, local = PublishTests().fixture(Path(scratch))
            github = DeletedTagAtPublishGitHub()
            with patch.object(P, "local_plan", return_value=local), self.assertRaises(ValueError):
                P.promote(args, github)
            self.assertFalse(github.release["draft"])



if __name__ == "__main__":
    unittest.main()
