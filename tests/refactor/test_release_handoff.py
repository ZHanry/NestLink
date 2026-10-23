"""Pure handoff custody tests; no real signing, builds, uploads or repository edits."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
# During isolated review, reuse the exact frozen verifier dependency. Integrated
# source uses its normal packaging/native module; no fallback enters production.
if not (ROOT / "packaging/native/release_verify.py").is_file():
    dependency = ROOT.parent.parent / "native-packaging-lifecycle-draft-20261015/mirror/packaging/native"
    if dependency.is_dir():
        sys.path.insert(0, str(dependency))
spec = importlib.util.spec_from_file_location("nestlink_release_handoff", ROOT / "scripts/refactor-release-handoff.py")
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)


def fixture():
    artifacts = [{"id": role, "role": role, "path": "fixed/" + role + ".bin", "bytes": 1, "sha256": "a" * 64, "source_revision": "b" * 40 if role in handoff.CURRENT_ROLES else None} for role in sorted(handoff.CURRENT_ROLES | handoff.PRESERVATION_ROLES)]
    return {"schema_version": 1, "product": "NestLink-v15", "purpose": "release-handoff", "version": "15.0.0", "source_revision": "b" * 40, "repository_node_id": handoff.REPOSITORY_ID, "update_certificate_sha256": "c" * 64, "completion": {key: "passed" for key in ("implementation", "installed_product_acceptance", "release_bytes_frozen", "legacy_preservation_review")}, "artifacts": artifacts, "acceptance_cases": [{"id": case, "status": "passed", "evidence_artifact_id": "acceptance"} for case in sorted(handoff.REQUIRED_CASES)], "legacy_assets": []}


class HandoffTests(unittest.TestCase):
    def test_template_is_blocked_without_invented_release_identity(self):
        plan = json.loads((ROOT / "config/release-handoff.template.json").read_text(encoding="utf-8"))
        with self.assertRaises(handoff.Blocked): handoff.validate(plan)

    def test_one_source_and_complete_platform_cohort_are_mandatory(self):
        plan = fixture(); handoff.validate(plan)
        plan["artifacts"][0]["source_revision"] = "d" * 40
        with self.assertRaises(ValueError): handoff.validate(plan)
        plan = fixture(); plan["artifacts"].pop()
        with self.assertRaises(ValueError): handoff.validate(plan)
        plan = fixture(); plan["artifacts"][-1]["path"] = plan["artifacts"][0]["path"].upper()
        with self.assertRaises(ValueError): handoff.validate(plan)

    def test_pending_runtime_or_claimed_completion_cannot_be_promoted(self):
        for key in fixture()["completion"]:
            plan = fixture(); plan["completion"][key] = "pending"
            with self.assertRaises(handoff.Blocked): handoff.validate(plan)
        plan = fixture(); plan["acceptance_cases"][0]["status"] = "pending"
        with self.assertRaises(handoff.Blocked): handoff.validate(plan)
        self.assertNotIn("android-api-29", handoff.REQUIRED_CASES)
        self.assertFalse(any(case.startswith("android-") for case in handoff.REQUIRED_CASES))
        self.assertTrue({"linux-x64-server-installed", "linux-arm64-server-installed"} <= handoff.REQUIRED_CASES)

    def test_custody_rejects_modified_bytes_and_duplicate_json(self):
        with tempfile.TemporaryDirectory(prefix="nestlink-handoff-custody-") as temporary:
            root = Path(temporary); path = root / "artifact"; path.write_bytes(b"x")
            item = {"path": "artifact", "bytes": 1, "sha256": handoff.verify.sha256(path)}
            self.assertEqual(handoff.fixed_file(root, item), path)
            path.write_bytes(b"y")
            with self.assertRaises(ValueError): handoff.fixed_file(root, item)
            path.write_text('{"id":1,"id":2}', encoding="utf-8")
            with self.assertRaises(ValueError): handoff.bounded_json(path)

    def test_independent_pin_and_unchanged_statement_are_required_before_output(self):
        with tempfile.TemporaryDirectory(prefix="nestlink-handoff-statement-") as temporary:
            root = Path(temporary); plan = fixture(); file = root / "handoff.json"
            file.write_text(json.dumps(plan), encoding="utf-8")
            args = SimpleNamespace(plan=file, bundle=root, signature=root / "not-a-signature", certificate=root / "not-a-certificate", certificate_sha256="d" * 64, openssl="not-invoked", expected_source="b" * 40, output=root / "upload-plan.json")
            with mock.patch.object(handoff.verify, "verify_cms") as cms:
                with self.assertRaises(ValueError): handoff.prepare(args)
                cms.assert_not_called()
            args.certificate_sha256 = "c" * 64
            def mutate(*unused, **keywords):
                plan["source_revision"] = "d" * 40
                file.write_text(json.dumps(plan), encoding="utf-8")
            with mock.patch.object(handoff.verify, "verify_cms", side_effect=mutate):
                with self.assertRaises(ValueError): handoff.prepare(args)
            self.assertFalse(args.output.exists())

    def test_every_legacy_asset_must_be_preserved_against_original_repository_identity(self):
        plan = fixture()
        inventory = {"components": {component: {"repository": identity[0], "repository_node_id": identity[1], "asset_count": 0, "assets": []} for component, identity in handoff.REPOSITORIES.items()}}
        inventory["components"]["client"].update(asset_count=1, assets=[{"release_id": 11, "asset_id": 22, "bytes": 3, "github_sha256": "e" * 64, "state": "uploaded"}])
        source_bundle = next(item for item in plan["artifacts"] if item["role"] == "legacy-source-bundle")
        report = {"bundle_standalone_verified": True, "restored_ref_map_verified": True, "strict_fsck_passed": True, "bundle": {key: source_bundle[key] for key in ("bytes", "sha256")}, "unavailable_gitlinks": ["f" * 40]}
        with mock.patch.object(handoff, "fixed_file", side_effect=lambda bundle, item: Path(item["role"])), mock.patch.object(handoff, "bounded_json", side_effect=[inventory, report]), mock.patch.object(handoff.verify, "sha256", return_value="a" * 64):
            with self.assertRaises(handoff.Blocked): handoff.verify_preservation(plan, Path("bundle"))
        plan["legacy_assets"] = [{"component": "client", "release_id": 11, "asset_id": 22, "path": "legacy/fixed.blob", "bytes": 3, "sha256": "e" * 64}]
        with mock.patch.object(handoff, "fixed_file", side_effect=lambda bundle, item: Path(item["role"])), mock.patch.object(handoff, "bounded_json", side_effect=[inventory, report]), mock.patch.object(handoff.verify, "sha256", return_value="a" * 64):
            self.assertEqual(handoff.verify_preservation(plan, Path("bundle")), ["f" * 40])
        inventory["components"]["client"]["repository_node_id"] = "wrong"
        with mock.patch.object(handoff, "fixed_file", return_value=Path("inventory")), mock.patch.object(handoff, "bounded_json", return_value=inventory), mock.patch.object(handoff.verify, "sha256", return_value="a" * 64):
            with self.assertRaises(ValueError): handoff.verify_preservation(plan, Path("bundle"))


if __name__ == "__main__":
    unittest.main()
