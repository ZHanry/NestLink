"""The GitHub integration must fail closed and keep ephemeral secrets private."""
import importlib.util
import json
import copy
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("browser_native_runner", ROOT / "scripts/refactor-browser-native-run.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def completed_workspace_ui():
    def geometry(viewport, keys):
        return {"viewport": viewport, "document_width": viewport["width"], "items": {
            key: {"count": 1, "visible": True, "hit": True,
                  "rect": {"x": 1, "y": 2, "width": 30, "height": 40}} for key in keys}}

    session = ("stop", "close", "request", "canvas")
    ui = {"passed": True, "navigation": [], "active_layouts": [],
          "steady_layout_samples": [geometry(RUNNER.UI_VIEWPORTS[0], session) for _ in range(3)],
          "permissions": {"toggled_through_ui": True, "requested_values_preserved": True,
              "before": [{"tag": tag} for tag in ["INPUT"] * 6 + ["SELECT"] * 2],
              "initial_frame": geometry(RUNNER.UI_VIEWPORTS[0], session),
              "reopened_frame": geometry(RUNNER.UI_VIEWPORTS[0], session)},
          "request_hid_options_without_moving_actions": True,
          "trusted_clicks": [{"selector": selector, "trusted": True} for selector in RUNNER.UI_REQUIRED_CLICKS],
          "close_clicked_after_cleanup": True, "screenshots": ["workspace", "tunnel-editor", "remote-narrow"]}
    for viewport in RUNNER.UI_VIEWPORTS:
        ui["navigation"].append({"viewport": viewport, "desktop": geometry(viewport, ("connect",)),
            "tunnels": geometry(viewport, ("create",)), "editor": geometry(viewport, ("save", "close")),
            "after_scroll": geometry(viewport, ("save", "close")), "native_body_scroll_observed": True,
            "draft_preserved": True if viewport["width"] == 390 else None})
        ui["active_layouts"].append({"viewport": viewport, **{
            field: geometry(viewport, session) for field in ("baseline", "drawer", "options", "restored")}})
    return ui


def completed_receipts():
    browser = {key: True for key in (
        "passed", "browser_peers_closed", "browser_closed", "cleanup_requested",
        "persistent_controller_preserved", "ui_cleanup_complete", "renewal_sequence_valid")}
    browser.update({"page_errors": [], "api_failures": [], "response_inspection_errors": [],
        "workspace_ui": completed_workspace_ui(),
        "edge_namespace_ui": {field: True for field in (
            "passed", "forbidden_is_error", "explicit_revision_zero", "create_saved",
            "failed_initialization_preserves_draft", "same_node_draft_preserved",
            "read_saved_configuration", "cas_conflict_preserves_draft", "conflict_recovered",
            "slow_old_response_ignored", "node_switch_clears_draft")},
        "edge_namespace_ui_helper_sha256": RUNNER.sha256(
            (ROOT / "scripts/lib/refactor-browser-edge-namespace.cjs").read_bytes()),
        "network_membership_ui": {field: True for field in RUNNER.MEMBERSHIP_UI_FIELDS},
        "network_authority_ui": {field: True for field in RUNNER.AUTHORITY_UI_FIELDS},
        "network_membership_ui_helper_sha256": RUNNER.sha256(
            (ROOT / "scripts/lib/refactor-browser-network-membership.cjs").read_bytes()),
        "relay_attributes_ui": {field: True for field in RUNNER.RELAY_ATTRIBUTES_UI_FIELDS},
        "relay_attributes_ui_helper_sha256": RUNNER.sha256(
            (ROOT / "scripts/lib/refactor-browser-relay-attributes.cjs").read_bytes()),
        "spaces_ui": {field: True for field in RUNNER.SPACES_UI_FIELDS},
        "spaces_ui_helper_sha256": RUNNER.sha256(
            (ROOT / "scripts/lib/refactor-browser-spaces.cjs").read_bytes()),
        "permit_response_observer": {"passed": True, "closed": True, "listeners_removed": True,
            "pending": 0, "errors": [], "session_owner": {
                **{key: True for key in ("session_created", "prepared_before_navigation",
                    "network_disabled", "session_detached", "closed", "passed")}, "cleanup_errors": []}},
        "error": None, "pending_response_observations_after_close": 0,
        "capture_profile": {"name": "smoke", "width": 320, "height": 180, "fps": 10,
                            "duration_seconds": 36, "with_audio": True},
        "decoded_elapsed_seconds": 36.01,
        "intervals": [{"decoded_fps": 9.9, "received_bytes": 150000}] * 3,
        "audio_intervals": [{"sample_rate": 48000, "packets_per_second": 50}] * 3,
        "renewals": [{"lease_sequence": number} for number in range(2, 7)],
        "steady_renewals": [{"lease_sequence": number} for number in range(3, 7)]})
    browser["owned_data"] = {key: True for key in (
        "passed", "focus_loss_release_observed", "panel_close_revoked_approvals",
        "private_stage_removed", "upload_acknowledged_by_actual_ui",
        "terminal_key_held_before_disconnect", "terminal_key_released",
        "browser_storage_lock_released", "owned_saved_file_removed")}
    host = {key: True for key in ("connected", "capture_prepared", "capture_reset",
                                  "audio_enabled", "audio_reset", "audio_cleanup_succeeded")}
    host.update({"cleanup_failed": False, "capture_starts": 1, "capture_frames": 470, "audio_chunks": 1200})
    data = {key: True for key in ("passed", "input_device_dropped", "input_exercised",
                                  "files_exact", "owned_sandbox_removed")}
    data.update({"held_buttons": 0, "input_resets": 2, "user_desktop_or_files_accessed": False,
                 "workers": {"read_finished": True, "write_finished": True,
                    "transfers_physically_clean": True, "owner_dropped": True,
                    "read_error": None, "write_error": None, "write_cleanup_error": None,
                    "read_cleanup_timed_out": False, "write_cleanup_timed_out": False}})
    database = {"servers_joined": True, "verified_owned_tempdir": True,
                "owned_temporary_database_removed": True, "cleanup_error": None}
    return [browser, host, data, database, {"browser": 0, "native": 0}]


class NativeRunnerTests(unittest.TestCase):
    def test_relay_attributes_require_actual_cases_cleanup_and_exact_helper(self):
        for replacement in (None, {}, {"passed": True}):
            receipts = completed_receipts()
            receipts[0]["relay_attributes_ui"] = replacement
            self.assertTrue(any(item.startswith("relay-attributes-") for item in RUNNER.validate_receipts(*receipts)))
        for field in RUNNER.RELAY_ATTRIBUTES_UI_FIELDS:
            receipts = completed_receipts()
            receipts[0]["relay_attributes_ui"][field] = False
            self.assertIn("relay-attributes-" + field, RUNNER.validate_receipts(*receipts))
        receipts = completed_receipts()
        receipts[0]["relay_attributes_ui_helper_sha256"] = "0" * 64
        self.assertIn("relay-attributes-helper-source", RUNNER.validate_receipts(*receipts))

    def test_spaces_require_all_actual_ui_cases_and_exact_helper_source(self):
        for replacement in (None, {}, {"passed": True}):
            receipts = completed_receipts()
            receipts[0]["spaces_ui"] = replacement
            self.assertTrue(any(item.startswith("spaces-") for item in RUNNER.validate_receipts(*receipts)))
        for field in RUNNER.SPACES_UI_FIELDS:
            receipts = completed_receipts()
            receipts[0]["spaces_ui"][field] = False
            self.assertIn("spaces-" + field, RUNNER.validate_receipts(*receipts))
        receipts = completed_receipts()
        receipts[0]["spaces_ui_helper_sha256"] = "0" * 64
        self.assertIn("spaces-helper-source", RUNNER.validate_receipts(*receipts))

    def test_membership_requires_every_real_browser_case_and_helper_source(self):
        for replacement in (None, {}, {"passed": True}):
            receipts = completed_receipts()
            receipts[0]["network_membership_ui"] = replacement
            self.assertTrue(any(item.startswith("network-membership-") for item in RUNNER.validate_receipts(*receipts)))
        for field in RUNNER.MEMBERSHIP_UI_FIELDS:
            receipts = completed_receipts()
            receipts[0]["network_membership_ui"][field] = False
            self.assertIn("network-membership-" + field, RUNNER.validate_receipts(*receipts))
        receipts = completed_receipts()
        receipts[0]["network_membership_ui_helper_sha256"] = "0" * 64
        self.assertIn("network-membership-helper-source", RUNNER.validate_receipts(*receipts))

    def test_authority_lifecycle_cannot_be_skipped_or_report_partial_success(self):
        for replacement in (None, {}, {"passed": True}):
            receipts = completed_receipts()
            receipts[0]["network_authority_ui"] = replacement
            self.assertTrue(any(item.startswith("network-authority-") for item in RUNNER.validate_receipts(*receipts)))
        for field in RUNNER.AUTHORITY_UI_FIELDS:
            receipts = completed_receipts()
            receipts[0]["network_authority_ui"][field] = False
            self.assertIn("network-authority-" + field, RUNNER.validate_receipts(*receipts))

    def test_namespace_evidence_and_source_cannot_be_skipped(self):
        for replacement in (None, {}, {"passed": True}):
            receipts = completed_receipts()
            receipts[0]["edge_namespace_ui"] = replacement
            self.assertTrue(any(item.startswith("edge-namespace-") for item in RUNNER.validate_receipts(*receipts)))
        for field in completed_receipts()[0]["edge_namespace_ui"]:
            receipts = completed_receipts()
            receipts[0]["edge_namespace_ui"][field] = False
            self.assertIn("edge-namespace-" + field, RUNNER.validate_receipts(*receipts))
        receipts = completed_receipts()
        receipts[0]["edge_namespace_ui_helper_sha256"] = "0" * 64
        self.assertIn("edge-namespace-helper-source", RUNNER.validate_receipts(*receipts))

    def test_response_observer_and_actual_session_cleanup_cannot_be_skipped(self):
        for replacement in (None, {}, {"passed": True}):
            receipts = completed_receipts()
            receipts[0]["permit_response_observer"] = replacement
            self.assertIn("permit-response-observer", RUNNER.validate_receipts(*receipts))
        for field in ("session_created", "prepared_before_navigation", "network_disabled", "session_detached", "closed", "passed"):
            receipts = completed_receipts()
            receipts[0]["permit_response_observer"]["session_owner"][field] = False
            self.assertIn("permit-response-session-owner", RUNNER.validate_receipts(*receipts))
        receipts = completed_receipts()
        receipts[0]["permit_response_observer"]["pending"] = 1
        self.assertIn("permit-response-observer", RUNNER.validate_receipts(*receipts))

    def test_workspace_helper_cannot_be_skipped_or_report_partial_coverage(self):
        receipts = completed_receipts()
        receipts[0].pop("workspace_ui")
        self.assertIn("workspace-ui-missing", RUNNER.validate_receipts(*receipts))
        valid = completed_workspace_ui()
        self.assertEqual(RUNNER.validate_workspace_ui(valid), [])
        for field in valid:
            partial = copy.deepcopy(valid)
            partial.pop(field)
            with self.subTest(missing=field):
                self.assertTrue(RUNNER.validate_workspace_ui(partial))
        for field in ("navigation", "active_layouts"):
            partial = copy.deepcopy(valid)
            partial[field].pop()
            self.assertTrue(RUNNER.validate_workspace_ui(partial))
        partial = copy.deepcopy(valid)
        partial["navigation"][-1]["draft_preserved"] = False
        self.assertIn("workspace-ui-narrow-draft-preserved", RUNNER.validate_workspace_ui(partial))
        partial = copy.deepcopy(valid)
        partial["active_layouts"][2].pop("drawer")
        self.assertIn("workspace-ui-active-2-drawer", RUNNER.validate_workspace_ui(partial))
        partial = copy.deepcopy(valid)
        partial["trusted_clicks"][0]["trusted"] = False
        self.assertIn("workspace-ui-trusted-action-coverage", RUNNER.validate_workspace_ui(partial))

    def test_browser_success_requires_every_native_cleanup_receipt(self):
        self.assertEqual(RUNNER.validate_receipts(*completed_receipts()), [])
        for index in (1, 2, 3, 4):
            receipts = completed_receipts()
            receipts[index] = {}
            with self.subTest(missing=index):
                self.assertTrue(RUNNER.validate_receipts(*receipts))

    def test_owner_release_and_exact_files_cannot_be_replaced_by_pass_flags(self):
        mutations = [(1, "cleanup_failed", True), (1, "capture_frames", 0),
                     (2, "held_buttons", 1), (2, "input_device_dropped", False),
                     (2, "files_exact", False), (2, "owned_sandbox_removed", False),
                     (3, "owned_temporary_database_removed", False), (4, "native", 1)]
        for index, field, value in mutations:
            receipts = completed_receipts()
            receipts[index][field] = value
            with self.subTest(field=field):
                self.assertTrue(RUNNER.validate_receipts(*receipts))
        receipts = completed_receipts()
        receipts[2]["workers"]["write_cleanup_timed_out"] = True
        self.assertIn("workers-write_cleanup_timed_out", RUNNER.validate_receipts(*receipts))

    def test_short_video_silent_audio_and_missing_renewals_fail(self):
        mutations = {"decoded_elapsed_seconds": 35.99, "audio_intervals": [], "steady_renewals": [],
                     "intervals": [{"decoded_fps": 8.9, "received_bytes": 10}] * 3,
                     "renewals": [{"lease_sequence": 2}, {"lease_sequence": 4}],
                     "page_errors": ["unexpected failure"]}
        for field, value in mutations.items():
            receipts = completed_receipts()
            receipts[0][field] = value
            with self.subTest(field=field):
                self.assertTrue(RUNNER.validate_receipts(*receipts))

    def test_private_cleanup_cannot_remove_parent_or_neighbor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            neighbor = root / "unrelated"
            neighbor.mkdir()
            (neighbor / "keep.txt").write_text("keep", encoding="utf-8")
            for rejected in (root, neighbor):
                with self.assertRaises(ValueError):
                    RUNNER.remove_private(rejected, root)
            owned = root / (RUNNER.PRIVATE_PREFIX + "owned")
            owned.mkdir()
            (owned / "private-key.pem").write_text("private", encoding="utf-8")
            self.assertTrue(RUNNER.remove_private(owned, root))
            self.assertEqual((neighbor / "keep.txt").read_text(encoding="utf-8"), "keep")

    def test_private_cleanup_rejects_root_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / (RUNNER.PRIVATE_PREFIX + "target")
            target.mkdir()
            link = root / (RUNNER.PRIVATE_PREFIX + "link")
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest("Creating directory symlinks is unavailable for this test token")
            with self.assertRaises(ValueError):
                RUNNER.remove_private(link, root)
            self.assertTrue(target.is_dir())

    def test_publish_allowlist_excludes_ready_profile_logs_and_private_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private, output = root / "private", root / "public"
            (private / "native").mkdir(parents=True)
            (private / "probe").mkdir()
            output.mkdir()
            secret = "random-fixture-password-73"
            for name in ("ready.json", "fixture.sqlite3", "leaf-key.pem", "native.log"):
                (private / "native" / name).write_text(secret, encoding="utf-8")
            RUNNER.write_json(private / "probe/browser-report.json", {
                "passed": False, "error": "Rejected " + secret, "nested": {"access_token": "hidden"}})
            RUNNER.write_json(private / "native/database-cleanup.json", {"owned_temporary_database_removed": True})
            RUNNER.publish_receipts(private, output, [secret])
            self.assertEqual({path.name for path in output.iterdir()}, {"browser-report.json", "database-cleanup.json"})
            published = (output / "browser-report.json").read_text(encoding="utf-8")
            self.assertNotIn(secret, published)
            self.assertNotIn("hidden", published)
            self.assertIn("[redacted]", published)

    def test_bearer_and_signed_tokens_are_redacted_in_error_text(self):
        message = RUNNER.sanitize("Authorization: Bearer abc123 and eyJhbGciOiJFZCJ9.eyJzdWIiOiJ4In0.signature")
        self.assertNotIn("abc123", message)
        self.assertNotIn("eyJ", message)

    def test_only_reviewed_ui_screenshot_names_are_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private, output = root / "private", root / "public"
            (private / "probe").mkdir(parents=True)
            output.mkdir()
            allowed = {"browser-report-workspace.png", "browser-report-tunnel-editor.png",
                       "browser-report-remote-narrow.png"}
            for name in allowed | {"browser-report-unreviewed.png"}:
                (private / "probe" / name).write_bytes(b"\x89PNG\r\n\x1a\nowned fixture")
            RUNNER.publish_receipts(private, output, [])
            self.assertEqual({path.name for path in output.iterdir()}, allowed)

    def test_negotiation_log_only_retains_fixed_categories_and_public_states(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / "native.log", root / "negotiation-events.jsonl"
            records = [
                {"event": "peer_state", "elapsed_since_first_event_ms": 0,
                 "detail": "ICE connection state changed: checking", "password": "never-publish"},
                {"event": "ice_start_failed", "elapsed_since_first_event_ms": 7,
                 "detail": "failed for password never-publish"},
                {"event": "peer_state", "elapsed_since_first_event_ms": 8,
                 "detail": "peer connection state changed: connected; secret=never-publish"},
                {"event": "unknown", "elapsed_since_first_event_ms": 9, "detail": "never-publish"},
                {"event": "dtls_flight", "elapsed_since_first_event_ms": -1, "detail": "never-publish"},
                {"event": "dtls_flight", "elapsed_since_first_event_ms": True, "detail": "never-publish"},
                {"event": ["malformed"], "elapsed_since_first_event_ms": 9},
            ]
            source.write_text("raw failure never-publish\n" + "\n".join(json.dumps(item) for item in records), encoding="utf-8")
            RUNNER.publish_negotiation_events(source, output)
            result = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(result), 3)
            self.assertEqual(result[0]["detail"], "ICE connection state changed: checking")
            self.assertNotIn("detail", result[1])
            self.assertNotIn("detail", result[2])
            self.assertNotIn("never-publish", output.read_text(encoding="utf-8"))

    def test_negotiation_events_are_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / "native.log", root / "negotiation-events.jsonl"
            source.write_text("\n".join(json.dumps({"event": "dtls_flight", "elapsed_since_first_event_ms": index})
                                        for index in range(250)), encoding="utf-8")
            RUNNER.publish_negotiation_events(source, output)
            self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 200)

    def test_proxy_only_accepts_explicit_loopback_origins(self):
        self.assertEqual(RUNNER.loopback_port("https://127.0.0.1:49321", "https"), 49321)
        for origin in ("http://127.0.0.1:49321", "https://localhost:49321", "https://example.com:443",
                       "https://user:pass@127.0.0.1:49321", "https://127.0.0.1:49321/path",
                       "https://127.0.0.1:49321?upstream=remote", "https://127.0.0.1"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                RUNNER.loopback_port(origin, "https")
        config = RUNNER.proxy_config(Path("/owned"), "https://127.0.0.1:49321", "http://127.0.0.1:49322")
        self.assertTrue(config["admin"]["disabled"])
        self.assertEqual(config["apps"]["http"]["servers"]["fixture"]["listen"], ["127.0.0.1:49321"])


if __name__ == "__main__":
    unittest.main()
