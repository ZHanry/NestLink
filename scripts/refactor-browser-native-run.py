"""Run the production Web/native integration on an ephemeral GitHub Linux runner.

No compilation happens here. CI supplies the same-run release site and optimized
native fixture. Private readiness, TLS, browser and database files never enter
the upload directory; successful browser and native cleanup are both required.
"""
import argparse
import base64
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
CADDY_SHA256 = "678ade3bfc088749c81a681adc603333ee0bb023b6a6cfe3c0f58bef8ff854e9"
PUPPETEER_VERSION = "25.14.0"
PRIVATE_PREFIX = "nestlink-browser-e2e-"
JSON_RECEIPTS = (
    "host-start-gate.json", "connected.json", "host-result.json",
    "data-result.json", "database-cleanup.json",
)
JSONL_RECEIPTS = ("management-stages.jsonl", "input-records.jsonl")
PNG_RECEIPTS = (
    "browser-report-video.png", "browser-report-failure.png",
    "browser-report-workspace.png", "browser-report-tunnel-editor.png", "browser-report-remote-narrow.png",
)
NEGOTIATION_EVENTS = frozenset((
    "ice_remote_response_unmatched", "ice_remote_packet_unmatched", "dtls_flight",
    "peer_state", "ice_start_failed", "dtls_start_failed",
))
PUBLIC_PEER_STATE = re.compile(
    r"(?:ICE connection state changed: (?:new|checking|connected|completed|failed|disconnected|closed)"
    r"|peer connection state changed: (?:new|connecting|connected|disconnected|failed|closed)"
    r"|signaling state changed to (?:stable|have-local-offer|have-remote-offer|have-local-pranswer|have-remote-pranswer|closed))",
    re.I,
)
UI_VIEWPORTS = [{"width": width, "height": height} for width, height in (
    (1440, 1000), (900, 800), (760, 560), (390, 844))]
UI_REQUIRED_CLICKS = frozenset((
    ".sidebar nav button", ".tunnel-heading > button.primary",
    ".service-editor .dialog-actions button.secondary", ".task-dialog[open] > button",
    '[aria-controls="remote-permissions"]', '[aria-controls="remote-operation-center"]',
    ".remote-actions > button:last-child", ".back-to-devices",
))
MEMBERSHIP_UI_FIELDS = (
    "passed", "forbidden_is_error", "explicit_initialization", "explicit_epoch_zero",
    "failed_read_preserves_draft", "cas_conflict_preserves_draft", "reread_preserves_draft",
    "revision_epoch_bound", "revoke_and_reenroll", "unmounted_response_ignored",
    "logout_response_ignored", "new_session_clean",
)
AUTHORITY_UI_FIELDS = (
    "passed", "revision_epoch_bound", "rotation_advances_and_changes_key",
    "stale_conflict_requires_reread", "policy_epoch_advances_without_key_change",
    "permanent_revocation_readback", "terminal_controls_disabled",
)
RELAY_ATTRIBUTES_UI_FIELDS = (
    "passed", "default_unknown_revision_zero", "explicit_zero_saved",
    "revision_bound", "stale_conflict_requires_reread", "unknown_clear_persisted",
    "unmounted_response_ignored", "logout_response_ignored", "new_session_clean",
    "response_observers_closed",
)
SPACES_UI_FIELDS = (
    "passed", "created_and_device_joined", "guest_isolated_context", "invitation_single_use", "invitation_link_opens_acceptance",
    "owner_admin_member_guest", "stale_revision_rejected", "revocation_and_audit",
    "archive_blocks_changes", "unmount_clears_secret_and_snapshot",
)
SUBNET_UI_FIELDS = (
    "passed", "real_policy_and_role_loaded", "draft_edits_clear_approval",
    "failed_read_clears_writable_snapshot", "failed_read_preserves_unapproved_draft",
    "late_space_reply_ignored", "no_unapproved_mapping_write",
)
SENSITIVE_KEY = re.compile(
    r"(^|_)(password|secret|token|authorization|cookie|private_key|ice_pwd|ice_ufrag)($|_)", re.I
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Expected a bounded regular JSON receipt")
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def sanitize(value, secrets=()):
    if isinstance(value, dict):
        return {key: "[redacted]" if SENSITIVE_KEY.search(key) else sanitize(item, secrets)
                for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item, secrets) for item in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[private]")
        value = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [redacted]", value)
        value = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
                       "[redacted signed token]", value)
    return value


def remove_private(directory, temporary_root):
    """Delete only the generated immediate child, without following a root link."""
    target = directory.resolve(strict=True)
    parent = temporary_root.resolve(strict=True)
    if (directory.is_symlink() or not directory.is_dir() or target.parent != parent
            or not target.name.startswith(PRIVATE_PREFIX) or target == parent):
        raise ValueError("Refusing cleanup outside the generated private directory")
    shutil.rmtree(target)
    return not target.exists()


def publish_negotiation_events(source, output):
    """Retain fixed event categories, never arbitrary native log/error text."""
    if not source.exists():
        return
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 512 * 1024:
        raise ValueError("Expected a bounded regular native negotiation log")
    events = []
    for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            continue
        category = value.get("event")
        if not isinstance(category, str) or category not in NEGOTIATION_EVENTS:
            continue
        elapsed = value.get("elapsed_since_first_event_ms")
        if type(elapsed) is not int or not 0 <= elapsed <= 3_600_000:
            continue
        event = {"event": category, "elapsed_since_first_event_ms": elapsed}
        detail = value.get("detail")
        if event["event"] == "peer_state" and isinstance(detail, str) and PUBLIC_PEER_STATE.fullmatch(detail):
            event["detail"] = detail
        events.append(event)
        if len(events) == 200:
            break
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        for event in events:
            stream.write(json.dumps(event) + "\n")


def publish_receipts(private, output, secrets):
    """An explicit file allowlist keeps ready.json, keys, profiles and DBs private."""
    # Preserve startup/negotiation categories even when a later receipt is
    # absent or incomplete. No raw native.log is ever copied to artifacts.
    publish_negotiation_events(private / "native.log", output / "negotiation-events.jsonl")
    sources = [(private / "probe" / "browser-report.json", "browser-report.json")]
    sources += [(private / "native" / name, name) for name in JSON_RECEIPTS]
    for source, name in sources:
        if source.exists():
            write_json(output / name, sanitize(read_json(source), secrets))
    lines = [(private / "probe" / "browser-report-progress.jsonl", "browser-report-progress.jsonl")]
    lines += [(private / "native" / name, name) for name in JSONL_RECEIPTS]
    for source, name in lines:
        if not source.exists():
            continue
        if source.is_symlink() or not source.is_file() or source.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("Expected a bounded regular JSONL receipt")
        # An interrupted final line cannot turn an earlier failed sample into a pass.
        parsed = [sanitize(json.loads(line), secrets)
                  for line in source.read_text(encoding="utf-8").splitlines() if line]
        with (output / name).open("x", encoding="utf-8", newline="\n") as stream:
            for entry in parsed:
                stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
    for name in PNG_RECEIPTS:
        source = private / "probe" / name
        if source.exists():
            if (source.is_symlink() or not source.is_file()
                    or source.stat().st_size > 16 * 1024 * 1024
                    or not source.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")):
                raise ValueError("Expected a bounded PNG screenshot")
            shutil.copyfile(source, output / name)


def validate_workspace_ui(ui):
    """Require each production UI exercise, not merely an optional helper flag."""
    failures = []

    def require(condition, label):
        if not condition:
            failures.append("workspace-ui-" + label)

    def geometry_complete(snapshot, viewport, keys, hit_keys=None):
        if not isinstance(snapshot, dict) or snapshot.get("viewport") != viewport:
            return False
        if type(snapshot.get("document_width")) not in (int, float):
            return False
        items = snapshot.get("items")
        if not isinstance(items, dict):
            return False
        for key in keys:
            item = items.get(key)
            if not isinstance(item, dict) or item.get("count") != 1 or item.get("visible") is not True:
                return False
            rect = item.get("rect")
            if not isinstance(rect, dict) or not all(type(rect.get(field)) in (int, float)
                    and math.isfinite(rect[field]) for field in ("x", "y", "width", "height")):
                return False
            if key in (keys if hit_keys is None else hit_keys) and item.get("hit") is not True:
                return False
        return True

    if not isinstance(ui, dict):
        return ["workspace-ui-missing"]
    require(ui.get("passed") is True, "passed")
    navigation, active = ui.get("navigation"), ui.get("active_layouts")
    for name, rows in (("navigation", navigation), ("active-layouts", active)):
        require(isinstance(rows, list) and len(rows) == len(UI_VIEWPORTS)
            and all(isinstance(row, dict) and row.get("viewport") == viewport
                    for row, viewport in zip(rows, UI_VIEWPORTS)), name + "-sizes")
    if isinstance(navigation, list):
        for index, row in enumerate(navigation):
            if not isinstance(row, dict) or index >= len(UI_VIEWPORTS):
                continue
            for field, keys in (("desktop", ("connect",)), ("tunnels", ("create",)),
                                ("editor", ("save", "close")), ("after_scroll", ("save", "close"))):
                require(geometry_complete(row.get(field), UI_VIEWPORTS[index], keys), f"navigation-{index}-{field}")
            require(type(row.get("native_body_scroll_observed")) is bool, f"navigation-{index}-scroll-observation")
        require(len(navigation) == 4 and isinstance(navigation[-1], dict)
                and navigation[-1].get("draft_preserved") is True, "narrow-draft-preserved")
    session_keys, session_hits = ("stop", "close", "request", "canvas"), ("stop", "close", "request")
    if isinstance(active, list):
        for index, row in enumerate(active):
            if not isinstance(row, dict) or index >= len(UI_VIEWPORTS):
                continue
            for field in ("baseline", "drawer", "options", "restored"):
                require(geometry_complete(row.get(field), UI_VIEWPORTS[index], session_keys, session_hits),
                        f"active-{index}-{field}")
    steady = ui.get("steady_layout_samples")
    require(isinstance(steady, list) and len(steady) >= 3
            and all(geometry_complete(item, UI_VIEWPORTS[0], session_keys, session_hits) for item in steady),
            "steady-layout-samples")
    permissions = ui.get("permissions", {})
    if not isinstance(permissions, dict):
        permissions = {}
    for field in ("toggled_through_ui", "requested_values_preserved"):
        require(permissions.get(field) is True, "permissions-" + field)
    values = permissions.get("before")
    require(isinstance(values, list) and len(values) == 8
            and all(isinstance(value, dict) and value.get("tag") == tag
                    for value, tag in zip(values, ["INPUT"] * 6 + ["SELECT"] * 2)), "permission-controls")
    for field in ("initial_frame", "reopened_frame"):
        require(geometry_complete(permissions.get(field), UI_VIEWPORTS[0], session_keys, session_hits), "permissions-" + field)
    require(ui.get("request_hid_options_without_moving_actions") is True, "request-fixed-actions")
    clicks = ui.get("trusted_clicks")
    require(isinstance(clicks, list) and bool(clicks)
            and all(isinstance(event, dict) and event.get("trusted") is True for event in clicks)
            and UI_REQUIRED_CLICKS <= {event.get("selector") for event in clicks}, "trusted-action-coverage")
    require(ui.get("close_clicked_after_cleanup") is True, "close-after-cleanup")
    require(ui.get("screenshots") == ["workspace", "tunnel-editor", "remote-narrow"], "screenshots")
    return failures


def validate_receipts(browser, host, data, database, exit_codes, expected_browser_product="chrome"):
    """A browser pass alone never qualifies a native integration as successful."""
    failures = []

    def require(condition, label):
        if not condition:
            failures.append(label)

    require(exit_codes == {"browser": 0, "native": 0}, "process-exit")
    require(expected_browser_product in ("chrome", "edge")
            and browser.get("browser_product") == expected_browser_product
            and browser.get("browser_product_verified") is True, "browser-product")
    failures.extend(validate_workspace_ui(browser.get("workspace_ui")))
    namespace = browser.get("edge_namespace_ui", {})
    for field in ("passed", "forbidden_is_error", "explicit_revision_zero", "create_saved",
                  "failed_initialization_preserves_draft", "same_node_draft_preserved", "read_saved_configuration", "cas_conflict_preserves_draft",
                  "conflict_recovered", "slow_old_response_ignored", "node_switch_clears_draft"):
        require(isinstance(namespace, dict) and namespace.get(field) is True, "edge-namespace-" + field)
    require(browser.get("edge_namespace_ui_helper_sha256") ==
            sha256((ROOT / "scripts/lib/refactor-browser-edge-namespace.cjs").read_bytes()),
            "edge-namespace-helper-source")
    membership = browser.get("network_membership_ui", {})
    for field in MEMBERSHIP_UI_FIELDS:
        require(isinstance(membership, dict) and membership.get(field) is True, "network-membership-" + field)
    authority = browser.get("network_authority_ui", {})
    for field in AUTHORITY_UI_FIELDS:
        require(isinstance(authority, dict) and authority.get(field) is True, "network-authority-" + field)
    require(browser.get("network_membership_ui_helper_sha256") ==
            sha256((ROOT / "scripts/lib/refactor-browser-network-membership.cjs").read_bytes()),
            "network-membership-helper-source")
    relay_attributes = browser.get("relay_attributes_ui", {})
    for field in RELAY_ATTRIBUTES_UI_FIELDS:
        require(isinstance(relay_attributes, dict) and relay_attributes.get(field) is True, "relay-attributes-" + field)
    require(browser.get("relay_attributes_ui_helper_sha256") ==
            sha256((ROOT / "scripts/lib/refactor-browser-relay-attributes.cjs").read_bytes()),
            "relay-attributes-helper-source")
    spaces = browser.get("spaces_ui", {})
    for field in SPACES_UI_FIELDS:
        require(isinstance(spaces, dict) and spaces.get(field) is True, "spaces-" + field)
    require(browser.get("spaces_ui_helper_sha256") ==
            sha256((ROOT / "scripts/lib/refactor-browser-spaces.cjs").read_bytes()), "spaces-helper-source")
    subnet = browser.get("subnet_ui", {})
    for field in SUBNET_UI_FIELDS:
        require(isinstance(subnet, dict) and subnet.get(field) is True, "subnet-" + field)
    require(browser.get("subnet_ui_helper_sha256") ==
            sha256((ROOT / "scripts/lib/refactor-browser-subnet.cjs").read_bytes()), "subnet-helper-source")
    for field in ("passed", "browser_peers_closed", "browser_closed", "cleanup_requested",
                  "persistent_controller_preserved", "ui_cleanup_complete", "renewal_sequence_valid"):
        require(browser.get(field) is True, "browser-" + field)
    for field in ("page_errors", "api_failures", "response_inspection_errors"):
        require(browser.get(field) == [], "browser-" + field)
    require(browser.get("error") is None and not browser.get("cleanup_errors"), "browser-errors")
    require(browser.get("pending_response_observations_after_close") == 0, "response-observers")
    observer = browser.get("permit_response_observer", {})
    require(isinstance(observer, dict) and observer.get("passed") is True
            and observer.get("closed") is True and observer.get("listeners_removed") is True
            and observer.get("pending") == 0 and observer.get("errors") == [], "permit-response-observer")
    owner = observer.get("session_owner", {}) if isinstance(observer, dict) else {}
    require(isinstance(owner, dict) and all(owner.get(key) is True for key in (
        "session_created", "prepared_before_navigation", "network_disabled", "session_detached", "closed", "passed"))
        and owner.get("cleanup_errors") == [], "permit-response-session-owner")
    profile = browser.get("capture_profile", {})
    require(all(profile.get(key) == value for key, value in {
        "name": "smoke", "width": 320, "height": 180, "fps": 10,
        "duration_seconds": 36, "with_audio": True,
    }.items()), "capture-profile")
    require(browser.get("decoded_elapsed_seconds", 0) >= 36, "video-duration")
    intervals = browser.get("intervals", [])
    require(len(intervals) == 3 and all(item.get("decoded_fps", 0) >= 9
            and item.get("received_bytes", 0) > 0 for item in intervals), "actual-video-counters")
    audio = browser.get("audio_intervals", [])
    require(len(audio) == 3 and all(item.get("sample_rate", 0) >= 43200
            and item.get("packets_per_second", 0) >= 45 for item in audio), "actual-opus-counters")
    renewals = browser.get("renewals", [])
    require(len(browser.get("steady_renewals", [])) >= 4, "steady-signed-renewals")
    require(len(renewals) >= 4 and all(item.get("lease_sequence") == index + 2
            for index, item in enumerate(renewals)), "renewal-sequence")
    owned = browser.get("owned_data", {})
    for field in ("passed", "focus_loss_release_observed", "panel_close_revoked_approvals",
                  "private_stage_removed", "upload_acknowledged_by_actual_ui",
                  "terminal_key_held_before_disconnect", "terminal_key_released",
                  "browser_storage_lock_released", "owned_saved_file_removed"):
        require(owned.get(field) is True, "browser-data-" + field)
    for field in ("connected", "capture_prepared", "capture_reset", "audio_enabled",
                  "audio_reset", "audio_cleanup_succeeded"):
        require(host.get(field) is True, "native-" + field)
    require(host.get("cleanup_failed") is False, "native-cleanup")
    require(host.get("capture_starts") == 1 and host.get("capture_frames", 0) > 0
            and host.get("audio_chunks", 0) > 0, "native-media-production")
    for field in ("passed", "input_device_dropped", "input_exercised", "files_exact",
                  "owned_sandbox_removed"):
        require(data.get(field) is True, "native-data-" + field)
    require(data.get("held_buttons") == 0 and data.get("input_resets", 0) > 0, "native-input-release")
    require(data.get("user_desktop_or_files_accessed") is False, "owned-devices-only")
    workers = data.get("workers", {})
    for field in ("read_finished", "write_finished", "transfers_physically_clean", "owner_dropped"):
        require(workers.get(field) is True, "workers-" + field)
    for field in ("read_error", "write_error", "write_cleanup_error"):
        require(field in workers and workers[field] is None, "workers-" + field)
    for field in ("read_cleanup_timed_out", "write_cleanup_timed_out"):
        require(workers.get(field) is False, "workers-" + field)
    for field in ("servers_joined", "verified_owned_tempdir", "owned_temporary_database_removed"):
        require(database.get(field) is True, "database-" + field)
    require("cleanup_error" in database and database["cleanup_error"] is None, "database-error")
    return failures


def command(arguments, *, input_bytes=None):
    result = subprocess.run(arguments, input=input_bytes, capture_output=True, timeout=20, check=False)
    if result.returncode:
        raise RuntimeError("TLS setup or pinned proxy validation failed")
    return result.stdout


def make_tls(private, origin):
    cert, key = private / "leaf.pem", private / "leaf-key.pem"
    command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
             "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
             "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth",
             "-keyout", str(key), "-out", str(cert)])
    key.chmod(0o600)
    leaf = command(["openssl", "x509", "-in", str(cert), "-outform", "DER"])
    public = command(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"])
    spki = command(["openssl", "pkey", "-pubin", "-outform", "DER"], input_bytes=public)
    tls = {"origin": origin, "global_trust_modified": False, "leaf_sha256": sha256(leaf),
           "leaf_spki_sha256_base64": base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii"),
           "profile": str(private / "profile")}
    write_json(private / "tls.json", tls)
    return tls


def loopback_port(origin, scheme):
    parsed = urlsplit(origin)
    if (parsed.scheme != scheme or parsed.hostname != "127.0.0.1" or not parsed.port
            or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("Only an exact ephemeral loopback origin is allowed")
    return parsed.port


def proxy_config(private, origin, backend):
    port, upstream = loopback_port(origin, "https"), loopback_port(backend, "http")
    return {"admin": {"disabled": True}, "apps": {
        "http": {"servers": {"fixture": {
            "listen": [f"127.0.0.1:{port}"], "automatic_https": {"disable": True},
            "tls_connection_policies": [{}], "routes": [{"handle": [{
                "handler": "reverse_proxy", "upstreams": [{"dial": f"127.0.0.1:{upstream}"}],
                "flush_interval": -1,
            }]}],
        }}},
        "tls": {"certificates": {"load_files": [{"certificate": str(private / "leaf.pem"),
                                                   "key": str(private / "leaf-key.pem")}]}}
    }}


def wait_ready(path, process):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Native fixture exited before readiness")
        if path.exists():
            try:
                return read_json(path)
            except json.JSONDecodeError:
                pass  # The fixture writes one bounded file; do not parse a partial write.
        time.sleep(0.1)
    raise RuntimeError("Native fixture readiness exceeded twenty seconds")


def verify_https(private, tls, site, process):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(private / "leaf.pem"))
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Pinned TLS proxy exited before readiness")
        connection = http.client.HTTPSConnection("127.0.0.1", loopback_port(tls["origin"], "https"),
                                                 timeout=2, context=context)
        try:
            connection.connect()
            if sha256(connection.sock.getpeercert(binary_form=True)) != tls["leaf_sha256"]:
                raise RuntimeError("Loopback peer did not present the exact temporary leaf")
            connection.request("GET", "/")
            response = connection.getresponse()
            if response.status != 200 or sha256(response.read()) != sha256((site / "index.html").read_bytes()):
                raise RuntimeError("HTTPS did not serve the same-run production index")
            return
        except (ConnectionRefusedError, TimeoutError):
            time.sleep(0.1)
        finally:
            connection.close()
    raise RuntimeError("HTTPS readiness exceeded twelve seconds")


def stop_process_group(process):
    """Only signal the new session created for this exact child, including Chrome."""
    if process is None:
        return False
    forced = process.poll() is None
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # The leader may exit before its browser descendants. Their owned process
    # group still needs termination before deleting the temporary profile.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)
    return forced


def run(args):
    if sys.platform != "linux" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("Run this integration on an ephemeral GitHub Linux runner")
    temporary_root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    private = Path(tempfile.mkdtemp(prefix=PRIVATE_PREFIX, dir=temporary_root))
    private.chmod(0o700)
    processes = {"native": None, "proxy": None, "browser": None}
    logs = []
    secrets = [str(private)]
    facts = {"schema_version": 1, "passed": False, "github_sha": os.environ.get("GITHUB_SHA"),
             "scope": "Production Web/native loopback integration with real VP8/Opus, owned input and files; not physical Windows or external-network acceptance",
             "started_unix_ms": int(time.time() * 1000), "global_trust_modified": False,
             "browser_product": args.browser_product,
             "exit_codes": {}, "validation_failures": [], "cleanup": {}, "error": None}

    def interrupted(_number, _frame):
        raise InterruptedError("GitHub integration cancellation requested")

    previous_handlers = {number: signal.signal(number, interrupted)
                         for number in (signal.SIGTERM, signal.SIGINT)}

    def spawn(name, arguments, env):
        log = (private / (name + ".log")).open("xb")
        logs.append(log)
        process = subprocess.Popen([str(arg) for arg in arguments], stdout=log, stderr=log,
                                   env=env, start_new_session=True)
        processes[name] = process
        return process

    try:
        site, fixture, caddy, chrome, tools = (Path(value).resolve(strict=True) for value in
                                               (args.site, args.fixture, args.caddy, args.chrome, args.tools))
        if sha256(caddy.read_bytes()) != CADDY_SHA256:
            raise ValueError("Use the pinned Caddy v2.11.7 Linux amd64 executable")
        if read_json(tools / "package.json").get("version") != PUPPETEER_VERSION:
            raise ValueError("Use the reviewed puppeteer-core 25.14.0 runtime")
        if not (site / "index.html").is_file() or not fixture.is_file() or not chrome.is_file():
            raise ValueError("The same-run release site and native/browser executables are required")
        facts["inputs"] = {"native_sha256": sha256(fixture.read_bytes()), "caddy_sha256": CADDY_SHA256,
                           "site_index_sha256": sha256((site / "index.html").read_bytes()),
                           "runner_sha256": sha256(Path(__file__).read_bytes())}
        for name in ("runtime", "probe", "received"):
            (private / name).mkdir()
        env = dict(os.environ, TMPDIR=str(private / "runtime"),
                   XDG_CONFIG_HOME=str(private / "xdg-config"), XDG_DATA_HOME=str(private / "xdg-data"))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            origin = f"https://127.0.0.1:{listener.getsockname()[1]}"
        tls = make_tls(private, origin)
        native = spawn("native", [fixture, site, private / "native", origin, "smoke", "36", "audio", "owned-data"], env)
        ready = wait_ready(private / "native" / "ready.json", native)
        if ready.get("origin") != origin or not ready.get("scope", "").startswith("Ephemeral local development fixture"):
            raise ValueError("Native readiness did not match this owned integration")
        secrets.append(ready["password"])
        descriptor = ready["owned_data"]["upload"]
        length = descriptor["bytes"]
        if type(length) is not int or not 0 < length <= 4 * 1024 * 1024:
            raise ValueError("Owned upload length exceeded its bounded fixture")
        upload = bytes((index * 31 + 7) % 251 for index in range(length))
        if sha256(upload) != descriptor["sha256"]:
            raise ValueError("Owned upload descriptor did not match its deterministic payload")
        (private / "selected-upload.bin").write_bytes(upload)
        config = private / "caddy.json"
        write_json(config, proxy_config(private, origin, ready["browser_backend_origin"]))
        command([str(caddy), "validate", "--config", str(config)])
        proxy = spawn("proxy", [caddy, "run", "--config", config], env)
        verify_https(private, tls, site, proxy)
        facts["tls_verified_exact_leaf_and_ip_san"] = True
        browser = spawn("browser", ["node", ROOT / "scripts/refactor-browser-native-check.cjs",
            "--ready", private / "native/ready.json", "--report", private / "probe/browser-report.json",
            "--tools", tools, "--executable", chrome, "--engine", "chrome", "--tls", private / "tls.json",
            "--browser-product", args.browser_product,
            "--owned-data", "true", "--upload-fixture", private / "selected-upload.bin",
            "--download-directory", private / "received"], env)
        # Includes the space lifecycle's deliberate production rate-window
        # pacing; individual business, media and cleanup deadlines are unchanged.
        facts["exit_codes"]["browser"] = browser.wait(timeout=240)
    except Exception as error:
        facts["error"] = sanitize(f"{type(error).__name__}: {error}", secrets)
    finally:
        # Keep teardown independent: a failed browser termination must still
        # stop the native owner and proxy, and can never yield a passing receipt.
        for number in previous_handlers:
            signal.signal(number, signal.SIG_IGN)
        process_errors = []
        try:
            facts["cleanup"]["browser_forced"] = stop_process_group(processes["browser"])
        except Exception as error:
            process_errors.append(f"browser: {type(error).__name__}")
        try:
            stop = private / "native" / "stop.request"
            if stop.parent.is_dir() and not stop.exists():
                stop.write_text("Owned CI runner finished\n", encoding="utf-8")
            native = processes["native"]
            if native is not None:
                try:
                    facts["exit_codes"]["native"] = native.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    facts["validation_failures"].append("native-stop-timeout")
        except Exception as error:
            process_errors.append(f"native stop: {type(error).__name__}")
        for name in ("native", "proxy"):
            try:
                forced = stop_process_group(processes[name])
                if name == "native":
                    facts["cleanup"]["native_forced"] = forced
            except Exception as error:
                process_errors.append(f"{name}: {type(error).__name__}")
        facts["cleanup"]["process_errors"] = process_errors
        facts["cleanup"]["owned_processes_stopped"] = not process_errors
        for log in logs:
            log.close()
        try:
            receipts = [read_json(private / folder / filename) for folder, filename in (
                ("probe", "browser-report.json"), ("native", "host-result.json"),
                ("native", "data-result.json"), ("native", "database-cleanup.json"))]
            facts["validation_failures"].extend(validate_receipts(
                *receipts, facts["exit_codes"], expected_browser_product=args.browser_product))
        except Exception as error:
            facts["validation_failures"].append("missing-or-invalid-completion-receipt")
            facts["receipt_error"] = sanitize(f"{type(error).__name__}: {error}", secrets)
        try:
            publish_receipts(private, output, secrets)
        except Exception as error:
            facts["validation_failures"].append("evidence-publication")
            facts["publication_error"] = sanitize(f"{type(error).__name__}: {error}", secrets)
        received = private / "received"
        facts["cleanup"]["download_directory_empty_after_probe"] = received.is_dir() and not any(received.iterdir())
        try:
            facts["cleanup"]["private_directory_removed"] = remove_private(private, temporary_root)
        except Exception as error:
            facts["cleanup"]["private_cleanup_error"] = sanitize(f"{type(error).__name__}: {error}", secrets)
        cleanup = facts["cleanup"]
        facts["passed"] = (facts["error"] is None and not facts["validation_failures"]
            and all(cleanup.get(key) is True for key in ("owned_processes_stopped",
                    "download_directory_empty_after_probe", "private_directory_removed"))
            and cleanup.get("browser_forced") is False and cleanup.get("native_forced") is False)
        facts["finished_unix_ms"] = int(time.time() * 1000)
        write_json(output / "runner-result.json", sanitize(facts, secrets))
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
    print(json.dumps({key: facts[key] for key in ("passed", "validation_failures", "error")}))
    return 0 if facts["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("site", "fixture", "caddy", "chrome", "tools", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--browser-product", choices=("chrome", "edge"), default="chrome")
    return run(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
