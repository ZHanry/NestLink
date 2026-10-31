//! Re-project retained observations before export. Private metadata is not a
//! license to copy arbitrary JSON, labels, paths or future unknown fields.
use super::service;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    io,
    path::{Path, PathBuf},
};

const NATIVE_LIMIT: u64 = 256 * 1024;
const EXPORT_LIMIT: usize = 512 * 1024;

#[derive(clap::Args)]
pub(crate) struct ExportArgs {
    /// Existing owner-private installation directory. No login is required.
    #[arg(long)]
    state_dir: PathBuf,
    /// New absolute file in an existing owner-private directory.
    #[arg(long)]
    output: PathBuf,
}

pub(crate) fn run_export(args: ExportArgs) -> io::Result<()> {
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() == 0 {
        return Err(io::Error::other(
            "diagnostic export must run as the ordinary installation owner",
        ));
    }
    #[cfg(windows)]
    nestlink_privileged::windows::require_normal_user_process()?;
    if !args.state_dir.is_absolute() || !args.output.is_absolute() {
        return Err(io::Error::other(
            "diagnostic source and output require absolute paths",
        ));
    }
    nestlink_platform_security::check_private_directory(&args.state_dir)?;
    let parent = args
        .output
        .parent()
        .ok_or_else(|| io::Error::other("diagnostic output parent missing"))?;
    nestlink_platform_security::check_private_directory(parent)?;
    let bytes = serde_json::to_vec_pretty(&collect(&args.state_dir))?;
    if bytes.len() > EXPORT_LIMIT {
        return Err(io::Error::other("diagnostic export exceeds limit"));
    }
    nestlink_platform_security::create_private(&args.output, &bytes)?;
    let actual = nestlink_platform_security::read_private(&args.output, EXPORT_LIMIT as u64)?;
    if *actual != bytes {
        return Err(io::Error::other(
            "diagnostic export readback differs; file retained",
        ));
    }
    println!(
        "diagnostics_bytes={} diagnostics_sha256={}",
        bytes.len(),
        nestlink_protocol::diagnostics::request_hash(
            std::str::from_utf8(&bytes).map_err(io::Error::other)?
        )
    );
    Ok(())
}

fn typed<T: DeserializeOwned + Serialize>(value: &Value) -> Value {
    serde_json::from_value::<T>(value.clone())
        .ok()
        .and_then(|value| serde_json::to_value(value).ok())
        .unwrap_or(Value::Null)
}
fn number(value: &Value) -> Value {
    value.as_u64().map_or(Value::Null, |number| json!(number))
}
fn hash(value: &Value) -> Value {
    value
        .as_str()
        .filter(|text| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .map_or(Value::Null, |text| json!(text))
}
fn label(value: &Value, allowed: &[&str]) -> Value {
    value
        .as_str()
        .filter(|text| allowed.contains(text))
        .map_or(Value::Null, |text| json!(text))
}
fn native_event(value: &Value) -> Option<Value> {
    value.get("sequence")?.as_u64()?;
    value.get("elapsed_ms")?.as_u64()?;
    let state = &value["state"];
    let event = label(
        &state["event"],
        &[
            "native_session",
            "native_connection_failed",
            "daemon_disconnected",
        ],
    );
    if event.is_null() {
        return None;
    }
    let quality = &value["quality"];
    let binding = &quality["binding"];
    Some(
        json!({"sequence":number(&value["sequence"]),"elapsed_ms":number(&value["elapsed_ms"]),
        "state":{"event":event,"request_sha256":hash(&state["request_sha256"]),
            "core_generation":number(&state["core_generation"]),"connection_generation":number(&state["connection_generation"]),
            "lease_sequence":number(&state["lease_sequence"]),"status":typed::<nestlink_app_core::NativeSessionStatus>(&state["status"]),
            "observed_route":label(&state["observed_route"], &["direct","relay"]),
            "stop_reason":typed::<nestlink_app_core::NativeSessionStopReason>(&state["stop_reason"]),
            "cleanup":typed::<nestlink_app_core::NativeSessionCleanup>(&state["cleanup"]),
            "failure":typed::<nestlink_app_core::Failure>(&state["failure"])},
        "quality":if quality.is_null() {Value::Null} else {json!({
            "transport":typed::<nestlink_protocol::api::Transport>(&quality["transport"]),
            "candidate_kind":typed::<nestlink_protocol::api::CandidateKind>(&quality["candidate_kind"]),
            "network_generation":number(&quality["network_generation"]),"bilateral_ice":quality["bilateral_ice"].as_bool(),
            "binding":if binding.is_null() {Value::Null} else {json!({
                "business_grant_sha256":typed::<[u8;32]>(&binding["business_grant_sha256"]),
                "business_generation":number(&binding["business_generation"]),"path_grant_sha256":hash(&binding["path_grant_sha256"]),
                "transport_group":typed::<[u8;32]>(&binding["transport_group"]),"route_binding":typed::<[u8;32]>(&binding["route_binding"])})},
            "rtt_us":number(&quality["rtt_us"]),"smoothed_rtt_change_us":number(&quality["smoothed_rtt_change_us"]),
            "packet_window":typed::<nestlink_app_core::NativePacketObservationWindow>(&quality["packet_window"]),
            "business_tx":typed::<nestlink_app_core::NativeBusinessTxWindow>(&quality["business_tx"]),
            "available_bytes_per_second":number(&quality["available_bytes_per_second"]),"cost":number(&quality["cost"]),
            "mtu":null,"queue_delay_us":null,"outer_vpn_route":null})}}),
    )
}
fn browser_event(value: Value) -> Option<Value> {
    let request = hash(&value["request_sha256"]);
    if request.is_null() {
        return None;
    }
    Some(
        json!({"request_sha256":request,"connection_generation":number(&value["connection_generation"]),
        "unix_ms":number(&value["unix_ms"]),"elapsed_ms":number(&value["elapsed_ms"]),
        "stage":label(&value["stage"], &["FetchHostPermit","PrepareCapture","AwaitDisplayApproval","PrepareData",
            "ActivateSession","CreatePeer","HostLoop","RefreshSdk","AnswerNextOffer","Shutdown"]),
        "source":if value["source"] == "Progress" {Some("progress")} else if value["source"].is_string() {Some("unclassified")} else {None},
        "peer_timeline":typed::<nestlink_sdk::webrtc_host::WebRtcConnectionTimeline>(&value["peer_timeline"]),
        "peer_elapsed_ms":number(&value["peer_elapsed_ms"])}),
    )
}
fn service_event(value: Value) -> Option<Value> {
    let event = serde_json::from_value::<service::Event>(value).ok()?;
    if [
        &event.operation_sha256,
        &event.service_sha256,
        &event.space_sha256,
    ]
    .iter()
    .any(|text| hash(&json!(text)).is_null())
    {
        return None;
    }
    serde_json::to_value(event).ok()
}
fn read(path: &Path, limit: u64) -> Result<Vec<u8>, &'static str> {
    match nestlink_platform_security::read_private(path, limit) {
        Ok(bytes) => Ok(bytes.to_vec()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err("missing"),
        Err(_) => Err("unreadable"),
    }
}
fn lines(path: &Path, projection: fn(Value) -> Option<Value>) -> Value {
    let bytes = match read(path, service::LIMIT as u64) {
        Ok(bytes) => bytes,
        Err(status) => return json!({"status":status,"events":[]}),
    };
    let mut events = std::collections::VecDeque::new();
    let mut rejected = 0u64;
    let mut omitted = 0u64;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let Some(event) = serde_json::from_slice(line).ok().and_then(projection) else {
            rejected += 1;
            continue;
        };
        if events.len() == nestlink_protocol::diagnostics::TIMELINE_EVENT_LIMIT {
            events.pop_front();
            omitted += 1;
        }
        events.push_back(event);
    }
    json!({"status":if rejected == 0 {"present"} else {"partial"},"rejected_records":rejected,"omitted_records":omitted,"events":events})
}
fn native(path: &Path) -> Value {
    let bytes = match read(path, NATIVE_LIMIT) {
        Ok(bytes) => bytes,
        Err(status) => return json!({"status":status,"events":[]}),
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return json!({"status":"invalid","events":[]});
    };
    if value["schema_version"] != 1
        || value["source"] != "desktop_observation_of_original_core_session"
    {
        return json!({"status":"unsupported","events":[]});
    }
    let Some(source_events) = value["events"].as_array() else {
        return json!({"status":"invalid","events":[]});
    };
    let retained = source_events
        .len()
        .min(nestlink_protocol::diagnostics::TIMELINE_EVENT_LIMIT);
    let events = source_events
        .iter()
        .rev()
        .take(retained)
        .filter_map(native_event)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let rejected = retained - events.len();
    let latest_terminal = native_event(&value["latest_terminal"]);
    let invalid_terminal = !value["latest_terminal"].is_null() && latest_terminal.is_none();
    json!({"status":if rejected == 0 && !invalid_terminal {"present"} else {"partial"},"events":events,
        "rejected_records":rejected,"omitted_records":source_events.len()-retained,
        "dropped_events":number(&value["dropped_events"]),"latest_terminal":latest_terminal})
}
fn collect(directory: &Path) -> Value {
    json!({"schema_version":1,"version":env!("CARGO_PKG_VERSION"),
        "scope":"retained_local_connection_observations",
        "native":native(&directory.join("native-network-diagnostics.json")),
        "browser_host":lines(&directory.join("browser-host-diagnostics.jsonl"), browser_event),
        "private_service":lines(&directory.join(service::FILE), service_event),
        "semantics":{
            "correlation":"native and browser request_sha256 use the same protocol hash; service operation_sha256 is local and independent",
            "time":"elapsed values are local monotonic observations; separate sources have different anchors and are not one-way latency",
            "retention":"bounded newest observations; missing, unreadable and invalid sources are explicit, not successful empty sessions",
            "source":"atomic files read independently; no claim of a synchronized live snapshot",
            "route":"selected_relay_count is configuration; only observed_route and proved browser selected_path are observations",
            "quality":"unknown stays null; local business bytes do not measure delivery or available bandwidth",
            "authorization":"diagnostics grant no access and never restore or extend an owner"}})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_reprojects_nested_unknown_data_and_retains_unknown_metrics()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "Bearer SECRET screen file cookie password 192.168.99.2";
        let input = json!({"sequence":1,"elapsed_ms":2,"secret":secret,"state":{"event":"native_session",
            "request_sha256":nestlink_protocol::diagnostics::request_hash("request"),"status":"connected","failure":{"kind":"transport","status":null,"code":null,"token":secret},
            "observed_route":secret},"quality":{"rtt_us":null,"candidate_kind":secret,"binding":{"path_grant_sha256":secret,"token":secret},"payload":secret}});
        let output = native_event(&input).ok_or("missing event")?;
        let encoded = serde_json::to_string(&output)?;
        assert!(!encoded.contains("SECRET"));
        assert!(!encoded.contains("192.168"));
        assert!(output["quality"]["rtt_us"].is_null());
        assert!(output["state"]["observed_route"].is_null());
        assert_eq!(output["state"]["failure"]["kind"], "transport");
        Ok(())
    }
    #[test]
    fn browser_labels_and_ids_cannot_inject_secrets_into_export()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(browser_event(json!({"request_sha256":"secret"})).is_none());
        let event = browser_event(json!({"request_sha256":"a".repeat(64),"stage":"secret URL","source":"secret token","peer_timeline":null})).ok_or("missing event")?;
        assert!(event["stage"].is_null());
        assert_eq!(event["source"], "unclassified");
        assert!(!event.to_string().contains("secret"));
        Ok(())
    }
    #[test]
    fn malformed_source_is_explicit_and_export_never_overwrites_private_input()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let directory = temp.path().join("private");
        nestlink_platform_security::new_private_directory(&directory)?;
        nestlink_platform_security::create_private(
            &directory.join("browser-host-diagnostics.jsonl"),
            b"{broken}\n",
        )?;
        let report = collect(&directory);
        assert_eq!(report["native"]["status"], "missing");
        assert_eq!(report["browser_host"]["status"], "partial");
        assert_eq!(report["browser_host"]["rejected_records"], 1);
        assert_eq!(report["private_service"]["status"], "missing");
        assert!(
            nestlink_platform_security::create_private(
                &directory.join("browser-host-diagnostics.jsonl"),
                b"replacement"
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn native_invalid_event_container_and_records_cannot_be_reported_as_successful_empty_history()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let directory = temp.path().join("private");
        nestlink_platform_security::new_private_directory(&directory)?;
        let path = directory.join("native-network-diagnostics.json");
        for (events, expected) in [
            (json!({}), "invalid"),
            (json!([{"secret":"password"}]), "partial"),
            (json!([]), "present"),
        ] {
            let bytes = serde_json::to_vec(
                &json!({"schema_version":1,"source":"desktop_observation_of_original_core_session","events":events}),
            )?;
            nestlink_platform_security::replace_private_metadata(&path, &bytes)?;
            let report = native(&path);
            assert_eq!(report["status"], expected);
            assert!(!report.to_string().contains("password"));
        }
        Ok(())
    }
}
