#![cfg(windows)]
use super::{DnsPlan, Journal, ProcessIdentity, Result, Value, command, io};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;

async fn invoke(action: &str, plan: Option<&DnsPlan>, expected: Option<&Value>, pid: u32) -> Result<Value> {
    let source = include_str!("nrpt.ps1");
    let encoded = STANDARD.encode(source.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    let request = json!({"action": action, "plan":plan, "expected":expected, "pid":pid});
    let bytes = command::run(&nestlink_sdk::system_tools::windows_powershell()?,
        &["-NoLogo".into(), "-NoProfile".into(), "-NonInteractive".into(), "-EncodedCommand".into(), encoded],
        Some(("NESTLINK_DNS_REQUEST", serde_json::to_string(&request)?))).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(super) async fn identity(pid: u32) -> Result<ProcessIdentity> {
    Ok(serde_json::from_value(invoke("identity", None, None, pid).await?)?)
}
pub(super) async fn require_admin() -> Result { invoke("admin", None, None, 0).await?; Ok(()) }
pub(super) async fn preflight(plan: &DnsPlan) -> Result { invoke("preflight", Some(plan), None, 0).await?; Ok(()) }
pub(super) async fn inspect(plan: &DnsPlan) -> Result<Option<Value>> {
    let state = invoke("inspect", Some(plan), None, 0).await?;
    Ok(if state.is_null() { None } else { Some(state) })
}
pub(super) async fn install(plan: &DnsPlan) -> Result { invoke("install", Some(plan), None, 0).await?; Ok(()) }
pub(super) fn verify_installed(plan: &DnsPlan, current: &Value) -> Result {
    if current["namespace"] != json!([format!(".{}", plan.suffix)]) || current["name_servers"] != json!(["127.0.0.1"])
        || current["display_name"] != plan.marker() || current["comment"] != plan.marker()
        || current["da_enable"] != false || current["dnssec_enable"] != false
        || current["dnssec_validation"] != false || current["da_ipsec"] != false || current["dnssec_ipsec"] != false
        || !current["name"].as_str().is_some_and(|name| name.len() <= 64 && name.chars().all(|c| c.is_ascii_hexdigit() || matches!(c, '{' | '}' | '-')))
    { return Err(io::Error::other("NRPT did not confirm the exact owned private-suffix rule").into()); }
    Ok(())
}
pub(super) async fn remove(journal: &Journal) -> Result {
    invoke("remove", Some(&journal.plan), journal.installed.as_ref(), 0).await?;
    Ok(())
}

#[cfg(test)]
pub(super) async fn native_unrelated_state() -> Result<Value> { invoke("baseline", None, None, 0).await }
#[cfg(test)]
pub(super) async fn native_query(plan: &DnsPlan) -> Result<String> { Ok(invoke("query", Some(plan), None, 0).await?.to_string()) }
#[cfg(test)]
pub(super) async fn native_change_owned(plan: &DnsPlan) -> Result { invoke("test-change", Some(plan), None, 0).await?; Ok(()) }
#[cfg(test)]
pub(super) async fn native_restore_owned(plan: &DnsPlan, _expected: &Value) -> Result { invoke("test-restore", Some(plan), None, 0).await?; Ok(()) }
