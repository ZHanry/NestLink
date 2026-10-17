//! Owned, private OS services for the public Portal + PipeWire integration path.
pub mod daemon;
pub mod service;
pub mod session;

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// This ignored test must not connect to the host login or portal services.
/// The launcher verifies isolation before mounting; independently verify it here
/// before creating any service or requesting any OS grant.
pub fn isolated() -> Result {
    let original: std::collections::HashMap<String, String> =
        serde_json::from_str(&std::env::var("NESTLINK_TEST_PORTAL_NAMESPACES")?)?;
    for name in ["mnt", "net", "user"] {
        let previous = original.get(name).ok_or("missing original namespace")?;
        let current = std::fs::read_link(format!("/proc/self/ns/{name}"))?;
        if current.to_str() == Some(previous) {
            return Err("portal fixture requires isolated user/mount/network namespaces".into());
        }
    }
    let status = std::fs::read_to_string("/proc/self/status")?;
    let parent = status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .ok_or("missing parent")?
        .trim();
    if parent != std::env::var("NESTLINK_TEST_PORTAL_PID")? {
        return Err("portal fixture must run under its namespace launcher".into());
    }
    let uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .ok_or("missing uid")?;
    if uid.split_whitespace().any(|part| part != "0") {
        return Err("private system service must be UID 0 inside the user namespace".into());
    }
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    if !mounts.lines().any(|line| {
        line.split_whitespace().nth(4) == Some("/run/dbus") && line.contains(" - tmpfs ")
    }) {
        return Err("private /run/dbus mount missing".into());
    }
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS")?;
    if !address.starts_with("unix:path=/tmp/nestlink-portal-") || address.contains(';') {
        return Err("owned session bus address missing".into());
    }
    Ok(())
}
