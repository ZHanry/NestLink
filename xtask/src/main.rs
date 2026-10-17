use nestlink_policy::{NetworkPolicy, PublicIngress, ServerForwarding};
use nestlink_protocol::{ALPN, API_BASE, SCHEMA_VERSION};
use serde_json::{Value, json};
use std::{env, fs, path::PathBuf, process::Command};
mod api;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn is_first_party_manifest(path: &str) -> bool {
    let path = path.replace('\\', "/");
    ![
        "/crates/traversal/vendor/",
        "/crates/web-vendor/",
        "/crates/platform-vendor/",
    ]
    .iter()
    .any(|vendor_root| path.contains(vendor_root))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("contract") if args.len() == 1 || args.get(1).is_some_and(|v| v == "--write") => {
            contract(&root, args.len() == 2)?;
        }
        Some("check") if args.len() == 1 => {
            contract(&root, false)?;
            check_workspace(&root)?;
            println!("contract, versions and isolated workspace: passed");
        }
        Some("policy") if args.len() == 2 => {
            let policy: NetworkPolicy = serde_json::from_slice(&fs::read(&args[1])?)?;
            let policy = policy.validate()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "allowed_peer_paths": policy.paths()?.to_wire(),
                    "public_ingress_allowed": policy.server_forwarding == ServerForwarding::Allow && policy.public_ingress == PublicIngress::Enabled
                }))?
            );
        }
        _ => {
            return Err(
                "usage: cargo xtask check | contract [--write] | policy <network-policy.json>"
                    .into(),
            );
        }
    }
    Ok(())
}

fn contract(root: &std::path::Path, write: bool) -> Result<(), Box<dyn std::error::Error>> {
    let spec: Value = serde_json::from_slice(&fs::read(root.join("protocol-spec/contract.json"))?)?;
    let compatibility: Value = serde_json::from_slice(&fs::read(root.join("compatibility.json"))?)?;
    if compatibility["protocol_alpn"] != ALPN
        || compatibility["api_base"] != API_BASE
        || compatibility["schema_version"] != SCHEMA_VERSION
        || compatibility["version"] != spec["product_version"]
        || spec["product_version"].as_str() != Some(env!("CARGO_PKG_VERSION"))
        || compatibility["legacy_compatible"] != false
        || compatibility["release_ready"] != false
    {
        return Err("compatibility metadata differs from the internal protocol source".into());
    }
    let (paths, schemas) = api::document(root)?;
    let openapi = json!({
        "openapi": "3.1.0",
        "info": { "title": "NestLink management contract", "version": spec["product_version"],
            "description": "Generated from protocol-spec/management.rs and management-routes.json." },
        "servers": [{"url": API_BASE}],
        "paths": paths,
        "components": {"schemas": schemas,"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"},"accessCookie":{"type":"apiKey","in":"cookie","name":"nl15_access"}}},
        "x-nestlink-alpn": ALPN,
        "x-nestlink-schema-version": SCHEMA_VERSION,
        "x-nestlink-budgets": spec["limits"]
    });
    let rendered = serde_json::to_string_pretty(&openapi)? + "\n";
    let path = root.join("protocol-spec/openapi.json");
    if write {
        fs::write(path, rendered)?;
        println!("generated protocol-spec/openapi.json");
    } else if fs::read_to_string(&path)? != rendered {
        return Err("OpenAPI drift: run cargo xtask contract --write".into());
    }
    Ok(())
}

fn check_workspace(root: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .current_dir(root)
        .args(["metadata", "--format-version", "1", "--locked"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)?;
    let workspace_members = metadata["workspace_members"]
        .as_array()
        .ok_or("missing workspace members")?;
    for package in metadata["packages"].as_array().ok_or("missing packages")? {
        let path = package["manifest_path"]
            .as_str()
            .ok_or("missing manifest")?
            .replace('\\', "/");
        if path.contains("/legacy/") || path.contains("/homedesk-core/") {
            return Err(format!("legacy package in build graph: {path}").into());
        }
        if package["source"]
            .as_str()
            .is_some_and(|s| s.starts_with("git+"))
        {
            return Err(format!("unreviewed git dependency: {}", package["name"]).into());
        }
        // Cargo metadata includes local path dependencies in workspace_members,
        // including upstream forks under the explicitly reviewed vendor roots.
        // Those packages keep their upstream license and are checked by cargo-deny.
        if workspace_members.contains(&package["id"])
            && is_first_party_manifest(&path)
            && package["license"] != "Apache-2.0"
        {
            return Err(format!("unexpected first-party license: {}", package["name"]).into());
        }
        if ["rustdesk", "hbb_common", "frpc", "frps"]
            .iter()
            .any(|v| package["name"] == *v)
        {
            return Err(format!("forbidden legacy runtime package: {}", package["name"]).into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_first_party_manifest;

    #[test]
    fn vendor_forks_keep_their_upstream_license() {
        for path in [
            r"D:\repo\crates\traversal\vendor\turn\Cargo.toml",
            r"D:\repo\crates\traversal\vendor\ice\Cargo.toml",
            r"D:\repo\crates\web-vendor\leptos_macro\Cargo.toml",
            r"D:\repo\crates\platform-vendor\objc2-foundation\Cargo.toml",
        ] {
            assert!(!is_first_party_manifest(path), "{path}");
        }
    }

    #[test]
    fn first_party_packages_remain_subject_to_apache_license_check() {
        for path in [
            r"D:\repo\crates\policy\Cargo.toml",
            r"D:\repo\apps\server\Cargo.toml",
            r"D:\repo\xtask\Cargo.toml",
        ] {
            assert!(is_first_party_manifest(path), "{path}");
        }
    }
}
