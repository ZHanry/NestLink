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

fn reviewed_git_dependency(package: &Value, forks: &Value) -> bool {
    let Some(name) = package["name"].as_str() else {
        return false;
    };
    let Some(version) = package["version"].as_str() else {
        return false;
    };
    forks["schema_version"] == 2
        && forks["packages"]
            .get(format!("{name}@{version}"))
            .is_some_and(|reviewed| {
                reviewed["name"] == name
                    && package["version"] == reviewed["version"]
                    && package["source"].as_str()
                        == Some(
                            format!(
                                "git+{}?branch={}#{}",
                                forks["repository"].as_str().unwrap_or_default(),
                                forks["branch"].as_str().unwrap_or_default(),
                                forks["commit"].as_str().unwrap_or_default(),
                            )
                            .as_str(),
                        )
            })
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
    let forks: Value =
        serde_json::from_slice(&fs::read(root.join("config/dependency-forks.json"))?)?;
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
            && !reviewed_git_dependency(package, &forks)
        {
            return Err(format!("unreviewed git dependency: {}", package["name"]).into());
        }
        // Upstream forks are Git dependencies outside the first-party workspace.
        if workspace_members.contains(&package["id"]) && package["license"] != "Apache-2.0" {
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
    use super::*;

    #[test]
    fn git_forks_require_the_reviewed_package_version_branch_and_commit() {
        let forks = json!({
            "schema_version": 2,
            "repository": "https://example.com/dependencies.git",
            "branch": "reviewed",
            "commit": "abc",
            "packages": {
                "turn@0.17.2": {"name": "turn", "version": "0.17.2", "directory": "turn"},
                "turn@0.11.0": {"name": "turn", "version": "0.11.0", "directory": "turn-client"}
            }
        });
        let approved = json!({"name":"turn", "version":"0.17.2", "source":"git+https://example.com/dependencies.git?branch=reviewed#abc"});
        assert!(reviewed_git_dependency(&approved, &forks));
        let mut client = approved.clone();
        client["version"] = json!("0.11.0");
        assert!(reviewed_git_dependency(&client, &forks));
        let mut missing_client = forks.clone();
        missing_client["packages"] = json!({"turn@0.17.2": forks["packages"]["turn@0.17.2"]});
        assert!(!reviewed_git_dependency(&client, &missing_client));
        let mut old_schema = forks.clone();
        old_schema["schema_version"] = json!(1);
        assert!(!reviewed_git_dependency(&approved, &old_schema));
        let mut wrong_identity = forks.clone();
        wrong_identity["packages"]["turn@0.17.2"]["name"] = json!("another-package");
        assert!(!reviewed_git_dependency(&approved, &wrong_identity));
        for (field, replacement) in [
            ("name", "other-package"),
            ("version", "0.17.3"),
            (
                "source",
                "git+https://example.com/dependencies.git?branch=reviewed#def",
            ),
            (
                "source",
                "git+https://example.com/dependencies.git?branch=other#abc",
            ),
            (
                "source",
                "git+https://example.com/other.git?branch=reviewed#abc",
            ),
        ] {
            let mut changed = approved.clone();
            changed[field] = json!(replacement);
            assert!(!reviewed_git_dependency(&changed, &forks));
        }
    }
}
