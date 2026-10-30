use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let spec = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("../../protocol-spec");
    let contract = spec.join("contract.json");
    let proto = spec.join("nestlink.proto");
    println!("cargo:rerun-if-changed={}", contract.display());
    println!("cargo:rerun-if-changed={}", proto.display());
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&contract)?)?;
    let mut constants = format!(
        "pub const SCHEMA_VERSION: u32 = {};\npub const ALPN: &str = {:?};\npub const API_BASE: &str = {:?};\n",
        value["schema_version"].as_u64().ok_or("schema_version")?,
        value["alpn"].as_str().ok_or("alpn")?,
        value["api_base"].as_str().ok_or("api_base")?
    );
    for (name, limit) in value["limits"].as_object().ok_or("limits")? {
        constants.push_str(&format!(
            "pub const {}: u64 = {};\n",
            name.to_uppercase(),
            limit.as_u64().ok_or("limit")?
        ));
    }
    fs::write(
        PathBuf::from(env::var("OUT_DIR")?).join("contract.rs"),
        constants,
    )?;
    let mut config = prost_build::Config::new();
    // Windows protoc uses narrow paths. Stage into TEMP so Chinese workspace
    // paths never reach protoc; Rust itself reads and writes the original paths.
    let staging = tempfile::tempdir()?;
    let staged_proto = staging.path().join("nestlink.proto");
    fs::copy(&proto, &staged_proto)?;
    config.out_dir(staging.path());
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".", "#[derive(schemars::JsonSchema)]");
    for message in [
        "nestlink.v1.EndpointProofClaims",
        "nestlink.v1.NativeProof",
        "nestlink.v1.TurnResourceQueryClaims",
        "nestlink.v1.SignedTurnResourceQuery",
        "nestlink.v1.TurnGrantClaims",
        "nestlink.v1.TurnPeerBindingClaims",
        "nestlink.v1.SignedTurnPeerBinding",
        "nestlink.v1.TurnResourceSnapshotClaims",
        "nestlink.v1.SignedTurnResourceSnapshot",
        "nestlink.v1.TurnCredentialsClaims",
        "nestlink.v1.SignedTurnCredentials",
    ] {
        config.type_attribute(message, "#[serde(deny_unknown_fields)]");
    }
    config.field_attribute(
        "nestlink.v1.NodeResourceSnapshotClaims.network_routes",
        "#[serde(default)]",
    );
    config.field_attribute(
        "nestlink.v1.NodeResourceSnapshotClaims.topology_publications_json",
        "#[serde(default)]",
    );
    config.field_attribute(
        "nestlink.v1.RelayAllocationClaims.node_endpoint_revision",
        "#[serde(default)]",
    );
    for field in [
        "media_format_version",
        "media_formats",
        "media_format_sha256",
    ] {
        config.field_attribute(
            format!("nestlink.v1.PermitClaims.{field}"),
            "#[serde(default)]",
        );
    }
    for message in ["NativeVideo", "NativeVideoFeedback"] {
        for field in ["format_epoch", "format_sha256"] {
            config.field_attribute(
                format!("nestlink.v1.{message}.{field}"),
                "#[serde(default)]",
            );
        }
    }
    config.enum_attribute(
        "nestlink.v1.ErrorCode",
        "#[serde(rename_all = \"SCREAMING_SNAKE_CASE\")]",
    );
    config.compile_protos(&[staged_proto], &[staging.path()])?;
    fs::copy(
        staging.path().join("nestlink.v1.rs"),
        PathBuf::from(env::var("OUT_DIR")?).join("nestlink.v1.rs"),
    )?;
    Ok(())
}
