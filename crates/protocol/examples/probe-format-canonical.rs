//! Intended path: crates/protocol/examples/probe-format-canonical.rs
//! Pure preparation: consumes raw successful probe JSON, never runs a probe.
use nestlink_protocol::media_format::{FrameRate, Geometry, VideoFormat};
use serde::Deserialize;
use std::{error::Error, io};

#[derive(Deserialize)]
struct Fields {
    kind: String,
    backend: String,
    width: u32,
    height: u32,
    fps_target: u32,
    kbps_ceiling: u32,
    profile_idc: u8,
    constraints: u8,
    level_idc: u8,
    coded_width: u32,
    coded_height: u32,
    crop_luma: [u32; 4],
    hardware_output: bool,
    adapter_luid: Option<String>,
    driver_version: Option<String>,
    owner_closed: bool,
    checked_flush: bool,
}
fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 1 {
        return Err("usage: probe-format-canonical RAW_SUCCESSFUL_PROBE_JSON".into());
    }
    let bytes = std::fs::read(&args[0])?;
    if bytes.len() > 65536 {
        return Err("probe JSON too large".into());
    }
    let root: serde_json::Value = serde_json::from_slice(&bytes)?;
    let raw = root.get("pass_fields").unwrap_or(&root);
    // Accept raw stdout object, or existing controller runner result.pass_fields.
    let fields: Fields = serde_json::from_value(raw.clone())?;
    if !matches!(
        fields.kind.as_str(),
        "controller-direction-functional-probe" | "cpu-direction-functional-probe"
    ) || fields.backend != "CpuSoftware"
        || fields.profile_idc != 66
        || fields.hardware_output
        || fields.adapter_luid.is_some()
        || fields.driver_version.is_some()
        || !fields.owner_closed
        || !fields.checked_flush
    {
        return Err("not a successful actual software Baseline direction receipt".into());
    }
    let enough = if fields.kind == "cpu-direction-functional-probe" {
        raw.get("outputs")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|n| n >= 16)
            && matches!(
                raw.get("direction").and_then(serde_json::Value::as_str),
                Some("encode" | "decode")
            )
    } else {
        ["decoded", "color_verified"].iter().all(|key| {
            raw.get(key)
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|n| n >= 16)
        })
    };
    if !enough {
        return Err("insufficient real direction outputs".into());
    }
    // Exact production NativeMediaProvider conversion; preserve observed crop,
    // constraints and level. Color/profile/tier follow that SAME constructor.
    let format = VideoFormat::h264_observed(
        fields.level_idc,
        fields.constraints,
        Geometry {
            coded_width: fields.coded_width,
            coded_height: fields.coded_height,
            crop: fields.crop_luma,
        },
        fields.width,
        fields.height,
        FrameRate::new(fields.fps_target, 1).map_err(io::Error::other)?,
        fields.kbps_ceiling,
    )
    .map_err(io::Error::other)?;
    let canonical = format.encode().map_err(io::Error::other)?;
    let digest = format.digest().map_err(io::Error::other)?;
    let hex = |bytes: &[u8]| bytes.iter().map(|v| format!("{v:02x}")).collect::<String>();
    println!(
        "{}",
        serde_json::json!({
            "canonical_hex": hex(&canonical), "format_sha256": hex(&digest),
            "capture_target": [fields.width, fields.height, fields.fps_target, fields.kbps_ceiling],
            "scope": "preparation-only-not-probe-provenance-or-runtime-authority"
        })
    );
    Ok(())
}
