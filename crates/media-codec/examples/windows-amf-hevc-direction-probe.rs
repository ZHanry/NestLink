//! Explicit AMF encoder variant of the original finite direction workload.
//! Original MF tool/commands remain distinct. This never grants live authority.
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nestlink_media_codec::{
        ExecutionDirection, HevcEncoderBackend, VideoConfig, probe_hevc_direction_with_encoder,
    };
    use std::sync::atomic::AtomicBool;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 6 {
        return Err("usage: windows-amf-hevc-direction-probe encode|decode main8|main10 WIDTH HEIGHT FPS KBPS".into());
    }
    let direction = match args[0].as_str() {
        "encode" => ExecutionDirection::Encode,
        "decode" => ExecutionDirection::Decode,
        _ => return Err("exact direction required".into()),
    };
    let depth = match args[1].as_str() {
        "main8" => 8,
        "main10" => 10,
        _ => return Err("exact SDR profile required".into()),
    };
    let config = VideoConfig {
        width: args[2].parse()?,
        height: args[3].parse()?,
        fps: args[4].parse()?,
        bitrate_kbps: args[5].parse()?,
    };
    let receipt = probe_hevc_direction_with_encoder(
        config,
        direction,
        &AtomicBool::new(false),
        depth,
        HevcEncoderBackend::AmdAmf,
    )?;
    let contract = receipt.contract();
    let observed = contract.config();
    let owner = receipt.owner();
    owner.require_hardware_identity()?;
    if (
        observed.width,
        observed.height,
        observed.fps,
        observed.bitrate_kbps,
    ) != (config.width, config.height, config.fps, config.bitrate_kbps)
        || contract.bit_depth() != depth
        || receipt.direction() != direction
        || receipt.outputs() < 16
        || !receipt.owner_closed()
        || !receipt.checked_flush()
        || receipt.encoder_backend() != HevcEncoderBackend::AmdAmf
        || receipt.encoder_runtime_version().is_none()
    {
        return Err("AMF receipt differs from exact original workload".into());
    }
    println!(
        "{}",
        serde_json::json!({
            "kind":"hevc-direction-functional-probe", "encoder_implementation":"amd-amf", "decoder_implementation":"original-system-mf",
            "direction":args[0], "profile":args[1], "width":config.width, "height":config.height, "fps_target":config.fps,
            "kbps_ceiling":config.bitrate_kbps, "bit_depth":contract.bit_depth(), "general_profile_tier_level":contract.general_profile_tier_level(),
            "amf_runtime_version":receipt.encoder_runtime_version().map(|v|format!("{v:016x}")),
            "resource_id":owner.resource_id, "adapter_luid":owner.adapter_luid.map(|v|format!("{v:016x}")),
            "driver_version":owner.driver_version.map(|v|format!("{v:016x}")), "hardware_output":owner.hardware_output,
            "outputs":receipt.outputs(), "owner_closed":receipt.owner_closed(), "checked_flush":receipt.checked_flush(),
            "synthetic_input":true, "color":"BT709-limited-SDR", "desktop_capture":false,
            "native_ten_bit_capture":false, "hdr_qualified":false, "performance_qualified":false, "scanout_verified":false
        })
    );
    Ok(())
}
#[cfg(not(windows))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("Windows AMF direction workload unsupported on this platform".into())
}
