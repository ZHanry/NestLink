//! Independent finite PQ/BT2020/P010 workload. No desktop or display authority.
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nestlink_media_codec::{
        ExecutionDirection, HevcEncoderBackend, VideoConfig, probe_hevc_hdr10_direction,
    };
    use std::sync::atomic::AtomicBool;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 6 {
        return Err("usage: windows-hdr10-direction-probe encode|decode system-mf|amd-amf WIDTH HEIGHT FPS KBPS".into());
    }
    let direction = match args[0].as_str() {
        "encode" => ExecutionDirection::Encode,
        "decode" => ExecutionDirection::Decode,
        _ => return Err("exact encode or decode direction required".into()),
    };
    let encoder = match args[1].as_str() {
        "system-mf" => HevcEncoderBackend::SystemMf,
        "amd-amf" => HevcEncoderBackend::AmdAmf,
        _ => return Err("one exact encoder implementation required".into()),
    };
    let config = VideoConfig {
        width: args[2].parse()?,
        height: args[3].parse()?,
        fps: args[4].parse()?,
        bitrate_kbps: args[5].parse()?,
    };
    let receipt = probe_hevc_hdr10_direction(config, direction, &AtomicBool::new(false), encoder)?;
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
        || contract.bit_depth() != 10
        || !contract.is_hdr10()
        || receipt.direction() != direction
        || receipt.outputs() != 32
        || !receipt.owner_closed()
        || !receipt.checked_flush()
        || receipt.encoder_backend() != encoder
        || (encoder == HevcEncoderBackend::AmdAmf && receipt.encoder_runtime_version().is_none())
    {
        return Err("HDR receipt differs from exact independent PQ/P010 workload".into());
    }
    println!(
        "{}",
        serde_json::json!({
            "kind":"hevc-hdr10-direction-functional-probe", "encoder_implementation":args[1],
            "decoder_implementation":"original-system-mf", "direction":args[0],
            "width":config.width, "height":config.height, "fps_target":config.fps,
            "kbps_ceiling":config.bitrate_kbps, "bit_depth":contract.bit_depth(),
            "general_profile_tier_level":contract.general_profile_tier_level(),
            "color":"PQ-BT2020-nonconstant-limited", "format_version":5,
            "amf_runtime_version":receipt.encoder_runtime_version().map(|v|format!("{v:016x}")),
            "resource_id":owner.resource_id, "adapter_luid":owner.adapter_luid.map(|v|format!("{v:016x}")),
            "driver_version":owner.driver_version.map(|v|format!("{v:016x}")),
            "hardware_output":owner.hardware_output, "outputs":receipt.outputs(),
            "owner_closed":receipt.owner_closed(), "checked_flush":receipt.checked_flush(),
            "synthetic_p010_quadrants":true, "actual_ten_bit_samples_checked_by_two_decoders":true,
            "desktop_capture":false, "native_ten_bit_capture":false, "hdr_display_qualified":false,
            "performance_qualified":false, "scanout_verified":false
        })
    );
    Ok(())
}
#[cfg(not(windows))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("Windows independent HDR direction workload unsupported on this platform".into())
}
