//! GitHub-build then run under an ordinary interactive Windows account.
//! Explicit product target only; no absent-argument fallback or desktop capture.
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nestlink_media_codec::{
        VideoConfig, build_controller_probe_fixture, probe_controller_cpu, probe_controller_gpu,
    };
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 6 {
        return Err("usage: windows-controller-direction-probe WIDTH HEIGHT FPS KBPS cpu-software|cpu-hardware|gpu".into());
    }
    if !matches!(args[5].as_str(), "cpu-software" | "cpu-hardware" | "gpu") {
        return Err("unknown direction backend".into());
    }
    let config = VideoConfig {
        width: args[1].parse()?,
        height: args[2].parse()?,
        fps: args[3].parse()?,
        bitrate_kbps: args[4].parse()?,
    };
    let fixture = build_controller_probe_fixture(config)?;
    let receipt = match args[5].as_str() {
        "cpu-software" => probe_controller_cpu(&fixture, false)?,
        "cpu-hardware" => probe_controller_cpu(&fixture, true)?,
        "gpu" => probe_controller_gpu(&fixture)?,
        _ => return Err("unknown direction backend".into()),
    };
    let owner = receipt.owner();
    let geometry = receipt.geometry();
    let sps = receipt.sps();
    println!(
        "{}",
        serde_json::json!({
            "kind":"controller-direction-functional-probe","backend":format!("{:?}",receipt.backend()),
            "width":config.width,"height":config.height,"fps_target":config.fps,"kbps_ceiling":config.bitrate_kbps,
            "profile_idc":sps.profile_idc,"constraints":sps.constraints,"level_idc":sps.level_idc,
            "coded_width":geometry.coded_width,"coded_height":geometry.coded_height,"crop_luma":geometry.crop,
            "resource_id":owner.resource_id,"adapter_luid":owner.adapter_luid.map(|value|format!("{value:016x}")),"driver_version":owner.driver_version.map(|value|format!("{value:016x}")),
            "hardware_output":owner.hardware_output,"accepted":receipt.accepted(),"decoded":receipt.decoded(),
            "color_verified":receipt.color_verified(),"submitted":receipt.submitted(),"owner_closed":receipt.owner_closed(),
            "pending_decodes_discarded":receipt.pending_decodes_discarded(),"pending_pictures_discarded":receipt.pending_pictures_discarded(),
            "checked_flush":receipt.checked_flush(),"eos_complete":receipt.eos_complete(),"performance_qualified":receipt.performance_qualified(),"scanout_verified":false,"desktop_capture":false
        })
    );
    Ok(())
}
#[cfg(not(windows))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("Windows controller-direction probe unsupported".into())
}
