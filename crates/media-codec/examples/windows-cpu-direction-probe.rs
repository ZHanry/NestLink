//! Intended path: crates/media-codec/examples/windows-cpu-direction-probe.rs
//! Exposes the SAME CPU direction functions used by NativeMediaProvider.
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nestlink_media_codec::{VideoConfig, probe_cpu_decode, probe_cpu_encode};
    use std::sync::atomic::AtomicBool;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 5 || !matches!(args[0].as_str(), "encode" | "decode") {
        return Err(
            "usage: windows-cpu-direction-probe encode|decode WIDTH HEIGHT FPS KBPS".into(),
        );
    }
    let target = VideoConfig {
        width: args[1].parse()?,
        height: args[2].parse()?,
        fps: args[3].parse()?,
        bitrate_kbps: args[4].parse()?,
    };
    let cancel = AtomicBool::new(false);
    let receipt = if args[0] == "encode" {
        probe_cpu_encode(target, &cancel)?
    } else {
        probe_cpu_decode(target, &cancel)?
    };
    let c = receipt.config();
    let s = receipt.sps();
    let g = receipt.geometry();
    let owner = receipt.owner();
    println!(
        "{}",
        serde_json::json!({
            "kind":"cpu-direction-functional-probe", "direction":args[0], "backend":"CpuSoftware",
            "width":c.width, "height":c.height, "fps_target":c.fps, "kbps_ceiling":c.bitrate_kbps,
            "profile_idc":s.profile_idc, "constraints":s.constraints, "level_idc":s.level_idc,
            "coded_width":g.coded_width, "coded_height":g.coded_height, "crop_luma":g.crop,
            "outputs":receipt.outputs(), "owner_closed":receipt.owner_closed(),
            "checked_flush":receipt.checked_flush(), "resource_id":owner.resource_id,
            "hardware_output":owner.hardware_output,
            "adapter_luid":owner.adapter_luid.map(|v| format!("{v:016x}")),
            "driver_version":owner.driver_version.map(|v| format!("{v:016x}")),
            "performance_qualified":false, "desktop_capture":false, "scanout_verified":false
        })
    );
    Ok(())
}
#[cfg(not(windows))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("Windows actual CPU direction probe unsupported".into())
}
