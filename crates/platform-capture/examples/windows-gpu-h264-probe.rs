//! Synthetic GPU surfaces only. Never opens DXGI/WGC or captures screen pixels.
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nestlink_media_codec::{H264EncodingLimits, VideoConfig};
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() > 5 {
        return Err("usage: WIDTH HEIGHT FPS KBPS [MAX_LEVEL_IDC]".into());
    }
    let value = |i: usize, default: u32| -> Result<u32, Box<dyn std::error::Error>> {
        Ok(match args.get(i) {
            Some(v) => v.parse()?,
            None => default,
        })
    };
    let config = VideoConfig {
        width: value(0, 1280)?,
        height: value(1, 720)?,
        fps: value(2, 60)?,
        bitrate_kbps: value(3, 4000)?,
    };
    let limits = H264EncodingLimits {
        max_level_idc: u8::try_from(value(4, 42)?)?,
        require_constrained_baseline: false,
    };
    limits.validate_config(config)?;
    match nestlink_platform_capture::probe_windows_gpu_h264(config, limits) {
        Ok(probe) => println!(
            "hardware_surface_probe=passed target={}x{}@{} actual_sps={} same_device=true desktop_capture=false performance_qualified=false driver_internal_readback=unknown",
            config.width,
            config.height,
            config.fps,
            probe.sps.profile_level_id()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::Unsupported => println!(
            "hardware_surface_probe=SKIP target={}x{}@{} desktop_capture=false reason={error}",
            config.width, config.height, config.fps
        ),
        Err(error) => {
            eprintln!("hardware_surface_probe=failed desktop_capture=false reason={error}");
            return Err(error.into());
        }
    }
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    println!("hardware_surface_probe=SKIP reason=requires_Windows desktop_capture=false");
}
