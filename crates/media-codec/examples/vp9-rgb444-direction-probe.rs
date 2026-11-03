use nestlink_media_codec::{ExecutionDirection, VideoConfig, probe_vp9_rgb444_direction};
use std::io;

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "usage: vp9-rgb444-direction-probe encode|decode WIDTH HEIGHT FPS KBPS"));
    }
    let direction = match args[0].as_str() {
        "encode" => ExecutionDirection::Encode,
        "decode" => ExecutionDirection::Decode,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "direction must be encode or decode")),
    };
    let number = |index: usize| -> io::Result<u32> { args[index].parse().map_err(io::Error::other) };
    let probe = probe_vp9_rgb444_direction(direction, VideoConfig { width: number(1)?, height: number(2)?, fps: number(3)?, bitrate_kbps: number(4)? })?;
    println!("codec=vp9 profile=1 bit_depth=8 chroma=444 color=srgb range=full backend=cpu-software direction={:?} width={} height={} fps={} kbps={} output_frames={} elapsed_us={} checked_close={} sustainable_fps_proven=false", probe.direction, probe.config.width, probe.config.height, probe.config.fps, probe.config.bitrate_kbps, probe.output_frames, probe.elapsed.as_micros(), probe.checked_close);
    Ok(())
}
