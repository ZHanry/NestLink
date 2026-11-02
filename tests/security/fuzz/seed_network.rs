//! Construct structural corpus inputs on Actions, without issuing authority.
use nestlink_protocol::{
    media_format::{FrameRate, VideoFormat},
    network_datagram as v1, network_datagram_v2 as v2,
};
use std::{error::Error, path::Path};
fn main() -> Result<(), Box<dyn Error>> {
    let directory = std::env::args().nth(1).ok_or("corpus directory required")?;
    let directory = Path::new(&directory);
    std::fs::create_dir_all(directory)?;
    let write = |name: &str, selector: u8, data: &[u8]| -> std::io::Result<()> {
        let mut bytes = vec![selector];
        bytes.extend_from_slice(data);
        std::fs::write(directory.join(name), bytes)
    };
    for length in [1, 899, 900, 901, 1400] {
        let payload = vec![42; length];
        for direction in [v1::Direction::FirstToSecond, v1::Direction::SecondToFirst] {
            for (index, fragment) in v1::encode([1; 32], direction, 1, &payload)?
                .iter()
                .enumerate()
            {
                write(&format!("nrd1-{direction:?}-{length}-{index}"), 0, fragment)?;
            }
            for hops in [1, 2] {
                for (index, fragment) in v2::encode([1; 32], direction, hops, 1, &payload)?
                    .iter()
                    .enumerate()
                {
                    write(
                        &format!("nrd2-{direction:?}-{length}-{hops}-{index}"),
                        1,
                        fragment,
                    )?;
                }
            }
        }
    }
    let vp8 = VideoFormat::legacy_vp8(640, 360, FrameRate::new(30, 1)?, 8000)?;
    write("video-format-v2-vp8", 2, &vp8.encode()?)?;
    let h264 = VideoFormat::legacy_h264(31, 640, 360, FrameRate::new(30, 1)?, 8000)?;
    write("video-format-v2-h264", 2, &h264.encode()?)?;
    let hevc = VideoFormat::hevc_main8_observed(
        [1, 0x60, 0, 0, 0xb0, 0, 0, 0, 0, 0, 0, 93],
        640,
        360,
        FrameRate::new(30, 1)?,
        8000,
    )?;
    write("video-format-v3-hevc", 2, &hevc.encode()?)?;
    for (name, selector, magic) in [
        ("nlmf", 3, b"NLMF".as_slice()),
        ("grant", 4, b"{}"),
        ("offline", 5, b"{}"),
        ("renewal", 6, b"NLRN"),
        ("display", 6, b"NLDF"),
    ] {
        write(name, selector, magic)?;
    }
    // Original independent structural VP8 vector, not a decodable video claim.
    let hex = "080110091807200328013090bf05382040184801520c3000009d012a200018000000";
    let video = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    write("native-vp8", 7, &video)?;
    Ok(())
}
