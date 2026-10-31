//! A bounded adapter to the mature packed-pixel scaler. It changes no source,
//! authorization, colour metadata or input-coordinate space.
use fast_image_resize::{
    PixelType, ResizeAlg, ResizeOptions, Resizer,
    images::{Image, ImageRef},
};
use std::io;
use zeroize::Zeroizing;

fn length(width: u32, height: u32) -> io::Result<usize> {
    if width == 0 || height == 0 || width > 8192 || height > 8192 {
        return Err(io::Error::other("scaled frame exceeds raw pixel budget"));
    }
    let bytes = u64::from(width) * u64::from(height) * 4;
    if bytes > 64 * 1024 * 1024 {
        return Err(io::Error::other("scaled frame exceeds raw pixel budget"));
    }
    usize::try_from(bytes).map_err(io::Error::other)
}

pub fn scale_bgra(
    pixels: &[u8],
    source: (u32, u32),
    target: (u32, u32),
) -> io::Result<Zeroizing<Vec<u8>>> {
    let source_bytes = length(source.0, source.1)?;
    let target_bytes = length(target.0, target.1)?;
    if pixels.len() != source_bytes
        || target.0 > source.0
        || target.1 > source.1
        || u64::from(source.0) * u64::from(target.1) != u64::from(source.1) * u64::from(target.0)
    {
        return Err(io::Error::other(
            "scaler requires an exact bounded uncropped downscale",
        ));
    }
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(target_bytes)
        .map_err(io::Error::other)?;
    output.resize(target_bytes, 0);
    if source == target {
        output.copy_from_slice(pixels);
        return Ok(output);
    }
    let input =
        ImageRef::new(source.0, source.1, pixels, PixelType::U8x4).map_err(io::Error::other)?;
    let mut destination = Image::from_slice_u8(target.0, target.1, &mut output, PixelType::U8x4)
        .map_err(io::Error::other)?;
    // Nearest preserves each packed BGRA sample and uses no intermediate raw
    // pixel caches. Both caller-owned buffers retain their zeroizing lifetime.
    let mut resizer = Resizer::new();
    let options = ResizeOptions::new()
        .resize_alg(ResizeAlg::Nearest)
        .use_alpha(false);
    resizer
        .resize(&input, &mut destination, &options)
        .map_err(io::Error::other)?;
    if resizer.size_of_internal_buffers() != 0 {
        return Err(io::Error::other("unexpected scaler pixel cache"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_packed_scaler_preserves_colours_and_rejects_crop_upscale_or_short_input()
    -> io::Result<()> {
        let mut pixels = vec![0; 8 * 8 * 4];
        for y in 0..8 {
            for x in 0..8 {
                pixels[(y * 8 + x) * 4..(y * 8 + x + 1) * 4].copy_from_slice(&[
                    if x < 4 { 10 } else { 210 },
                    if y < 4 { 30 } else { 230 },
                    80,
                    255,
                ]);
            }
        }
        let scaled = scale_bgra(&pixels, (8, 8), (4, 4))?;
        assert_eq!(&scaled[..4], &[10, 30, 80, 255]);
        assert_eq!(&scaled[12..16], &[210, 30, 80, 255]);
        assert_eq!(&scaled[48..52], &[10, 230, 80, 255]);
        assert_eq!(&scaled[60..64], &[210, 230, 80, 255]);
        assert_eq!(&*scale_bgra(&pixels, (8, 8), (8, 8))?, &pixels);
        for target in [(0, 4), (16, 16), (4, 2), (u32::MAX, u32::MAX)] {
            assert!(scale_bgra(&pixels, (8, 8), target).is_err());
        }
        assert!(scale_bgra(&pixels[..pixels.len() - 1], (8, 8), (4, 4)).is_err());
        Ok(())
    }
}
