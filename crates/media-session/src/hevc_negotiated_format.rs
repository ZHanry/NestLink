//! Exact independently-versioned HEVC target conversion. No legacy codec mapping,
//! probe substitution, software fallback or implicit authority is introduced.
#[cfg(windows)]
use nestlink_media_codec::HevcExecutionTarget;
use nestlink_media_codec::{HevcMain8Contract, VideoConfig};
use nestlink_protocol::media_format::{Codec, Geometry, HEVC_FORMAT_VERSION, VideoFormat};
use std::io;

pub fn hevc_main8_contract(format: VideoFormat) -> io::Result<HevcMain8Contract> {
    format.validate().map_err(io::Error::other)?;
    if format.codec != Codec::Hevc
        || format.canonical_version() != HEVC_FORMAT_VERSION
        || format.geometry != Geometry::uncropped(format.width, format.height)
        || format.frame_rate.denominator != 1
    {
        return Err(io::Error::other(
            "signed format has no exact Main8 hardware execution",
        ));
    }
    let ptl = format
        .hevc_ptl
        .ok_or_else(|| io::Error::other("signed HEVC target lacks full PTL"))?;
    let config = VideoConfig {
        width: format.width,
        height: format.height,
        fps: format.frame_rate.numerator,
        bitrate_kbps: format.max_kbps,
    };
    HevcMain8Contract::from_exact_target(ptl.general_bytes(), config)
}
#[cfg(windows)]
pub fn hevc_execution_target(
    format: VideoFormat,
    adapter_luid: u64,
    driver_version: u64,
) -> io::Result<HevcExecutionTarget> {
    HevcExecutionTarget::new(
        hevc_main8_contract(format)?,
        format.digest().map_err(io::Error::other)?,
        adapter_luid,
        driver_version,
    )
}
#[cfg(windows)]
pub fn hevc_execution_receipt_matches(
    receipt: &nestlink_media_codec::HevcExecutionReceipt,
    format: VideoFormat,
) -> io::Result<()> {
    receipt.check_current()?;
    let owner = receipt.identity()?;
    if receipt.target()
        != hevc_execution_target(format, owner.adapter_luid(), owner.driver_version())?
    {
        return Err(io::Error::other(
            "live HEVC execution differs from frozen signed format",
        ));
    }
    Ok(())
}
#[cfg(windows)]
pub fn hevc_submission_receipt_matches(
    receipt: &nestlink_media_codec::HevcGpuSubmissionReceipt,
    format: VideoFormat,
) -> io::Result<()> {
    receipt.check_current()?;
    let owner = receipt.owner();
    owner.require_hardware_identity()?;
    let adapter = owner
        .adapter_luid
        .ok_or_else(|| io::Error::other("HEVC actual presenter adapter absent"))?;
    let driver = owner
        .driver_version
        .ok_or_else(|| io::Error::other("HEVC actual presenter driver absent"))?;
    if receipt.target() != hevc_execution_target(format, adapter, driver)? {
        return Err(io::Error::other(
            "actual HEVC GPU submission differs from frozen signed format",
        ));
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use nestlink_protocol::media_format::{FrameRate, HevcPtl};
    #[test]
    fn exact_4k_144_target_preserves_hardware_format_and_level_rate_limits() -> io::Result<()> {
        let mut ptl=[0;12];ptl[0]=1;ptl[11]=183;
        let format=VideoFormat::hevc_main8_observed(ptl,3840,2160,FrameRate::new(144,1).map_err(io::Error::other)?,40000).map_err(io::Error::other)?;
        let target=hevc_execution_target(format,7,8)?;
        assert_eq!((target.config().width,target.config().height,target.config().fps),(3840,2160,144));
        assert_eq!(target.format_digest(),format.digest().map_err(io::Error::other)?);
        ptl[11]=180;
        assert!(VideoFormat::hevc_main8_observed(ptl,3840,2160,FrameRate::new(144,1).map_err(io::Error::other)?,40000).is_err());
        Ok(())
    }
    #[test]
    fn exact_target_keeps_every_ptl_bit_and_independent_wire_digest() -> io::Result<()> {
        let mut ptl = [0; 12];
        ptl[0] = 1;
        ptl[11] = 120;
        let format = VideoFormat::hevc_main8_observed(
            ptl,
            640,
            480,
            FrameRate::new(30, 1).map_err(io::Error::other)?,
            4000,
        )
        .map_err(io::Error::other)?;
        let target = hevc_execution_target(format, 7, 8)?;
        assert_eq!(target.contract().general_profile_tier_level(), ptl);
        assert_eq!(
            target.format_digest(),
            format.digest().map_err(io::Error::other)?
        );
        assert_ne!(target.format_digest(), target.contract().digest());
        let mut changed = format;
        ptl[6] ^= 0x80;
        changed.hevc_ptl = Some(HevcPtl::main8(ptl).map_err(io::Error::other)?);
        assert_ne!(hevc_execution_target(changed, 7, 8)?, target);
        assert_ne!(hevc_execution_target(format, 7, 9)?, target);
        Ok(())
    }
    #[test]
    fn legacy_and_nonexecutable_main8_timing_or_surface_are_not_remapped() -> io::Result<()> {
        let h264 = VideoFormat::legacy_h264(
            31,
            640,
            480,
            FrameRate::new(30, 1).map_err(io::Error::other)?,
            4000,
        )
        .map_err(io::Error::other)?;
        assert!(hevc_execution_target(h264, 7, 8).is_err());
        let mut ptl = [0; 12];
        ptl[0] = 1;
        ptl[11] = 120;
        let hevc = VideoFormat::hevc_main8_observed(
            ptl,
            640,
            480,
            FrameRate::new(30, 1).map_err(io::Error::other)?,
            4000,
        )
        .map_err(io::Error::other)?;
        assert!(
            hevc_execution_target(
                VideoFormat {
                    frame_rate: FrameRate {
                        numerator: 30_000,
                        denominator: 1001
                    },
                    ..hevc
                },
                7,
                8
            )
            .is_err()
        );
        let mut changed = hevc;
        changed.width = 638;
        changed.geometry = Geometry::uncropped(638, 480);
        assert!(hevc_execution_target(changed, 7, 8).is_err());
        Ok(())
    }
}
