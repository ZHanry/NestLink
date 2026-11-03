//! Exact independently-versioned HEVC target conversion. No legacy codec mapping,
//! probe substitution, software fallback or implicit authority is introduced.
#[cfg(windows)]
use nestlink_media_codec::HevcExecutionTarget;
use nestlink_media_codec::{HevcMain8Contract, VideoConfig};
use nestlink_protocol::media_format::{
    Codec, Geometry, HEVC_FORMAT_VERSION, HEVC_HDR10_FORMAT_VERSION, HEVC_MAIN10_FORMAT_VERSION,
    VideoFormat,
};
use std::io;

pub fn hevc_main8_contract(format: VideoFormat) -> io::Result<HevcMain8Contract> {
    if format.canonical_version() != HEVC_FORMAT_VERSION {
        return Err(io::Error::other("not an exact v3 Main8 target"));
    }
    hevc_contract(format)
}
pub fn hevc_contract(format: VideoFormat) -> io::Result<HevcMain8Contract> {
    format.validate().map_err(io::Error::other)?;
    if format.codec != Codec::Hevc
        || !matches!(
            format.canonical_version(),
            HEVC_FORMAT_VERSION | HEVC_MAIN10_FORMAT_VERSION | HEVC_HDR10_FORMAT_VERSION
        )
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
    if format.canonical_version() == HEVC_HDR10_FORMAT_VERSION {
        HevcMain8Contract::from_hdr10_target(ptl.general_bytes(), config)
    } else if format.canonical_version() == HEVC_MAIN10_FORMAT_VERSION {
        HevcMain8Contract::from_main10_target(ptl.general_bytes(), config)
    } else {
        HevcMain8Contract::from_exact_target(ptl.general_bytes(), config)
    }
}
pub fn hevc_wire_codec(format: VideoFormat) -> io::Result<nestlink_protocol::NativeVideoCodec> {
    Ok(if hevc_contract(format)?.bit_depth() == 10 {
        nestlink_protocol::NativeVideoCodec::HevcMain10
    } else {
        nestlink_protocol::NativeVideoCodec::HevcMain8
    })
}
#[cfg(windows)]
pub fn hevc_execution_target(
    format: VideoFormat,
    adapter_luid: u64,
    driver_version: u64,
) -> io::Result<HevcExecutionTarget> {
    HevcExecutionTarget::new(
        hevc_contract(format)?,
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
    let selected = receipt.target().encoder();
    if (owner.direction() == nestlink_media_codec::ExecutionDirection::Decode
        && selected != nestlink_media_codec::HevcEncoderSelection::default())
        || receipt.target()
            != hevc_execution_target(format, owner.adapter_luid(), owner.driver_version())?
                .with_encoder(selected)
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
    fn hdr_v5_builds_an_independent_pq_contract_and_preserves_main10_sdr() -> io::Result<()> {
        let mut ptl = [0; 12];
        ptl[0] = 2;
        ptl[11] = 120;
        let rate = FrameRate::new(30, 1).map_err(io::Error::other)?;
        let hdr = VideoFormat::hevc_hdr10_observed(ptl, 640, 480, rate, 4000)
            .map_err(io::Error::other)?;
        let sdr = VideoFormat::hevc_main10_observed(ptl, 640, 480, rate, 4000)
            .map_err(io::Error::other)?;
        let actual = hevc_execution_target(hdr, 7, 9)?;
        assert!(actual.contract().is_hdr10());
        assert!(!hevc_contract(sdr)?.is_hdr10());
        assert_ne!(actual, hevc_execution_target(sdr, 7, 9)?);
        assert_eq!(
            hevc_wire_codec(hdr)?,
            nestlink_protocol::NativeVideoCodec::HevcMain10
        );
        assert!(hevc_main8_contract(hdr).is_err());
        Ok(())
    }
    #[test]
    fn main10_execution_requires_v4_and_keeps_exact_depth_digest_and_hardware() -> io::Result<()> {
        let mut ptl = [0; 12];
        ptl[0] = 2;
        ptl[11] = 153;
        let format = VideoFormat::hevc_main10_observed(
            ptl,
            3840,
            2160,
            FrameRate::new(60, 1).map_err(io::Error::other)?,
            40000,
        )
        .map_err(io::Error::other)?;
        assert!(hevc_main8_contract(format).is_err());
        let target = hevc_execution_target(format, 7, 9)?;
        assert_eq!(target.contract().bit_depth(), 10);
        assert_eq!(
            target.format_digest(),
            format.digest().map_err(io::Error::other)?
        );
        assert_eq!(
            hevc_wire_codec(format)?,
            nestlink_protocol::NativeVideoCodec::HevcMain10
        );
        assert_ne!(target, hevc_execution_target(format, 7, 10)?);
        let selected = nestlink_media_codec::HevcEncoderSelection::new(
            nestlink_media_codec::HevcEncoderBackend::AmdAmf,
            Some(1 << 48),
        )?;
        let amf = target.with_encoder(selected);
        assert_ne!(amf, target);
        assert_eq!(amf.contract(), target.contract());
        assert_eq!(amf.format_digest(), target.format_digest());
        assert_eq!((amf.adapter_luid(), amf.driver_version()), (7, 9));
        Ok(())
    }
    #[test]
    fn exact_4k_144_target_preserves_hardware_format_and_level_rate_limits() -> io::Result<()> {
        let mut ptl = [0; 12];
        ptl[0] = 1;
        ptl[11] = 183;
        let format = VideoFormat::hevc_main8_observed(
            ptl,
            3840,
            2160,
            FrameRate::new(144, 1).map_err(io::Error::other)?,
            40000,
        )
        .map_err(io::Error::other)?;
        let target = hevc_execution_target(format, 7, 8)?;
        assert_eq!(
            (
                target.contract().config().width,
                target.contract().config().height,
                target.contract().config().fps
            ),
            (3840, 2160, 144)
        );
        assert_eq!(
            target.format_digest(),
            format.digest().map_err(io::Error::other)?
        );
        ptl[11] = 180;
        assert!(
            VideoFormat::hevc_main8_observed(
                ptl,
                3840,
                2160,
                FrameRate::new(144, 1).map_err(io::Error::other)?,
                40000
            )
            .is_err()
        );
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
