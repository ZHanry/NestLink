//! Typed CPU admission for legacy codecs or the separately signed RGB444 mode.
use crate::LegacyPrepare;
use nestlink_media_codec::{H264SpsInfo, VideoCodec, VideoConfig};
use nestlink_protocol::media_format::VideoFormat;
use std::io;

pub enum SoftwareVideoPrepare {
    Legacy(LegacyPrepare),
    Vp9Rgb444(VideoFormat),
}
impl SoftwareVideoPrepare {
    pub fn new_cpu_visible(codec: VideoCodec, width: u32, height: u32) -> io::Result<Self> {
        Ok(Self::Legacy(LegacyPrepare::new_cpu_visible(
            codec, width, height,
        )?))
    }
    pub fn with_format(
        codec: VideoCodec,
        width: u32,
        height: u32,
        format: Option<VideoFormat>,
    ) -> io::Result<Self> {
        if codec != VideoCodec::Vp9Rgb444 {
            return Self::new_cpu_visible(codec, width, height);
        }
        let format =
            format.ok_or_else(|| io::Error::other("VP9 RGB444 requires an exact signed format"))?;
        let target = crate::vp9_rgb444_execution_target(format)?;
        if (target.config().width, target.config().height) != (width, height) {
            return Err(io::Error::other(
                "VP9 RGB444 capture geometry differs from signed format",
            ));
        }
        Ok(Self::Vp9Rgb444(format))
    }
    pub fn validate(&mut self, bytes: &[u8], keyframe: bool) -> io::Result<Option<H264SpsInfo>> {
        match self {
            Self::Legacy(value) => value.validate(bytes, keyframe),
            Self::Vp9Rgb444(format) => {
                if !keyframe {
                    return Err(io::Error::other(
                        "VP9 RGB444 requires independent keyframes",
                    ));
                }
                nestlink_media_codec::validate_vp9_rgb444_keyframe(
                    bytes,
                    format.width,
                    format.height,
                )?;
                Ok(None)
            }
        }
    }
    pub fn configured(
        &self,
        config: VideoConfig,
        sps: Option<H264SpsInfo>,
    ) -> io::Result<VideoFormat> {
        match self {
            Self::Legacy(value) => value.configured(config, sps),
            Self::Vp9Rgb444(format) => {
                let expected = crate::vp9_rgb444_execution_target(*format)?.config();
                if sps.is_some()
                    || (config.width, config.height, config.fps, config.bitrate_kbps)
                        != (
                            expected.width,
                            expected.height,
                            expected.fps,
                            expected.bitrate_kbps,
                        )
                {
                    return Err(io::Error::other(
                        "VP9 RGB444 actual configuration differs from signed format",
                    ));
                }
                Ok(*format)
            }
        }
    }
}
