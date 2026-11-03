//! Actual local product probes, never a signed capability or a fallback policy.
use crate::NativeHevcEncoder;
use clap::{Args, ValueEnum};
use nestlink_app_core::NativeMediaProvider;
use nestlink_media_codec::VideoConfig;
use nestlink_protocol::media_authority::MediaDirection;
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Mode {
    CpuH264,
    Vp9Rgb444,
    HevcMain8,
    HevcMain10,
    HevcHdr10,
}
impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::CpuH264 => "cpu-h264",
            Self::Vp9Rgb444 => "vp9-rgb444",
            Self::HevcMain8 => "hevc-main8",
            Self::HevcMain10 => "hevc-main10",
            Self::HevcHdr10 => "hevc-hdr10",
        }
    }
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Direction {
    Encode,
    Decode,
}
impl From<Direction> for MediaDirection {
    fn from(value: Direction) -> Self {
        match value {
            Direction::Encode => Self::Encode,
            Direction::Decode => Self::Decode,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Chroma {
    #[value(name = "420")]
    Yuv420,
    #[value(name = "444")]
    Yuv444,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum DynamicRange {
    Sdr,
    Hdr10,
    Hlg,
}
#[derive(Args)]
pub(crate) struct InspectArgs {
    /// One exact requested mode; no codec or backend is tried on failure.
    #[arg(long, value_enum)]
    mode: Mode,
    #[arg(long, value_enum)]
    direction: Direction,
    /// Exact workload, e.g. 1920x1080@60:8000. No adaptive ladder is inferred.
    #[arg(long, value_parser = crate::parse_media_target_syntax)]
    target: VideoConfig,
    /// HEVC encoder (also the decode probe's sample producer). Decoder stays MF.
    #[arg(long, value_enum)]
    encoder: Option<NativeHevcEncoder>,
    /// VP9 RGB444 requires explicit 444; H264/HEVC modes retain 420 only.
    #[arg(long, value_enum, default_value = "420")]
    chroma: Chroma,
    /// Independent hevc-hdr10 mode requires hdr10. Main10 remains SDR.
    #[arg(long, value_enum, default_value = "sdr")]
    dynamic_range: DynamicRange,
}
impl InspectArgs {
    fn encoder_name(&self) -> Option<&'static str> {
        if matches!(self.mode, Mode::CpuH264 | Mode::Vp9Rgb444) && self.encoder.is_none() {
            return None;
        }
        Some(match self.encoder.unwrap_or(NativeHevcEncoder::SystemMf) {
            NativeHevcEncoder::SystemMf => "system-mf",
            NativeHevcEncoder::AmdAmf => "amd-amf",
        })
    }
    fn provider(&self) -> io::Result<NativeMediaProvider> {
        if self.mode == Mode::Vp9Rgb444 {
            if self.chroma != Chroma::Yuv444 || self.dynamic_range != DynamicRange::Sdr || self.encoder.is_some() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "VP9 RGB444 requires explicit 444, SDR and its software encoder; no HEVC encoder applies"));
            }
            return NativeMediaProvider::software_vp9_rgb444(self.target);
        }
        if self.chroma != Chroma::Yuv420 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the selected H264/HEVC mode has no exact 4:4:4 owner; no replacement was attempted",
            ));
        }
        if (self.mode == Mode::HevcHdr10 && self.dynamic_range != DynamicRange::Hdr10)
            || (self.mode != Mode::HevcHdr10 && self.dynamic_range != DynamicRange::Sdr)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "independent hevc-hdr10 requires explicit hdr10 dynamic range; other modes remain SDR and no replacement was attempted",
            ));
        }
        let encoder = self.encoder.unwrap_or(NativeHevcEncoder::SystemMf).into();
        match self.mode {
            Mode::Vp9Rgb444 => Err(io::Error::other("VP9 mode must use its exact RGB444 configuration")),
            Mode::CpuH264 if self.encoder.is_some() => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HEVC encoder selection cannot apply to the explicit CPU H.264 mode",
            )),
            Mode::CpuH264 => NativeMediaProvider::cpu_software(self.target),
            Mode::HevcMain8 => {
                NativeMediaProvider::gpu_hevc_main8_with_encoder(self.target, encoder)
            }
            Mode::HevcMain10 => {
                NativeMediaProvider::gpu_hevc_main10_with_encoder(self.target, encoder)
            }
            Mode::HevcHdr10 => {
                NativeMediaProvider::gpu_hevc_hdr10_with_encoder(self.target, encoder)
            }
        }
    }
    fn report(&self) -> Value {
        let direction = MediaDirection::from(self.direction);
        json!({
            "schema": 1,
            "scope": "unsigned_local_product_direction_probe",
            "end_to_end_qualified": false,
            "implicit_fallback": false,
            "requested": {
                "mode": self.mode.name(),
                "direction": direction.as_str(),
                "encoder": self.encoder_name(),
                "decoder": if self.mode == Mode::Vp9Rgb444 { "libvpx-software" } else if self.mode == Mode::CpuH264 { "system-mf-software" } else { "system-mf-hardware" },
                "chroma": if self.chroma == Chroma::Yuv420 { "420" } else { "444" },
                "dynamic_range": match self.dynamic_range {
                    DynamicRange::Sdr => "sdr", DynamicRange::Hdr10 => "hdr10", DynamicRange::Hlg => "hlg",
                },
                "width": self.target.width, "height": self.target.height,
                "fps": self.target.fps, "bitrate_kbps": self.target.bitrate_kbps,
            },
            "probe_dependencies": if self.mode == Mode::Vp9Rgb444 {
                "actual libvpx profile1 sRGB/full 8-bit I444 encode and independent decode with adjacent single-pixel color validation"
            } else if self.mode == Mode::CpuH264 {
                "actual CPU H.264 encode and independent decode validation"
            } else {
                "selected hardware encoder, original MF hardware decoder, independent software decoder; sample production is required for either direction"
            },
            "available": false,
            "observation": null,
            "error": null,
        })
    }
}

pub(crate) async fn run(args: InspectArgs) -> io::Result<()> {
    let mut report = args.report();
    let cancelled = AtomicBool::new(false);
    let result = match args.provider() {
        Ok(provider) => {
            let probe = provider.inspect_local_direction(args.direction.into(), &cancelled);
            tokio::pin!(probe);
            tokio::select! {
                result = &mut probe => result,
                signal = tokio::signal::ctrl_c() => {
                    cancelled.store(true, Ordering::Release);
                    let result = probe.await;
                    match signal {
                        Ok(()) => result.and(Err(io::Error::new(io::ErrorKind::Interrupted, "local media inspection cancelled"))),
                        Err(error) => Err(error),
                    }
                }
            }
        }
        Err(error) => Err(error),
    };
    match &result {
        Ok(observed) => {
            report["available"] = json!(true);
            // The ephemeral label is not a device identity or remote permission.
            report["observation"] = json!({
                "version": observed.version,
                "direction": observed.direction,
                "revision": observed.revision,
                "expires_at_unix_ms": observed.expires_at_unix_ms,
                "probe": observed.probe,
                "canonical_formats": observed.formats,
                "checked_close_and_worker_join": true,
            });
        }
        Err(error) => {
            report["error"] =
                json!({"kind": format!("{:?}", error.kind()), "message": error.to_string()});
        }
    }
    {
        let mut output = io::stdout().lock();
        serde_json::to_writer_pretty(&mut output, &report)?;
        writeln!(output)?;
        output.flush()?;
    }
    result.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: InspectArgs,
    }
    #[test]
    fn rgb444_inspection_requires_explicit_chroma_and_software_mode() -> io::Result<()> {
        let args = Cli::try_parse_from(["media-capabilities", "--mode", "vp9-rgb444", "--chroma", "444", "--direction", "decode", "--target", "641x481@144:8000"]).map_err(io::Error::other)?.args;
        args.provider()?;
        assert_eq!(args.report()["requested"]["mode"], "vp9-rgb444");
        assert_eq!(args.report()["requested"]["decoder"], "libvpx-software");
        assert!(args.encoder_name().is_none());
        for extra in [vec![], vec!["--chroma", "420"], vec!["--chroma", "444", "--encoder", "amd-amf"], vec!["--chroma", "444", "--dynamic-range", "hdr10"]] {
            let mut input = vec!["media-capabilities", "--mode", "vp9-rgb444", "--direction", "encode", "--target", "640x480@60:8000"];
            input.extend(extra);
            assert!(Cli::try_parse_from(input).map_err(io::Error::other)?.args.provider().is_err());
        }
        Ok(())
    }
    fn parse(extra: &[&str]) -> Result<InspectArgs, clap::Error> {
        let mut args = vec![
            "media-capabilities",
            "--mode",
            "hevc-main10",
            "--direction",
            "decode",
            "--target",
            "1920x1080@60:8000",
        ];
        args.extend_from_slice(extra);
        Cli::try_parse_from(args).map(|cli| cli.args)
    }
    #[test]
    fn explicit_unsupported_color_requests_never_construct_a_different_provider() -> io::Result<()>
    {
        for extra in [
            vec!["--chroma", "444"],
            vec!["--dynamic-range", "hdr10"],
            vec!["--dynamic-range", "hlg"],
        ] {
            let args = parse(&extra).map_err(io::Error::other)?;
            let error = match args.provider() {
                Ok(_) => return Err(io::Error::other("unsupported mode constructed a provider")),
                Err(error) => error,
            };
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(args.report()["available"], false);
            assert!(args.report()["observation"].is_null());
        }
        Ok(())
    }
    #[test]
    fn main10_sdr_and_sample_encoder_are_explicit_but_not_observed_capability() -> io::Result<()> {
        let args = parse(&["--encoder", "amd-amf"]).map_err(io::Error::other)?;
        let provider = args.provider()?;
        assert_eq!(
            provider.hevc_encoder_backend(),
            nestlink_media_codec::HevcEncoderBackend::AmdAmf
        );
        let report = args.report();
        assert_eq!(report["requested"]["mode"], "hevc-main10");
        assert_eq!(report["requested"]["dynamic_range"], "sdr");
        assert_eq!(report["requested"]["encoder"], "amd-amf");
        assert_eq!(report["requested"]["decoder"], "system-mf-hardware");
        assert_eq!(report["available"], false);
        assert!(report["observation"].is_null());
        Ok(())
    }
    #[test]
    fn hdr_requires_its_independent_mode_and_explicit_hdr_dynamic_range() -> io::Result<()> {
        let args = Cli::try_parse_from([
            "media-capabilities",
            "--mode",
            "hevc-hdr10",
            "--dynamic-range",
            "hdr10",
            "--direction",
            "encode",
            "--target",
            "1920x1080@60:8000",
            "--encoder",
            "amd-amf",
        ])
        .map_err(io::Error::other)?
        .args;
        args.provider()?;
        assert_eq!(args.report()["requested"]["mode"], "hevc-hdr10");
        assert_eq!(args.report()["requested"]["dynamic_range"], "hdr10");
        assert_eq!(args.report()["available"], false);
        Ok(())
    }
    #[test]
    fn malformed_missing_and_over_budget_requests_do_not_run_a_probe() -> io::Result<()> {
        for missing in [
            vec!["media-capabilities"],
            vec!["media-capabilities", "--mode", "hevc-main8"],
        ] {
            assert!(Cli::try_parse_from(missing).is_err());
        }
        assert!(parse(&["--encoder", "automatic"]).is_err());
        assert!(parse(&["--chroma", "422"]).is_err());
        for target in [
            "1920x1080",
            "1920x1080@60:0",
            "1920x1080@145:8000",
            "8192x2160@60:8000",
        ] {
            let args = Cli::try_parse_from([
                "media-capabilities",
                "--mode",
                "hevc-main10",
                "--direction",
                "encode",
                "--target",
                target,
            ]);
            if let Ok(args) = args {
                assert!(args.args.provider().is_err());
            }
        }
        let args = Cli::try_parse_from([
            "media-capabilities",
            "--mode",
            "cpu-h264",
            "--direction",
            "encode",
            "--target",
            "320x240@30:1000",
            "--encoder",
            "amd-amf",
        ])
        .map_err(io::Error::other)?;
        assert!(args.args.provider().is_err());
        Ok(())
    }
}
