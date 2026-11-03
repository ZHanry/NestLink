//! Run only in Actions against its compiled original product executable.
use serde_json::Value;
use std::{io, process::Command};

#[test]
fn unsupported_color_mode_prints_failure_without_starting_an_installation() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let unused_state = root.path().join("must-not-create-user-runtime");
    for extra in [
        ["--chroma", "444"],
        ["--dynamic-range", "hdr10"],
        ["--dynamic-range", "hlg"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_nestlink-daemon"))
            .arg("--state-dir")
            .arg(&unused_state)
            .args([
                "media-capabilities",
                "--mode",
                "hevc-main10",
                "--direction",
                "decode",
                "--target",
                "1920x1080@60:8000",
                "--encoder",
                "amd-amf",
            ])
            .args(extra)
            .output()?;
        assert_eq!(result.status.code(), Some(1));
        let report: Value = serde_json::from_slice(&result.stdout)?;
        assert_eq!(report["available"], false);
        assert_eq!(report["implicit_fallback"], false);
        assert_eq!(report["end_to_end_qualified"], false);
        assert_eq!(report["requested"]["mode"], "hevc-main10");
        assert_eq!(report["requested"]["encoder"], "amd-amf");
        assert_eq!(report["error"]["kind"], "Unsupported");
        assert!(report["observation"].is_null());
        assert!(
            !unused_state.exists(),
            "inspection must dispatch before installation startup"
        );
    }
    Ok(())
}
