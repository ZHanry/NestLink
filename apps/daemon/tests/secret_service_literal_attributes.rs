//! Exercise the real CLI parser and original owned Secret Service, not a stub.
#![cfg(target_os = "linux")]

#[path = "../src/session_store/secret_tool.rs"]
mod secret_tool;
#[path = "offline_remote_resident/support.rs"]
pub mod support;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{io, process::Stdio, time::Duration};
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn original_secret_service_stores_and_reads_a_leading_hyphen_attribute() -> support::Result {
    let area = tempfile::tempdir()?;
    let platform = support::Platform::new(area.path()).await?;
    let mut attribute = nestlink_auth::random_bytes::<32>();
    attribute[0] = 248; // The original URL-safe base64 alphabet encodes this as '-'.
    let binding = URL_SAFE_NO_PAD.encode(attribute);
    assert!(binding.starts_with('-'));
    let label = "--label=NestLink literal attribute regression";

    // The retired argv is rejected by the actual GLib option parser before
    // any Secret Service operation. This distinguishes usage(2) from store(1).
    for arguments in [
        vec![
            "store",
            label,
            "application",
            "NestLink",
            "instance",
            &binding,
        ],
        vec!["lookup", "application", "NestLink", "instance", &binding],
    ] {
        let status = tokio::time::timeout(
            Duration::from_secs(10),
            platform
                .command("secret-tool")
                .args(arguments)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
        )
        .await??;
        assert_eq!(
            status.code(),
            Some(2),
            "original CLI did not reject an option value"
        );
    }

    let secret_key = zeroize::Zeroizing::new(nestlink_auth::random_bytes::<32>());
    let secret = zeroize::Zeroizing::new(URL_SAFE_NO_PAD.encode(*secret_key));
    // Use the same bounded readiness allowance as the original store gate;
    // the actual newly started keyring still has to accept and retain data.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut store = platform
                .command("secret-tool")
                .args(secret_tool::store(label, &binding))
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            store
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("actual Secret Service input unavailable"))?
                .write_all(secret.as_bytes())
                .await?;
            if store.wait().await?.success() {
                return Ok::<_, io::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let lookup = tokio::time::timeout(
        Duration::from_secs(10),
        platform
            .command("secret-tool")
            .args(secret_tool::lookup(&binding))
            .stderr(Stdio::null())
            .output(),
    )
    .await??;
    assert!(
        lookup.status.success(),
        "actual literal-attribute lookup failed"
    );
    let saved = zeroize::Zeroizing::new(lookup.stdout);
    assert!(
        std::str::from_utf8(&saved)?.trim() == secret.as_str(),
        "actual Secret Service did not retain the exact secret under the literal attribute"
    );
    platform.shutdown().await;
    Ok(())
}
