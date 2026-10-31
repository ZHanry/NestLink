//! Actual production connect command, OS native stream, redirected byte stdio
//! and exit while the original stdin pipe is deliberately still open.
use std::{io::{Read, Write}, process::{Child, Command, Stdio}, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct ChildOwner(Child);
impl Drop for ChildOwner { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }

async fn exchange(half_close: bool) -> Result {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("private");
    nestlink_platform_security::new_private_directory(&directory)?;
    let mut listener = nestlink_platform_security::local_stream::Listener::bind(&directory, &nestlink_auth::random_id())?;
    let mut child = ChildOwner(Command::new(env!("CARGO_BIN_EXE_nestlink-daemon"))
        .args(["private-service-proxy", "--state-dir"]).arg(&directory)
        .args(["connect", "--endpoint"]).arg(listener.endpoint())
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?);
    let mut input = child.0.stdin.take().ok_or("child stdin missing")?;
    input.write_all(b"native stdio request")?;
    let mut stream = tokio::time::timeout(Duration::from_secs(3), listener.accept()).await??;
    if half_close {
        drop(input);
        let mut request = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut request)).await??;
        assert_eq!(request, b"native stdio request");
    } else {
        let mut request = [0_u8; 20];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut request)).await??;
        assert_eq!(&request, b"native stdio request");
        // Keep this parent write handle alive until the child exits. A naive
        // tokio::io::stdin reader would keep its runtime blocked after peer EOF.
        let _kept_input = &input;
    }
    let response = [0_u8, 255, 128, 1, 2, 0, 7];
    stream.write_all(&response).await?;
    stream.shutdown().await?;
    drop(stream);
    let status = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if let Some(status) = child.0.try_wait()? { break Ok::<_, std::io::Error>(status); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    let mut output = Vec::new();
    child.0.stdout.take().ok_or("child stdout missing")?.read_to_end(&mut output)?;
    let mut diagnostic = String::new();
    child.0.stderr.take().ok_or("child stderr missing")?.read_to_string(&mut diagnostic)?;
    assert!(status.success(), "production stdio connect failed: {diagnostic}");
    assert_eq!(output, response);
    listener.stop_accepting();
    listener.cleanup()?;
    Ok(())
}

#[tokio::test]
async fn remote_eof_exits_stdio_child_with_open_input_and_binary_output() -> Result { exchange(false).await }

#[cfg(unix)]
#[tokio::test]
async fn unix_stdio_input_eof_preserves_final_reverse_response() -> Result { exchange(true).await }
