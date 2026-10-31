//! Byte-preserving stdio adapter for a locally authenticated native stream.
use super::*;
use std::future::Future;
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// EOF from the native peer cancels the original local input operation. Unlike
/// tokio::io::stdin this does not leave an uninterruptible runtime-owned reader.
pub async fn relay_stdio(
    stream: LocalStream,
    stop: impl Future<Output = io::Result<()>>,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix::relay(stream, stop).await
    }
    #[cfg(windows)]
    {
        windows::relay(stream, stop).await
    }
}

async fn relay_io(
    input: impl AsyncRead + Unpin,
    output: impl AsyncWrite + Unpin,
    stream: LocalStream,
    stop: impl Future<Output = io::Result<()>>,
) -> io::Result<()> {
    let (mut input, mut output) = (input, output);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);
    let incoming = async {
        tokio::io::copy(&mut remote_read, &mut output).await?;
        output.flush().await
    };
    let outgoing = async {
        tokio::io::copy(&mut input, &mut remote_write).await?;
        remote_write.shutdown().await
    };
    tokio::pin!(incoming, outgoing, stop);
    tokio::select! { biased;
        result = &mut stop => result,
        result = &mut incoming => result,
        result = &mut outgoing => {
            result?;
            // Unix EOF still permits the backend's final reverse response.
            // A Windows named pipe has no independent write-half close.
            tokio::select! { biased;
                result = &mut stop => result,
                result = &mut incoming => result,
            }
        }
    }
}
