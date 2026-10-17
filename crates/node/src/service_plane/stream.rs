use super::{Error, ServiceFlowPermit, gate::rejected};
use nestlink_protocol::ErrorCode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Owns both sockets/carriers and one flow permit. EOF shuts down only the
/// opposite write half; the remaining direction continues until its own EOF.
/// Either authority/idle expiry cancels both directions and drops both I/O owners.
pub async fn forward_streams<A, B>(
    left: A,
    right: B,
    permit: ServiceFlowPermit,
) -> Result<(), Error>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    permit.check_live()?;
    let (left_read, left_write) = tokio::io::split(left);
    let (right_read, right_write) = tokio::io::split(right);
    let transfer = async {
        tokio::try_join!(
            copy_half(left_read, right_write, &permit),
            copy_half(right_read, left_write, &permit)
        )?;
        Ok(())
    };
    tokio::select! { biased;
        _=permit.wait_stopped()=>Err(rejected(ErrorCode::PolicyRevoked).into()),
        result=transfer=>result,
    }
}
async fn copy_half<R, W>(
    mut reader: R,
    mut writer: W,
    permit: &ServiceFlowPermit,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 16 * 1024];
    loop {
        permit.check_live()?;
        let maximum = permit.chunk_budget()?.min(buffer.len());
        let length = reader.read(&mut buffer[..maximum]).await?;
        if length == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        permit.activity()?;
        permit.charge(length).await?;
        let mut offset = 0;
        while offset < length {
            permit.check_live()?;
            let written = writer.write(&buffer[offset..length]).await?;
            if written == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "service stream write made no progress",
                )
                .into());
            }
            offset += written;
            permit.activity()?;
        }
    }
}
