//! Direct TLS and bounded framing. Application authorization is required separately.
pub mod owner;
pub mod tls;
use nestlink_protocol::{
    ALPN, AUDIO_FRAME_BYTES, CONTROL_BYTES, FILE_CHUNK_BYTES, FRAME_BYTES, INPUT_BYTES,
    VIDEO_FEEDBACK_BYTES,
};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

pub async fn connect(
    address: SocketAddr,
    config: rustls::ClientConfig,
    budget: Duration,
) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    tokio::time::timeout(budget, async move {
        let tcp = TcpStream::connect(address).await?;
        tcp.set_nodelay(true)?;
        let name = rustls::pki_types::ServerName::try_from("peer.nestlink.invalid")
            .map_err(io::Error::other)?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await?;
        if stream.get_ref().1.alpn_protocol() != Some(ALPN.as_bytes()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NestLink ALPN mismatch",
            ));
        }
        Ok(stream)
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "direct TLS connection budget exhausted",
        )
    })?
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Channel {
    Control = 1,
    Input = 2,
    Video = 3,
    Audio = 4,
    FileRead = 5,
    FileWrite = 6,
    ClipboardRead = 7,
    ClipboardWrite = 8,
    VideoFeedback = 9,
}
impl Channel {
    pub fn decode(byte: u8) -> io::Result<Self> {
        match byte {
            1 => Ok(Self::Control),
            2 => Ok(Self::Input),
            3 => Ok(Self::Video),
            4 => Ok(Self::Audio),
            5 => Ok(Self::FileRead),
            6 => Ok(Self::FileWrite),
            7 => Ok(Self::ClipboardRead),
            8 => Ok(Self::ClipboardWrite),
            9 => Ok(Self::VideoFeedback),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown mandatory channel",
            )),
        }
    }
    pub fn budget(self) -> usize {
        match self {
            Self::Control | Self::ClipboardRead | Self::ClipboardWrite => CONTROL_BYTES as usize,
            Self::Input => INPUT_BYTES as usize,
            Self::Video => FRAME_BYTES as usize,
            Self::Audio => AUDIO_FRAME_BYTES as usize,
            Self::FileRead | Self::FileWrite => FILE_CHUNK_BYTES as usize,
            Self::VideoFeedback => VIDEO_FEEDBACK_BYTES as usize,
        }
    }
}
pub struct Frame {
    pub channel: Channel,
    pub payload: Vec<u8>,
}
pub async fn write_frame<W: AsyncWrite + Unpin>(
    stream: &mut W,
    channel: Channel,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > channel.budget() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "channel frame exceeds budget",
        ));
    }
    stream.write_all(&[1, channel as u8]).await?;
    stream
        .write_u32(u32::try_from(payload.len()).map_err(io::Error::other)?)
        .await?;
    stream.write_all(payload).await?;
    stream.flush().await
}
pub async fn read_frame<R: AsyncRead + Unpin>(stream: &mut R) -> io::Result<Frame> {
    read_frame_inner(stream, None, usize::MAX, usize::MAX).await
}
/// Check a bound stream's channel and its additional budget before allocating
/// the body. A Video-sized frame on an Input stream must not allocate 8 MiB.
pub async fn read_channel_frame<R: AsyncRead + Unpin>(
    stream: &mut R,
    expected: Channel,
    budget: usize,
) -> io::Result<Frame> {
    read_frame_inner(stream, Some(expected), budget, usize::MAX).await
}
/// A post-proof native stream caps Control before allocation without reducing
/// the approved video/file budgets. Ordinary frame readers keep their contract.
pub async fn read_frame_control_bounded<R: AsyncRead + Unpin>(
    stream: &mut R,
    control_budget: usize,
) -> io::Result<Frame> {
    read_frame_inner(stream, None, usize::MAX, control_budget).await
}
async fn read_frame_inner<R: AsyncRead + Unpin>(
    stream: &mut R,
    expected: Option<Channel>,
    budget: usize,
    control_budget: usize,
) -> io::Result<Frame> {
    if stream.read_u8().await? != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame schema mismatch",
        ));
    }
    let channel = Channel::decode(stream.read_u8().await?)?;
    if expected.is_some_and(|expected| expected != channel) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame on the wrong bound stream",
        ));
    }
    let size = stream.read_u32().await? as usize;
    if size
        > channel
            .budget()
            .min(budget)
            .min(if channel == Channel::Control {
                control_budget
            } else {
                usize::MAX
            })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "channel frame exceeds budget",
        ));
    }
    let mut payload = vec![0; size];
    stream.read_exact(&mut payload).await?;
    Ok(Frame { channel, payload })
}
