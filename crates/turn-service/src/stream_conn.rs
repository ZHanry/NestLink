use async_trait::async_trait;
use std::{
    io,
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::{Mutex, watch},
    time::timeout,
};
use webrtc_util::{Conn, Result as UtilResult};

const MAX_TURN_FRAME: usize = 65_560;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_millis(500);

/// A preconnected TURN-over-TCP/TLS client transport. Each accepted stream is
/// isolated behind one TURN server instance, and framing is bounded before the
/// upstream protocol parser sees a message.
pub(crate) struct StreamConn<S> {
    reader: Mutex<Option<ReadHalf<S>>>,
    writer: Mutex<Option<WriteHalf<S>>>,
    local: SocketAddr,
    peer: SocketAddr,
    close_tx: watch::Sender<bool>,
    close_rx: watch::Receiver<bool>,
    closed: AtomicBool,
    authenticated: AtomicBool,
}

impl<S> StreamConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    pub(crate) fn new(stream: S, local: SocketAddr, peer: SocketAddr) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        let (close_tx, close_rx) = watch::channel(false);
        Self {
            reader: Mutex::new(Some(reader)),
            writer: Mutex::new(Some(writer)),
            local,
            peer,
            close_tx,
            close_rx,
            closed: AtomicBool::new(false),
            authenticated: AtomicBool::new(false),
        }
    }

    pub(crate) fn authenticated(&self) {
        self.authenticated.store(true, Ordering::Release);
    }

    pub(crate) async fn wait_closed(&self) {
        let mut closed = self.close_rx.clone();
        if !*closed.borrow() {
            let _ = closed.changed().await;
        }
    }

    fn close_error() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "TURN stream is closed")
    }

    fn mark_closed(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.close_tx.send_replace(true);
        }
    }
}

#[async_trait]
impl<S> Conn for StreamConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    async fn connect(&self, addr: SocketAddr) -> UtilResult<()> {
        if addr == self.peer {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TURN stream is preconnected to a different peer",
            )
            .into())
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> UtilResult<usize> {
        self.recv_from(buf).await.map(|(bytes, _)| bytes)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> UtilResult<(usize, SocketAddr)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Self::close_error().into());
        }
        let mut reader = self.reader.lock().await;
        let Some(reader) = reader.as_mut() else {
            return Err(Self::close_error().into());
        };
        let mut closed = self.close_rx.clone();
        let result = tokio::select! {
            biased;
            _ = closed.changed() => Err(Self::close_error()),
            result = timeout(if self.authenticated.load(Ordering::Acquire) { Duration::from_secs(600) } else { READ_TIMEOUT }, read_frame(reader, buf)) => match result {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "TURN stream read deadline elapsed")),
            },
        };
        match result {
            Ok(bytes) => Ok((bytes, self.peer)),
            Err(error) => {
                self.mark_closed();
                Err(error.into())
            }
        }
    }

    async fn send(&self, buf: &[u8]) -> UtilResult<usize> {
        self.send_to(buf, self.peer).await
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> UtilResult<usize> {
        if target != self.peer || self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TURN stream peer mismatch or close",
            )
            .into());
        }
        let mut writer = self.writer.lock().await;
        let Some(writer) = writer.as_mut() else {
            return Err(Self::close_error().into());
        };
        let mut closed = self.close_rx.clone();
        let result = tokio::select! {
            biased;
            _ = closed.changed() => Err(Self::close_error()),
            result = timeout(WRITE_TIMEOUT, writer.write_all(buf)) => match result {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "TURN stream write deadline elapsed")),
            },
        };
        match result {
            Ok(()) => Ok(buf.len()),
            Err(error) => {
                self.mark_closed();
                Err(error.into())
            }
        }
    }

    fn local_addr(&self) -> UtilResult<SocketAddr> {
        Ok(self.local)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.peer)
    }

    async fn close(&self) -> UtilResult<()> {
        self.mark_closed();
        let mut reader = self.reader.lock().await;
        reader.take();
        drop(reader);
        let mut writer = self.writer.lock().await;
        if let Some(mut writer) = writer.take() {
            let _ = writer.shutdown().await;
        }
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

async fn read_frame<R>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let frame_type = header[0] & 0xc0;
    let content_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let frame_len = match frame_type {
        0x00 => {
            if content_len % 4 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid STUN stream frame length",
                ));
            }
            20usize.checked_add(content_len)
        }
        0x40 => 4usize.checked_add(align4(content_len)),
        _ => None,
    }
    .filter(|length| *length <= MAX_TURN_FRAME && *length <= buffer.len())
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TURN stream frame exceeds limit",
        )
    })?;

    buffer[..4].copy_from_slice(&header);
    reader.read_exact(&mut buffer[4..frame_len]).await?;
    Ok(frame_len)
}

fn align4(length: usize) -> usize {
    length.saturating_add(3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn empty_and_partial_unauthenticated_frames_reach_a_fixed_deadline() -> io::Result<()> {
        for partial in [vec![], vec![0], vec![0, 0, 0, 4, 0, 0]] {
            let (mut peer, stream) = tokio::io::duplex(128);
            peer.write_all(&partial).await?;
            let address = SocketAddr::from(([127, 0, 0, 1], 12345));
            let connection = StreamConn::new(stream, address, address);
            let started = tokio::time::Instant::now();
            let mut buffer = [0; 128];
            assert!(connection.recv_from(&mut buffer).await.is_err());
            assert_eq!(started.elapsed(), READ_TIMEOUT);
            assert!(connection.closed.load(Ordering::Acquire));
        }
        Ok(())
    }

    #[tokio::test]
    async fn channel_data_stream_frames_include_rfc_padding() -> io::Result<()> {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        let frame = [
            0x40, 0x01, 0x00, 0x05, // channel and unpadded payload length
            b'h', b'e', b'l', b'l', b'o', 0, 0, 0, // payload plus stream padding
        ];
        writer.write_all(&frame).await?;
        let mut buffer = [0; 32];
        let read = read_frame(&mut reader, &mut buffer).await?;
        assert_eq!(read, frame.len());
        assert_eq!(&buffer[..read], &frame);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_invalid_and_oversized_stream_frame_headers() -> io::Result<()> {
        for header in [
            [0x80, 0, 0, 0],       // not a STUN or ChannelData frame
            [0, 0, 0, 2],          // STUN lengths must be four-byte aligned
            [0x40, 0, 0xff, 0xff], // frame does not fit in this receive buffer
        ] {
            let (mut writer, mut reader) = tokio::io::duplex(8);
            writer.write_all(&header).await?;
            let mut buffer = [0; 8];
            assert!(read_frame(&mut reader, &mut buffer).await.is_err());
        }
        Ok(())
    }
}
