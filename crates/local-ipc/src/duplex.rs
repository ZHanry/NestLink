//! Independent bounded read/write ownership after the authenticated handshake.
//! Dropping a partial operation poisons the complete channel, never resumes a
//! header on its half-written body. The slot lives until both halves are gone.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
struct Shared {
    poisoned: AtomicBool,
    cancel: watch::Sender<bool>,
    _slot: Option<OwnedSemaphorePermit>,
}
pub struct LocalRead {
    read: tokio::io::ReadHalf<tokio_rustls::TlsStream<TcpStream>>,
    shared: Arc<Shared>,
    stopped: Option<watch::Receiver<bool>>,
}
pub struct LocalWrite {
    write: tokio::io::WriteHalf<tokio_rustls::TlsStream<TcpStream>>,
    shared: Arc<Shared>,
    stopped: Option<watch::Receiver<bool>>,
}
pub struct LocalDuplexOwner {
    shared: Arc<Shared>,
}
impl Drop for LocalDuplexOwner {
    fn drop(&mut self) {
        self.shared.poisoned.store(true, Ordering::Release);
        self.shared.cancel.send_replace(true);
    }
}
struct Operation(Arc<Shared>, bool);
impl Drop for Operation {
    fn drop(&mut self) {
        if !self.1 {
            self.0.poisoned.store(true, Ordering::Release);
            self.0.cancel.send_replace(true);
        }
    }
}
impl LocalStream {
    pub fn into_duplex(self) -> Result<(LocalRead, LocalWrite, LocalDuplexOwner)> {
        if self.failed
            || self.binary_mode
            || self.video_read_remaining.is_some()
            || self.video_write_remaining.is_some()
        {
            return Err(Error::Stopped);
        }
        let shared = Arc::new(Shared {
            poisoned: AtomicBool::new(false),
            cancel: watch::channel(false).0,
            _slot: self._slot,
        });
        let (read, write) = tokio::io::split(self.stream);
        Ok((
            LocalRead {
                read,
                shared: shared.clone(),
                stopped: self.stopped.clone(),
            },
            LocalWrite {
                write,
                shared: shared.clone(),
                stopped: self.stopped,
            },
            LocalDuplexOwner { shared },
        ))
    }
}
impl LocalRead {
    /// One-way media peers send no bytes. Observe EOF without an idle timeout;
    /// daemon stop and the retained owner still cancel this wait immediately.
    pub async fn wait_closed(&mut self) -> Result<()> {
        let mut cancel = self.shared.cancel.subscribe();
        let stopped = self.stopped.as_mut();
        tokio::select! {biased;
            _=wait_stopped(&mut cancel)=>Err(Error::Stopped),
            _=async{if let Some(stop)=stopped{wait_stopped(stop).await}else{std::future::pending::<()>().await}}=>Err(Error::Stopped),
            _=self.read.read_u8()=>Err(Error::Stopped),
        }
    }
    pub async fn receive_bytes(&mut self, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
        if self.shared.poisoned.load(Ordering::Acquire) || maximum == 0 || maximum > 8 * 1024 * 1024
        {
            return Err(Error::Stopped);
        }
        let mut guard = Operation(self.shared.clone(), false);
        let mut cancel = self.shared.cancel.subscribe();
        let first = tokio::select! {biased;
            _=wait_stopped(&mut cancel)=>return Err(Error::Stopped),
            _=async{if let Some(stop)=self.stopped.as_mut(){wait_stopped(stop).await}else{std::future::pending::<()>().await}}=>return Err(Error::Stopped),
            first=self.read.read_u8()=>first.map_err(Error::Io)?,
        };
        let op = async {
            let mut prefix = [first, 0, 0, 0];
            self.read.read_exact(&mut prefix[1..]).await?;
            let n = u32::from_be_bytes(prefix) as usize;
            if n == 0 || n > maximum {
                return Err(io::Error::other("duplex frame budget exceeded"));
            }
            let mut bytes = Zeroizing::new(vec![0; n]);
            for chunk in bytes.chunks_mut(VIDEO_CHUNK_BYTES) {
                self.read.read_exact(chunk).await?;
            }
            Ok(bytes)
        };
        let result = tokio::select! {biased; _=wait_stopped(&mut cancel)=>Err(Error::Stopped), result=checked_io_with_budget(op,self.stopped.as_mut(),VIDEO_FRAME_BUDGET)=>result};
        guard.1 = result.is_ok();
        result
    }
    pub async fn receive<T: DeserializeOwned>(&mut self) -> Result<T> {
        let bytes = self.receive_bytes(4096).await?;
        serde_json::from_slice(&bytes).map_err(|_| Error::Protocol)
    }
}
impl LocalWrite {
    pub async fn send_bytes(
        &mut self,
        bytes: &[u8],
        mut authorized: impl FnMut() -> bool,
    ) -> Result<()> {
        if self.shared.poisoned.load(Ordering::Acquire)
            || bytes.is_empty()
            || bytes.len() > 8 * 1024 * 1024
            || !authorized()
        {
            return Err(Error::Stopped);
        }
        let mut guard = Operation(self.shared.clone(), false);
        let mut cancel = self.shared.cancel.subscribe();
        let op = async {
            self.write.write_u32(bytes.len() as u32).await?;
            for chunk in bytes.chunks(VIDEO_CHUNK_BYTES) {
                if !authorized() {
                    return Err(io::Error::other("duplex authority revoked"));
                }
                self.write.write_all(chunk).await?;
            }
            self.write.flush().await
        };
        let result = tokio::select! {biased; _=wait_stopped(&mut cancel)=>Err(Error::Stopped), result=checked_io_with_budget(op,self.stopped.as_mut(),VIDEO_FRAME_BUDGET)=>result};
        guard.1 = result.is_ok();
        result
    }
    pub async fn send<T: Serialize>(&mut self, value: &T) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::Protocol)?);
        if bytes.len() > 4096 {
            return Err(Error::Protocol);
        }
        self.send_bytes(&bytes, || true).await
    }
}
