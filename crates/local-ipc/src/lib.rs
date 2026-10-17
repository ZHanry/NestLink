//! Bounded, mutually pinned TLS 1.3 IPC between a normal UI and its user daemon.
//! It has a distinct ALPN and purpose-derived keys, and grants no remote permissions.
use nestlink_identity::InstallationIdentity;
use serde::{Serialize, de::DeserializeOwned};
use std::{io, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
};
use zeroize::Zeroizing;
pub mod instance;
pub mod maintenance;
mod state;
#[cfg(test)]
mod tests;
pub use state::initialize_directory;

pub const VERSION: u16 = 1;
pub const ALPN: &[u8] = b"nestlink-ipc/15";
pub const FRAME_BYTES: usize = 1_048_576;
pub const VIDEO_HEADER_BYTES: usize = 140;
pub const VIDEO_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
pub const VIDEO_FRAME_BYTES: usize = VIDEO_HEADER_BYTES + VIDEO_PAYLOAD_BYTES;
pub const VIDEO_CHUNK_BYTES: usize = 64 * 1024;
const HANDSHAKE_BUDGET: Duration = Duration::from_secs(2);
const IO_BUDGET: Duration = Duration::from_secs(20);
const VIDEO_CHUNK_BUDGET: Duration = Duration::from_secs(2);
const VIDEO_FRAME_BUDGET: Duration = Duration::from_secs(5);
const CLIENTS: usize = 8;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("local daemon I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("local daemon authentication failed")]
    Authentication,
    #[error("local daemon message invalid or exceeds its budget")]
    Protocol,
    #[error("NestLink installation maintenance is active")]
    Maintenance,
    #[error("a local daemon is already running")]
    AlreadyRunning,
    #[error("local daemon operation timed out")]
    Timeout,
    #[error("local daemon has stopped")]
    Stopped,
}
pub(crate) struct IdentityPair {
    server: InstallationIdentity,
    client: InstallationIdentity,
}
#[derive(Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    version: u16,
    runtime_id: String,
}
pub(crate) fn valid_runtime_id(value: &str) -> bool {
    nestlink_protocol::valid_id(value)
}

pub struct LocalServer {
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    runtime_id: String,
    slots: Arc<Semaphore>,
    stopped: watch::Sender<bool>,
    _state: state::StateLease,
}
impl LocalServer {
    pub async fn bind(directory: &Path) -> Result<Self> {
        let runtime_id = nestlink_auth::random_id();
        let state = state::StateLease::acquire(directory, &runtime_id)?;
        let keys = state::identities(directory, true)?;
        let mut tls =
            nestlink_transport_stream::tls::server_config(&keys.server, keys.client.fingerprint())
                .map_err(|_| Error::Authentication)?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        state.publish(listener.local_addr()?)?;
        let (stopped, _) = watch::channel(false);
        Ok(Self {
            listener,
            acceptor: Arc::new(tls).into(),
            runtime_id,
            slots: Arc::new(Semaphore::new(CLIENTS)),
            stopped,
            _state: state,
        })
    }
    pub fn runtime_id(&self) -> &str {
        &self.runtime_id
    }
    /// Accept a socket without letting its TLS handshake hold up subsequent
    /// clients. Admission is fixed before creating any handshake task.
    pub async fn accept(&self) -> Result<PendingConnection> {
        let (socket, address) = self.listener.accept().await?;
        if !address.ip().is_loopback() {
            return Err(Error::Authentication);
        }
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Protocol)?;
        socket.set_nodelay(true)?;
        Ok(PendingConnection {
            socket,
            acceptor: self.acceptor.clone(),
            runtime_id: self.runtime_id.clone(),
            stopped: self.stopped.subscribe(),
            slot,
        })
    }
    pub fn stop(&self) {
        self.stopped.send_replace(true);
    }
}
impl Drop for LocalServer {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct PendingConnection {
    socket: TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    runtime_id: String,
    stopped: watch::Receiver<bool>,
    slot: OwnedSemaphorePermit,
}
impl PendingConnection {
    pub async fn authenticate(mut self) -> Result<LocalStream> {
        let handshake = tokio::time::timeout(HANDSHAKE_BUDGET, self.acceptor.accept(self.socket));
        let stream = tokio::select! {
            biased;
            _ = wait_stopped(&mut self.stopped) => return Err(Error::Stopped),
            result = handshake => result.map_err(|_| Error::Timeout)?.map_err(|_| Error::Authentication)?,
        };
        if stream.get_ref().1.alpn_protocol() != Some(ALPN) {
            return Err(Error::Authentication);
        }
        let mut stream = LocalStream {
            stream: stream.into(),
            runtime_id: self.runtime_id.clone(),
            failed: false,
            binary_mode: false,
            video_write_remaining: None,
            video_read_remaining: None,
            stopped: Some(self.stopped),
            _slot: Some(self.slot),
        };
        stream
            .send(&Hello {
                version: VERSION,
                runtime_id: self.runtime_id,
            })
            .await?;
        Ok(stream)
    }
}

pub struct LocalStream {
    stream: tokio_rustls::TlsStream<TcpStream>,
    runtime_id: String,
    failed: bool,
    binary_mode: bool,
    video_write_remaining: Option<usize>,
    video_read_remaining: Option<usize>,
    stopped: Option<watch::Receiver<bool>>,
    _slot: Option<OwnedSemaphorePermit>,
}
impl LocalStream {
    pub async fn connect(directory: &Path) -> Result<Self> {
        let endpoint = state::endpoint(directory)?;
        let keys = state::identities(directory, false)?;
        let mut tls =
            nestlink_transport_stream::tls::client_config(&keys.client, keys.server.fingerprint())
                .map_err(|_| Error::Authentication)?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let stream = tokio::time::timeout(HANDSHAKE_BUDGET, async {
            // Keep endpoint/socket readiness errors distinct from TLS failures:
            // callers may retry a refused or missing local daemon endpoint, but
            // must not retry an authentication mismatch as if it were startup.
            let socket = TcpStream::connect(endpoint.address)
                .await
                .map_err(Error::Io)?;
            socket.set_nodelay(true).map_err(Error::Io)?;
            let name = rustls::pki_types::ServerName::try_from("peer.nestlink.invalid")
                .map_err(|_| Error::Authentication)?;
            tokio_rustls::TlsConnector::from(Arc::new(tls))
                .connect(name, socket)
                .await
                .map_err(|_| Error::Authentication)
        })
        .await
        .map_err(|_| Error::Timeout)??;
        if stream.get_ref().1.alpn_protocol() != Some(ALPN) {
            return Err(Error::Authentication);
        }
        let mut connection = Self {
            stream: stream.into(),
            runtime_id: endpoint.runtime_id.clone(),
            failed: false,
            binary_mode: false,
            video_write_remaining: None,
            video_read_remaining: None,
            stopped: None,
            _slot: None,
        };
        let hello: Hello = connection.receive().await?;
        if hello.version != VERSION || hello.runtime_id != endpoint.runtime_id {
            return Err(Error::Authentication);
        }
        Ok(connection)
    }
    pub fn runtime_id(&self) -> &str {
        &self.runtime_id
    }
    pub async fn send<T: Serialize>(&mut self, value: &T) -> Result<()> {
        if self.failed || self.binary_mode {
            return Err(Error::Stopped);
        }
        // JSON is a transient private transport buffer: never Debugged/logged.
        let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::Protocol)?);
        if bytes.is_empty() || bytes.len() > FRAME_BYTES {
            return Err(Error::Protocol);
        }
        // Mark terminal before the first await. Dropping this future mid-frame
        // cannot leave a reusable stream with an ambiguous partial write.
        self.failed = true;
        let operation = async {
            self.stream.write_u32(bytes.len() as u32).await?;
            self.stream.write_all(&bytes).await?;
            self.stream.flush().await
        };
        let result = checked_io(operation, self.stopped.as_mut()).await;
        self.failed = result.is_err();
        result
    }
    pub async fn receive<T: DeserializeOwned>(&mut self) -> Result<T> {
        if self.failed || self.binary_mode {
            return Err(Error::Stopped);
        }
        // Cancellation after any prefix/body byte is terminal, including when
        // the caller stops polling before the transport budget itself expires.
        self.failed = true;
        let operation = async {
            let size = self.stream.read_u32().await? as usize;
            if size == 0 || size > FRAME_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IPC frame size invalid",
                ));
            }
            let mut bytes = Zeroizing::new(vec![0; size]);
            self.stream.read_exact(&mut bytes).await?;
            serde_json::from_slice(&bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "IPC message invalid"))
        };
        let result = checked_io(operation, self.stopped.as_mut()).await;
        self.failed = result.is_err();
        result
    }

    /// Begins a permanently binary-only native-video frame. JSON framing
    /// remains capped by `FRAME_BYTES`; media uses a separate fixed budget.
    pub async fn send_video_header(&mut self, header: &[u8], payload_bytes: usize) -> Result<()> {
        if self.failed
            || header.len() != VIDEO_HEADER_BYTES
            || payload_bytes > VIDEO_PAYLOAD_BYTES
            || self.video_write_remaining.is_some()
        {
            return Err(Error::Protocol);
        }
        let body_bytes = header
            .len()
            .checked_add(payload_bytes)
            .filter(|bytes| *bytes <= VIDEO_FRAME_BYTES)
            .ok_or(Error::Protocol)?;
        self.binary_mode = true;
        self.failed = true;
        let operation = async {
            self.stream.write_u32(body_bytes as u32).await?;
            self.stream.write_all(header).await?;
            self.stream.flush().await
        };
        let result =
            checked_io_with_budget(operation, self.stopped.as_mut(), VIDEO_CHUNK_BUDGET).await;
        self.failed = result.is_err();
        if result.is_ok() && payload_bytes > 0 {
            self.video_write_remaining = Some(payload_bytes);
        }
        result
    }

    /// Sends one bounded payload chunk. A cancelled or timed-out chunk poisons
    /// the stream so a partial frame cannot be reused as another message.
    pub async fn send_video_payload_chunk(&mut self, bytes: &[u8]) -> Result<()> {
        let Some(remaining) = self.video_write_remaining else {
            return Err(Error::Protocol);
        };
        if self.failed
            || bytes.is_empty()
            || bytes.len() > VIDEO_CHUNK_BYTES
            || bytes.len() > remaining
        {
            return Err(Error::Protocol);
        }
        self.failed = true;
        let final_chunk = bytes.len() == remaining;
        let operation = async {
            self.stream.write_all(bytes).await?;
            if final_chunk {
                self.stream.flush().await?;
            }
            Ok::<_, io::Error>(())
        };
        let result =
            checked_io_with_budget(operation, self.stopped.as_mut(), VIDEO_CHUNK_BUDGET).await;
        self.failed = result.is_err();
        if result.is_ok() {
            self.video_write_remaining =
                (bytes.len() < remaining).then_some(remaining - bytes.len());
        }
        result
    }

    /// Reads a frame prefix and fixed header without allocating pixel memory.
    /// The caller validates the header before requesting the payload.
    pub async fn receive_video_header(&mut self) -> Result<([u8; VIDEO_HEADER_BYTES], usize)> {
        if self.failed || self.video_read_remaining.is_some() {
            return Err(Error::Protocol);
        }
        self.binary_mode = true;
        self.failed = true;
        let operation = async {
            let body_bytes = self.stream.read_u32().await? as usize;
            if !(VIDEO_HEADER_BYTES..=VIDEO_FRAME_BYTES).contains(&body_bytes) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native video frame size invalid",
                ));
            }
            let mut header = [0_u8; VIDEO_HEADER_BYTES];
            self.stream.read_exact(&mut header).await?;
            Ok::<_, io::Error>((header, body_bytes - VIDEO_HEADER_BYTES))
        };
        let result =
            checked_io_with_budget(operation, self.stopped.as_mut(), VIDEO_CHUNK_BUDGET).await;
        self.failed = result.is_err();
        if let Ok((_, payload_bytes)) = &result
            && *payload_bytes > 0
        {
            self.video_read_remaining = Some(*payload_bytes);
        }
        result
    }

    /// Reads the payload from the most recent frame header into one zeroizing
    /// allocation, bounded to 64 MiB and a five-second frame budget.
    pub async fn receive_video_payload(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let Some(payload_bytes) = self.video_read_remaining else {
            return Err(Error::Protocol);
        };
        if self.failed || payload_bytes > VIDEO_PAYLOAD_BYTES {
            return Err(Error::Protocol);
        }
        self.failed = true;
        let operation = async {
            let mut payload = Zeroizing::new(vec![0_u8; payload_bytes]);
            self.stream.read_exact(&mut payload).await?;
            Ok::<_, io::Error>(payload)
        };
        let result =
            checked_io_with_budget(operation, self.stopped.as_mut(), VIDEO_FRAME_BUDGET).await;
        self.failed = result.is_err();
        if result.is_ok() {
            self.video_read_remaining = None;
        }
        result
    }
}
async fn wait_stopped(stopped: &mut watch::Receiver<bool>) {
    loop {
        if *stopped.borrow_and_update() {
            return;
        }
        if stopped.changed().await.is_err() {
            return;
        }
    }
}
async fn checked_io<T>(
    operation: impl std::future::Future<Output = io::Result<T>>,
    stopped: Option<&mut watch::Receiver<bool>>,
) -> Result<T> {
    checked_io_with_budget(operation, stopped, IO_BUDGET).await
}
async fn checked_io_with_budget<T>(
    operation: impl std::future::Future<Output = io::Result<T>>,
    stopped: Option<&mut watch::Receiver<bool>>,
    budget: Duration,
) -> Result<T> {
    let operation = tokio::time::timeout(budget, operation);
    let result = if let Some(stopped) = stopped {
        tokio::select! {
            biased;
            _ = wait_stopped(stopped) => return Err(Error::Stopped),
            result = operation => result,
        }
    } else {
        operation.await
    };
    Ok(result.map_err(|_| Error::Timeout)??)
}
