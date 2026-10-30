//! Shared bounded dispatch for independent QUIC channels and framed TLS/WSS.
use crate::{AuthorizedConnection, LeaseControl, RemoteError, StopReport, lease_io, permission};
use nestlink_session::StopReason;
use nestlink_transport_stream::{Channel, Frame, write_frame};
use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::watch,
    task::JoinHandle,
};
use zeroize::Zeroize;

mod external;
pub use external::{ExternalChannelRuntime, ExternalDataChannelPort, ExternalDataEnvelope};

/// A producer's original local disclosure approval. This observes existing
/// authority and must not refresh a lease, run blocking OS I/O or acquire any
/// queue lock. It is checked before insertion and immediately before writing.
pub trait DeliveryGuard: Send + Sync {
    fn check(&self) -> io::Result<()>;
}
/// An actual carrier cleanup owner. Returning success certifies its tasks have
/// joined; transport adapters must retain unfinished handles across cancellation.
pub trait TransportOwner: Send + Sync {
    fn request_close(&self);
    fn close_and_wait(&mut self, deadline: tokio::time::Instant)
        -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>>;
}
struct FileGuard(Arc<dyn crate::files::FileReadConsent>);
impl DeliveryGuard for FileGuard {
    fn check(&self) -> io::Result<()> {
        self.0.check()
    }
}

// Round-robin keeps files progressing under an input flood. Media buffers
// may discard stale independent audio packets; reference-dependent encoded
// video and reliable input/file/clipboard producers wait for bounded capacity.
pub(crate) const CHANNELS: [Channel; 8] = [
    Channel::Input,
    Channel::VideoFeedback,
    Channel::Audio,
    Channel::Video,
    Channel::FileRead,
    Channel::FileWrite,
    Channel::ClipboardRead,
    Channel::ClipboardWrite,
];
const CAPACITY: [usize; 8] = [64, 8, 8, 1, 4, 4, 1, 1];
const AUDIO_AGE: Duration = Duration::from_millis(100);
/// A reliable reference may never be skipped and followed by its deltas.
/// Expiry therefore terminates this generation; recovery needs fresh proof.
const VIDEO_WRITE_AGE: Duration = Duration::from_millis(500);

pub(crate) async fn write_media_bounded<W: AsyncWrite + Unpin>(
    write: &mut W,
    channel: Channel,
    payload: &[u8],
    arrived: Instant,
) -> io::Result<()> {
    if channel != Channel::Video {
        return write_frame(write, channel, payload).await;
    }
    let deadline = arrived + VIDEO_WRITE_AGE;
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "video send deadline exhausted",
        ));
    }
    tokio::time::timeout_at(deadline.into(), write_frame(write, channel, payload))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "video send deadline exhausted"))?
}
#[cfg(test)]
#[path = "queues/file_disclosure_tests.rs"]
mod file_disclosure_tests;
#[cfg(test)]
#[path = "queues/cleanup_tests.rs"]
mod cleanup_tests;
pub(crate) struct Queued {
    pub(crate) frame: Frame,
    pub(crate) arrived: Instant,
    pub(crate) file_disclosure: Option<Disclosure>,
    pub(crate) delivery_guard: Option<Arc<dyn DeliveryGuard>>,
}
#[derive(Clone)]
pub(crate) struct Disclosure {
    check: Arc<dyn DeliveryGuard>,
    denied: Vec<u8>,
    expired: Vec<u8>,
    // Once observed, a failed original approval cannot resurrect plaintext
    // during capacity waits, even if a buggy producer later reports success.
    rejected: Arc<AtomicU8>,
}
impl Disclosure {
    fn fallback(&self) -> Option<&[u8]> {
        if self.rejected.load(Ordering::Acquire) == 0
            && let Err(error) = self.check.check()
        {
            let reason = if error.kind() == io::ErrorKind::TimedOut {
                2
            } else {
                1
            };
            let _ = self
                .rejected
                .compare_exchange(0, reason, Ordering::AcqRel, Ordering::Acquire);
        }
        match self.rejected.load(Ordering::Acquire) {
            1 => Some(&self.denied),
            2 => Some(&self.expired),
            _ => None,
        }
    }
}
impl Queued {
    /// Called without an intervening await immediately before a writer starts
    /// this frame. A stale page becomes the matching bounded business failure.
    pub(crate) fn check_file_delivery(&mut self) {
        if let Some(disclosure) = &self.file_disclosure
            && let Some(fallback) = disclosure.fallback()
        {
            self.frame.payload.zeroize();
            self.frame.payload = fallback.to_vec();
        }
    }
    pub(crate) fn check_delivery(&mut self) -> bool {
        if self
            .delivery_guard
            .as_ref()
            .is_some_and(|guard| guard.check().is_err())
        {
            self.frame.payload.zeroize();
            return false;
        }
        true
    }
    pub(crate) fn delivery_guard(&self) -> Option<Arc<dyn DeliveryGuard>> {
        self.delivery_guard.clone()
    }
    fn into_frame(mut self) -> Frame {
        Frame {
            channel: self.frame.channel,
            payload: std::mem::take(&mut self.frame.payload),
        }
    }
}
impl Drop for Queued {
    fn drop(&mut self) {
        if matches!(
            self.frame.channel,
            Channel::Video | Channel::Audio | Channel::ClipboardRead | Channel::ClipboardWrite
        ) {
            self.frame.payload.zeroize();
        }
    }
}
struct State {
    channels: [VecDeque<Queued>; 8],
    claimed: [bool; 8],
    retired: [bool; 8],
    cursor: usize,
    closed: bool,
}
pub(crate) struct Queue {
    state: Mutex<State>,
    updates: watch::Sender<u64>,
}
impl Queue {
    pub(crate) fn new() -> Arc<Self> {
        let (updates, _) = watch::channel(0);
        Arc::new(Self {
            state: Mutex::new(State {
                channels: std::array::from_fn(|_| VecDeque::new()),
                claimed: [false; 8],
                retired: [false; 8],
                cursor: 0,
                closed: false,
            }),
            updates,
        })
    }
    fn wake(&self) {
        self.updates.send_modify(|v| *v = v.saturating_add(1));
    }
    pub(crate) fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            for queue in &mut state.channels {
                queue.clear();
            }
        }
        self.wake();
    }
    fn discard(&self, channel: Channel) -> io::Result<()> {
        let index = CHANNELS
            .iter()
            .position(|candidate| *candidate == channel)
            .ok_or_else(|| io::Error::other("channel queue missing"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("channel queue poisoned"))?;
        state.channels[index].clear();
        drop(state);
        self.wake();
        Ok(())
    }
    fn retire_file_channel(&self, channel: Channel) -> io::Result<()> {
        if !matches!(channel, Channel::FileRead | Channel::FileWrite) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a file channel",
            ));
        }
        self.retire_auxiliary_channel(channel)
    }
    fn retire_auxiliary_channel(&self, channel: Channel) -> io::Result<()> {
        if !matches!(
            channel,
            Channel::FileRead
                | Channel::FileWrite
                | Channel::ClipboardRead
                | Channel::ClipboardWrite
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a retireable auxiliary channel",
            ));
        }
        let index = CHANNELS
            .iter()
            .position(|candidate| *candidate == channel)
            .ok_or_else(|| io::Error::other("auxiliary channel missing"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("channel queue poisoned"))?;
        // Preserve the claim forever. Late file replies neither enter the
        // fallback consumer nor backpressure the other channels on TLS/WSS.
        state.retired[index] = true;
        state.channels[index].clear();
        drop(state);
        self.wake();
        Ok(())
    }
    pub(crate) async fn put(
        &self,
        lease: &LeaseControl,
        channel: Channel,
        payload: &[u8],
    ) -> Result<(), RemoteError> {
        self.put_at(lease, channel, payload, Instant::now()).await
    }
    pub(crate) async fn put_at(
        &self,
        lease: &LeaseControl,
        channel: Channel,
        payload: &[u8],
        arrived: Instant,
    ) -> Result<(), RemoteError> {
        self.put_guarded(lease, channel, payload, arrived, None, None)
            .await
    }
    async fn put_video_guarded(
        &self,
        lease: &LeaseControl,
        payload: &[u8],
        guard: Arc<dyn DeliveryGuard>,
    ) -> Result<(), RemoteError> {
        self.put_guarded(
            lease,
            Channel::Video,
            payload,
            Instant::now(),
            None,
            Some(guard),
        )
        .await
    }
    async fn put_guarded(
        &self,
        lease: &LeaseControl,
        channel: Channel,
        payload: &[u8],
        arrived: Instant,
        file_disclosure: Option<Disclosure>,
        delivery_guard: Option<Arc<dyn DeliveryGuard>>,
    ) -> Result<(), RemoteError> {
        let mut updates = self.updates.subscribe();
        loop {
            if self.try_put_guarded(
                lease,
                channel,
                payload,
                arrived,
                file_disclosure.clone(),
                delivery_guard.clone(),
            )? {
                return Ok(());
            }
            lease_io(
                async {
                    // Guarded capacity waits also observe an independent local
                    // direction revoke/deadline without waiting for queue progress.
                    if file_disclosure.is_some() || delivery_guard.is_some() {
                        tokio::select! {
                            result = updates.changed() => result.map_err(io::Error::other),
                            _ = tokio::time::sleep(Duration::from_millis(20)) => Ok(()),
                        }
                    } else {
                        updates.changed().await.map_err(io::Error::other)
                    }
                },
                lease,
            )
            .await?;
        }
    }
    fn try_put(
        &self,
        lease: &LeaseControl,
        channel: Channel,
        payload: &[u8],
        arrived: Instant,
    ) -> Result<bool, RemoteError> {
        self.try_put_guarded(lease, channel, payload, arrived, None, None)
    }
    fn try_put_guarded(
        &self,
        lease: &LeaseControl,
        channel: Channel,
        payload: &[u8],
        arrived: Instant,
        file_disclosure: Option<Disclosure>,
        delivery_guard: Option<Arc<dyn DeliveryGuard>>,
    ) -> Result<bool, RemoteError> {
        let index = CHANNELS
            .iter()
            .position(|c| *c == channel)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "reserved channel"))?;
        if payload.len() > channel.budget() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame exceeds channel budget",
            )
            .into());
        }
        // Local consent must be checked outside the business authorization
        // lock: producers may observe that same lease in their guard.
        let replacement = file_disclosure
            .as_ref()
            .and_then(Disclosure::fallback)
            .map(Vec::from);
        let payload = replacement.as_deref().unwrap_or(payload);
        if let Some(guard) = &delivery_guard {
            guard.check()?;
        }
        // Authorization and insertion are serialized with terminal stop.
        let inserted = lease.operation(permission(channel)?, || {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("channel queue poisoned"))?;
            if state.closed {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "channel queues closed",
                ));
            }
            if state.retired[index] {
                return Ok(true);
            }
            let queue = &mut state.channels[index];
            if channel == Channel::Audio && queue.len() == CAPACITY[index] {
                queue.pop_front();
            }
            if queue.len() == CAPACITY[index] {
                return Ok(false);
            }
            queue.push_back(Queued {
                frame: Frame {
                    channel,
                    payload: payload.to_vec(),
                },
                arrived,
                file_disclosure,
                delivery_guard,
            });
            Ok(true)
        })?;
        if inserted {
            self.wake();
        }
        Ok(inserted)
    }
    async fn take(
        &self,
        lease: &LeaseControl,
        selected: Option<Channel>,
    ) -> Result<Frame, RemoteError> {
        Ok(self.take_queued(lease, selected).await?.into_frame())
    }
    pub(crate) async fn take_queued(
        &self,
        lease: &LeaseControl,
        selected: Option<Channel>,
    ) -> Result<Queued, RemoteError> {
        let mut updates = self.updates.subscribe();
        loop {
            lease.remaining()?;
            let _ = updates.borrow_and_update();
            let (next, removed) = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| io::Error::other("channel queue poisoned"))?;
                if state.closed {
                    return Err(RemoteError::Stopped);
                }
                let mut next = None;
                let mut removed = false;
                for offset in 0..CHANNELS.len() {
                    let index = (state.cursor + offset) % CHANNELS.len();
                    if selected.map_or(state.claimed[index], |channel| CHANNELS[index] != channel) {
                        continue;
                    }
                    let queue = &mut state.channels[index];
                    while queue.front().is_some_and(|v| {
                        let age = match v.frame.channel {
                            Channel::Audio => Some(AUDIO_AGE),
                            _ => None,
                        };
                        age.is_some_and(|age| v.arrived.elapsed() >= age)
                    }) {
                        queue.pop_front();
                        removed = true;
                    }
                    if let Some(frame) = queue.pop_front() {
                        removed = true;
                        state.cursor = (index + 1) % CHANNELS.len();
                        next = Some(frame);
                        break;
                    }
                }
                (next, removed)
            };
            if removed {
                self.wake();
            }
            if let Some(mut frame) = next {
                lease.authorize(frame.frame.channel)?;
                frame.check_file_delivery();
                if !frame.check_delivery() {
                    continue;
                }
                return Ok(frame);
            }
            // Observe the version before the locked inspection: arrivals
            // between inspection and waiting cannot lose their notification.
            lease_io(
                async { updates.changed().await.map_err(io::Error::other) },
                lease,
            )
            .await?;
        }
    }
}

/// Owns both transport halves in independent tasks. Callers never interrupt
/// a partial wire frame by dropping a send/receive future.
pub struct ChannelRuntime {
    renewal: Option<crate::native_renewal::NativeRenewalPort>,
    lease: LeaseControl,
    incoming: Arc<Queue>,
    outgoing: Arc<Queue>,
    tasks: Vec<JoinHandle<Result<(), RemoteError>>>,
    mode: TransportMode,
    connection: Option<quinn::Connection>,
    _endpoint: Option<quinn::Endpoint>,
    pub(crate) transport_owner: Option<Box<dyn TransportOwner>>,
    cleanup_deadline: Option<tokio::time::Instant>,
    cleanup_failure: Option<io::ErrorKind>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportMode {
    /// TLS/TCP or inner TLS/WSS retains wire head-of-line blocking.
    ReliableByteStream,
    /// Independent reliable business streams; approved Audio uses datagrams.
    QuicStreamsAndDatagrams,
}
#[derive(Clone)]
pub struct ChannelSender {
    lease: LeaseControl,
    outgoing: Arc<Queue>,
}
/// Exclusive incoming consumer of one business channel. The fallback receiver
/// skips this channel; dropping its owner stops the whole approved session.
/// This is local dispatch isolation, not an independent stream on TCP/WSS.
pub struct ChannelReceiver {
    lease: LeaseControl,
    incoming: Arc<Queue>,
    channel: Channel,
    stop_on_drop: bool,
}
impl ChannelReceiver {
    /// Return the authority and channel identity carried by this exclusive
    /// claim. Typed media attachments use these together so callers cannot
    /// combine a receiver from one session with a lease from another.
    pub fn lease_control(&self) -> LeaseControl {
        self.lease.clone()
    }
    pub fn channel(&self) -> Channel {
        self.channel
    }
    pub async fn receive(&mut self) -> Result<Frame, RemoteError> {
        self.incoming.take(&self.lease, Some(self.channel)).await
    }
    /// Only the file client can release an idle, protocol-clean claim without
    /// ending viewing. No generic video/input consumer can bypass owner Drop.
    pub(crate) fn retire_file_reader(mut self) -> Result<(), RemoteError> {
        if self.channel != Channel::FileRead {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a file reader").into());
        }
        self.incoming.retire_file_channel(Channel::FileRead)?;
        self.stop_on_drop = false;
        Ok(())
    }
    /// The upload client has cancelled or committed all of its transfers.
    /// Preserve the claim so late acknowledgements cannot reach another owner.
    pub(crate) fn retire_file_writer(mut self) -> Result<(), RemoteError> {
        if self.channel != Channel::FileWrite {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a file writer").into());
        }
        self.incoming.retire_file_channel(Channel::FileWrite)?;
        self.stop_on_drop = false;
        Ok(())
    }
    /// A typed clipboard owner has consumed all replies and ended its local
    /// consent. Retire this exact direction; it is never reassigned to a new UI.
    pub(crate) fn retire_clipboard(mut self) -> Result<(), RemoteError> {
        if !matches!(
            self.channel,
            Channel::ClipboardRead | Channel::ClipboardWrite
        ) {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "not a clipboard receiver").into(),
            );
        }
        self.incoming.retire_auxiliary_channel(self.channel)?;
        self.stop_on_drop = false;
        Ok(())
    }
}
impl Drop for ChannelReceiver {
    fn drop(&mut self) {
        if self.stop_on_drop {
            let _ = self.lease.stop_if_running(StopReason::ExplicitExit);
        }
    }
}
pub(crate) struct StopOnDrop(pub(crate) LeaseControl);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        let _ = self.0.stop_if_running(StopReason::Revoked);
    }
}
// Advisory only: peers must still obtain fresh control-plane two-party proof.
pub(crate) const RETRY_CLOSE_CODE: u32 = 0x4e01;
pub(crate) fn close_quic(connection: &quinn::Connection, lease: &LeaseControl) {
    let reports = lease.subscribe_stopped();
    let retry = reports.borrow().is_some_and(|report| {
        matches!(
            report.reason,
            StopReason::TransportLost | StopReason::NetworkChanged
        )
    });
    connection.close(
        if retry { RETRY_CLOSE_CODE } else { 0 }.into(),
        b"session stopped",
    );
}
pub(crate) struct CloseQuicOnDrop(pub(crate) quinn::Connection, pub(crate) LeaseControl);
impl Drop for CloseQuicOnDrop {
    fn drop(&mut self) {
        close_quic(&self.0, &self.1);
    }
}
pub(crate) fn stop_io_result<T>(lease: &LeaseControl, result: &Result<T, RemoteError>) {
    fn quic_reason(error: &quinn::ConnectionError) -> StopReason {
        match error {
            quinn::ConnectionError::TimedOut | quinn::ConnectionError::Reset => {
                StopReason::TransportLost
            }
            quinn::ConnectionError::ApplicationClosed(close)
                if close.error_code == quinn::VarInt::from_u32(RETRY_CLOSE_CODE) =>
            {
                StopReason::TransportLost
            }
            quinn::ConnectionError::ApplicationClosed(_)
            | quinn::ConnectionError::LocallyClosed => StopReason::Revoked,
            _ => StopReason::ProtocolViolation,
        }
    }
    let reason = match result {
        Err(RemoteError::Io(error)) => {
            let inner = error.get_ref();
            if let Some(error) = inner.and_then(|v| v.downcast_ref::<quinn::ConnectionError>()) {
                quic_reason(error)
            } else if let Some(quinn::ReadError::ConnectionLost(error)) =
                inner.and_then(|v| v.downcast_ref::<quinn::ReadError>())
            {
                quic_reason(error)
            } else if let Some(quinn::WriteError::ConnectionLost(error)) =
                inner.and_then(|v| v.downcast_ref::<quinn::WriteError>())
            {
                quic_reason(error)
            } else {
                match error.kind() {
                    io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::TimedOut => StopReason::TransportLost,
                    io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => {
                        StopReason::ProtocolViolation
                    }
                    _ => StopReason::Revoked,
                }
            }
        }
        Err(RemoteError::Cleanup(_)) => StopReason::PlatformChanged,
        Err(RemoteError::Authorization(_) | RemoteError::Stopped) => StopReason::Revoked,
        Ok(_) => StopReason::Revoked,
    };
    // The lease retains an earlier revoke/network/expiry/exit reason.
    if reason == StopReason::Revoked {
        // A stopped lease's authorization/queue/cleanup observation adds no
        // fresh revocation. Keep genuine direct revokes and protocol errors
        // sticky, while synthetic teardown preserves a retryable first stop.
        let _ = lease.stop_if_running(reason);
    } else {
        let _ = lease.stop(reason);
    }
}
impl ChannelSender {
    /// Return the authority carried by this sender. Media attachments use the
    /// sender itself as the transport capability and derive their lease from
    /// this same object.
    pub fn lease_control(&self) -> LeaseControl {
        self.lease.clone()
    }
    pub(crate) async fn send_checked_file_read(
        &self,
        payload: &[u8],
        check: Arc<dyn crate::files::FileReadConsent>,
        denied: Vec<u8>,
        expired: Vec<u8>,
    ) -> Result<(), RemoteError> {
        self.send_checked_file(Channel::FileRead, payload, check, denied, expired)
            .await
    }
    /// An upload chunk retains its source approval until the transport writer
    /// starts it. Revocation or the original operation deadline replaces the
    /// chunk with its exact transfer/sequence cancellation request.
    pub(crate) async fn send_checked_file_write(
        &self,
        payload: &[u8],
        check: Arc<dyn crate::files::FileReadConsent>,
        cancelled: Vec<u8>,
    ) -> Result<(), RemoteError> {
        self.send_checked_file(
            Channel::FileWrite,
            payload,
            check,
            cancelled.clone(),
            cancelled,
        )
        .await
    }
    async fn send_checked_file(
        &self,
        channel: Channel,
        payload: &[u8],
        check: Arc<dyn crate::files::FileReadConsent>,
        denied: Vec<u8>,
        expired: Vec<u8>,
    ) -> Result<(), RemoteError> {
        self.send_checked_delivery(
            channel,
            payload,
            Arc::new(FileGuard(check)),
            denied,
            expired,
        )
        .await
    }
    /// Only a typed protocol producer may choose fallback bytes. The transport
    /// never invents a business response or transfers permission between channels.
    pub(crate) async fn send_checked_delivery(
        &self,
        channel: Channel,
        payload: &[u8],
        check: Arc<dyn DeliveryGuard>,
        denied: Vec<u8>,
        expired: Vec<u8>,
    ) -> Result<(), RemoteError> {
        if !matches!(
            channel,
            Channel::FileRead
                | Channel::FileWrite
                | Channel::ClipboardRead
                | Channel::ClipboardWrite
        ) || denied.len() > channel.budget()
            || expired.len() > channel.budget()
        {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "invalid file reply fallback").into(),
            );
        }
        self.outgoing
            .put_guarded(
                &self.lease,
                channel,
                payload,
                Instant::now(),
                Some(Disclosure {
                    check,
                    denied,
                    expired,
                    rejected: Arc::new(AtomicU8::new(0)),
                }),
                None,
            )
            .await
    }
    /// Coalescing media recovery may defer a request while this reliable queue
    /// is full. A false result inserted no bytes and consumes no request ID.
    pub fn try_send_video_feedback(&self, payload: &[u8]) -> Result<bool, RemoteError> {
        self.outgoing
            .try_put(&self.lease, Channel::VideoFeedback, payload, Instant::now())
    }
    pub async fn send(&self, channel: Channel, payload: &[u8]) -> Result<(), RemoteError> {
        self.outgoing.put(&self.lease, channel, payload).await
    }
    /// Sends one reference-dependent encoded frame with its original capture
    /// approval checked at enqueue and immediately before transport writing.
    pub async fn send_video_guarded(
        &self,
        payload: &[u8],
        guard: Arc<dyn DeliveryGuard>,
    ) -> Result<(), RemoteError> {
        self.outgoing
            .put_video_guarded(&self.lease, payload, guard)
            .await
    }
    /// Discards any frame waiting behind transport backpressure after its
    /// platform capture source has stopped.
    pub fn discard_video(&self) -> Result<(), RemoteError> {
        self.outgoing
            .discard(Channel::Video)
            .map_err(RemoteError::from)
    }
}
impl<R: AsyncRead + Unpin + Send + 'static, W: AsyncWrite + Unpin + Send + 'static>
    AuthorizedConnection<R, W>
{
    pub fn into_channels(self) -> ChannelRuntime {
        let Self {
            mut read,
            mut write,
            lease,
            renewal,
        } = self;
        let (renewal, control_in, mut control_out) = match renewal {
            Some((port, io)) => (Some(port), Some(io.incoming), Some(io.outgoing)),
            None => (None, None, None),
        };
        let incoming = Queue::new();
        let outgoing = Queue::new();
        let reader_queue = incoming.clone();
        let reader_lease = lease.clone();
        let reader = tokio::spawn(async move {
            let _scope = StopOnDrop(reader_lease.clone());
            let result = async {
                loop {
                    let frame = lease_io(
                        nestlink_transport_stream::read_frame_control_bounded(
                            &mut read,
                            nestlink_protocol::native_renewal::MAX_BYTES,
                        ),
                        &reader_lease,
                    )
                    .await?;
                    if frame.channel == Channel::Control {
                        let tx = control_in.as_ref().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "unnegotiated native control",
                            )
                        })?;
                        reader_lease.remaining()?;
                        tx.try_send(frame.payload).map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "native control queue overflow or closed",
                            )
                        })?;
                        continue;
                    }
                    reader_lease.authorize(frame.channel)?;
                    reader_queue
                        .put(&reader_lease, frame.channel, &frame.payload)
                        .await?;
                }
            }
            .await;
            stop_io_result(&reader_lease, &result);
            reader_queue.close();
            result
        });
        let writer_queue = outgoing.clone();
        let writer_lease = lease.clone();
        let writer = tokio::spawn(async move {
            let _scope = StopOnDrop(writer_lease.clone());
            let result = async {
                loop {
                    let mut queued = tokio::select! { biased;
                        bytes=async {match &mut control_out {Some(rx)=>rx.recv().await,None=>std::future::pending().await}} => {
                            let bytes=bytes.ok_or_else(||io::Error::new(io::ErrorKind::BrokenPipe,"native control owner closed"))?;
                            writer_lease.remaining()?;
                            lease_io(write_frame(&mut write,Channel::Control,&bytes),&writer_lease).await?;
                            continue;
                        }
                        queued=writer_queue.take_queued(&writer_lease,None)=>queued?,
                    };
                    writer_lease.authorize(queued.frame.channel)?;
                    queued.check_file_delivery();
                    if !queued.check_delivery() {
                        continue;
                    }
                    let channel = queued.frame.channel;
                    let payload =
                        zeroize::Zeroizing::new(std::mem::take(&mut queued.frame.payload));
                    let delivery_guard = queued.delivery_guard();
                    let written = lease_io(
                        async {
                            if delivery_guard
                                .as_ref()
                                .is_some_and(|guard| guard.check().is_err())
                            {
                                return Ok(false);
                            }
                            write_media_bounded(&mut write, channel, &payload, queued.arrived)
                                .await?;
                            Ok(true)
                        },
                        &writer_lease,
                    )
                    .await?;
                    if !written {
                        continue;
                    }
                }
            }
            .await;
            stop_io_result(&writer_lease, &result);
            writer_queue.close();
            let _ = tokio::time::timeout(Duration::from_millis(100), write.shutdown()).await;
            result
        });
        ChannelRuntime {
            renewal,
            lease,
            incoming,
            outgoing,
            tasks: vec![reader, writer],
            mode: TransportMode::ReliableByteStream,
            connection: None,
            _endpoint: None,
            transport_owner: None,
            cleanup_deadline: None,
            cleanup_failure: None,
        }
    }
}
impl ChannelRuntime {
    /// Retain a carrier's explicit close/cancellation owner. This grants no
    /// business authority; lease supervision still closes the inner transport.
    pub fn with_transport_owner(mut self, owner: impl TransportOwner + 'static) -> Self {
        self.transport_owner = Some(Box::new(owner));
        self
    }
    pub(crate) fn quic(
        lease: LeaseControl,
        incoming: Arc<Queue>,
        outgoing: Arc<Queue>,
        tasks: Vec<JoinHandle<Result<(), RemoteError>>>,
        connection: quinn::Connection,
        endpoint: Option<quinn::Endpoint>,
    ) -> Self {
        Self {
            renewal: None,
            lease,
            incoming,
            outgoing,
            tasks,
            mode: TransportMode::QuicStreamsAndDatagrams,
            connection: Some(connection),
            _endpoint: endpoint,
            transport_owner: None,
            cleanup_deadline: None,
            cleanup_failure: None,
        }
    }
    pub(crate) fn with_native_renewal(
        mut self,
        port: Option<crate::native_renewal::NativeRenewalPort>,
    ) -> Self {
        self.renewal = port;
        self
    }
    /// One native coordinator exclusively claims the authenticated control port.
    pub fn take_native_renewal_port(&mut self) -> Option<crate::native_renewal::NativeRenewalPort> {
        self.renewal.take()
    }
    pub fn mode(&self) -> TransportMode {
        self.mode
    }
    pub fn sender(&self) -> ChannelSender {
        ChannelSender {
            lease: self.lease.clone(),
            outgoing: self.outgoing.clone(),
        }
    }
    pub fn lease_control(&self) -> LeaseControl {
        self.lease.clone()
    }
    /// Claim before handing the runtime to a fallback consumer. Each channel
    /// can be claimed only once; an old claim is never reassigned or replayed.
    pub fn claim_channel(&mut self, channel: Channel) -> Result<ChannelReceiver, RemoteError> {
        let index = CHANNELS
            .iter()
            .position(|c| *c == channel)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "reserved channel"))?;
        self.lease.operation(permission(channel)?, || {
            let mut state = self
                .incoming
                .state
                .lock()
                .map_err(|_| io::Error::other("channel queue poisoned"))?;
            if state.closed || state.claimed[index] {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "incoming channel already claimed or closed",
                ));
            }
            state.claimed[index] = true;
            Ok(())
        })?;
        self.incoming.wake();
        Ok(ChannelReceiver {
            lease: self.lease.clone(),
            incoming: self.incoming.clone(),
            channel,
            stop_on_drop: true,
        })
    }
    pub async fn send(&self, channel: Channel, payload: &[u8]) -> Result<(), RemoteError> {
        self.outgoing.put(&self.lease, channel, payload).await
    }
    pub async fn receive(&mut self) -> Result<Frame, RemoteError> {
        self.incoming.take(&self.lease, None).await
    }
    /// Wait for terminal cleanup and for all owned I/O tasks to drop their
    /// transports. Failed attached cleanup remains visible in the report.
    pub async fn wait_stopped(&mut self) -> Result<StopReport, RemoteError> {
        let mut reports = self.lease.subscribe_stopped();
        let report = loop {
            if let Some(report) = *reports.borrow_and_update() {
                break report;
            }
            reports.changed().await.map_err(|_| RemoteError::Stopped)?;
        };
        self.incoming.close();
        self.outgoing.close();
        if let Some(connection) = &self.connection {
            close_quic(connection, &self.lease);
        }
        let deadline = *self
            .cleanup_deadline
            .get_or_insert_with(|| tokio::time::Instant::now() + Duration::from_secs(2));
        // Keep handles owned until each join completes. Cancelling this wait
        // cannot detach running tasks or restart the original cleanup budget.
        while let Some(task) = self.tasks.first_mut() {
            match tokio::time::timeout_at(deadline, &mut *task).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    let _ = error;
                    self.cleanup_failure.get_or_insert(io::ErrorKind::Other);
                }
                Err(_) => {
                    task.abort();
                    self.cleanup_failure.get_or_insert(io::ErrorKind::TimedOut);
                    // Abort requests cancellation; it is not completion. Keep
                    // every handle so a later wait can reap a finished task
                    // against this same absolute deadline, without detaching
                    // an uncooperative task or awaiting it without a budget.
                    for pending in &self.tasks { pending.abort(); }
                    if let Some(owner) = &self.transport_owner { owner.request_close(); }
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "transport task cleanup pending").into());
                }
            }
            self.tasks.remove(0);
        }
        // No business task may retain a stream before carrier cleanup starts.
        // Release runtime clones so the unique endpoint owner can confirm the
        // final physical socket and writable poller have actually gone away.
        drop(self.connection.take());
        drop(self._endpoint.take());
        if let Err(error) = self.lease.wait_supervisor_stopped(deadline).await {
            self.cleanup_failure.get_or_insert(error.kind());
        }
        if let Some(owner) = self.transport_owner.as_mut() {
            match tokio::time::timeout_at(deadline, owner.close_and_wait(deadline)).await {
                Ok(Ok(())) => self.transport_owner = None,
                Ok(Err(error)) => { self.cleanup_failure.get_or_insert(error.kind()); },
                Err(_) => { self.cleanup_failure.get_or_insert(io::ErrorKind::TimedOut); },
            }
        }
        if let Some(failure) = self.cleanup_failure {
            return Err(io::Error::new(failure, "transport cleanup failed").into());
        }
        Ok(report)
    }
    pub async fn shutdown(&mut self, reason: StopReason) -> Result<StopReport, RemoteError> {
        self.lease.stop(reason)?;
        self.wait_stopped().await
    }
}
impl Drop for ChannelRuntime {
    fn drop(&mut self) {
        let _ = self.lease.stop(StopReason::ExplicitExit);
        self.incoming.close();
        self.outgoing.close();
        if let Some(connection) = &self.connection {
            close_quic(connection, &self.lease);
        }
        if let Some(owner) = &self.transport_owner {
            owner.request_close();
        }
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}
