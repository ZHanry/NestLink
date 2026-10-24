//! H264 access units use a bounded FIFO on a dedicated TLS connection. Small
//! authorization/stop/decoder feedback uses a separate full-duplex connection.
use crate::{
    Error, NativeVideoBinding,
    wire::{Command, Reply, Request, Response},
};
use nestlink_app_core::{CoreHandle, NativeSessionBinding, VideoSinkContext, VideoSinkFeedback};
use nestlink_local_ipc::{LocalDuplexOwner, LocalRead, LocalStream, LocalWrite};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::Path,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCompressedBinding {
    pub runtime_id: String,
    pub ui_generation: u64,
    pub request_id: String,
    pub connection_generation: u64,
    pub source: u32,
    pub stream_id: [u8; 16],
    pub stream_epoch: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressedContext {
    pub binding: NativeCompressedBinding,
    pub catalog_revision: u64,
    pub selection_sequence: u64,
    pub layout_epoch: u64,
    pub decode_epoch: u64,
    pub configuration_id: u64,
}
impl CompressedContext {
    fn domain(&self) -> VideoSinkContext {
        VideoSinkContext {
            connection_generation: self.binding.connection_generation,
            source: self.binding.source,
            stream_id: self.binding.stream_id,
            stream_epoch: self.binding.stream_epoch,
            catalog_revision: self.catalog_revision,
            selection_sequence: self.selection_sequence,
            layout_epoch: self.layout_epoch,
            decode_epoch: self.decode_epoch,
            configuration_id: self.configuration_id,
        }
    }
    fn session(&self) -> NativeSessionBinding {
        NativeSessionBinding {
            request_id: self.binding.request_id.clone(),
            connection_generation: self.binding.connection_generation,
        }
    }
    fn from_domain(binding: &NativeVideoBinding, c: VideoSinkContext) -> Self {
        Self {
            binding: NativeCompressedBinding {
                runtime_id: binding.runtime_id.clone(),
                ui_generation: binding.ui_generation,
                request_id: binding.request_id.clone(),
                connection_generation: binding.connection_generation,
                source: binding.source,
                stream_id: c.stream_id,
                stream_epoch: c.stream_epoch,
            },
            catalog_revision: c.catalog_revision,
            selection_sequence: c.selection_sequence,
            layout_epoch: c.layout_epoch,
            decode_epoch: c.decode_epoch,
            configuration_id: c.configuration_id,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCompressedOpen {
    pub ui_generation: u64,
    pub request_id: String,
    pub connection_generation: u64,
    pub source: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerControl {
    Prepare {
        context: CompressedContext,
        width: u32,
        height: u32,
        qpc_frequency: u64,
    },
    Activate {
        context: CompressedContext,
    },
    Authority {
        context: CompressedContext,
        sequence: u64,
        not_after_qpc: u64,
    },
    Stop {
        context: CompressedContext,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientControl {
    Prepared {
        context: CompressedContext,
    },
    Fence {
        context: CompressedContext,
    },
    Accepted {
        context: CompressedContext,
        delivery_sequence: u64,
    },
    Decoded {
        context: CompressedContext,
        delivery_sequence: u64,
        native_sequence: u64,
        pts_90khz: u64,
    },
    NeedKeyframe {
        context: CompressedContext,
    },
    Stopped {
        context: CompressedContext,
        joined: bool,
    },
}
fn stale_decode_context(received: &CompressedContext, current: &CompressedContext) -> bool {
    if received.decode_epoch >= current.decode_epoch {
        return false;
    }
    let mut normalized = received.clone();
    normalized.decode_epoch = current.decode_epoch;
    &normalized == current
}
impl ClientControl {
    pub fn context(&self) -> &CompressedContext {
        match self {
            Self::Fence { context }
            | Self::Prepared { context }
            | Self::Accepted { context, .. }
            | Self::Decoded { context, .. }
            | Self::NeedKeyframe { context }
            | Self::Stopped { context, .. } => context,
        }
    }
    fn domain(&self) -> VideoSinkFeedback {
        match self {
            Self::Prepared { .. } => VideoSinkFeedback::Prepared,
            Self::Fence { .. } => VideoSinkFeedback::Fence,
            Self::Accepted {
                delivery_sequence, ..
            } => VideoSinkFeedback::Accepted {
                delivery_sequence: *delivery_sequence,
            },
            Self::Decoded {
                delivery_sequence,
                native_sequence,
                pts_90khz,
                ..
            } => VideoSinkFeedback::Decoded {
                delivery_sequence: *delivery_sequence,
                native_sequence: *native_sequence,
                pts_90khz: *pts_90khz,
            },
            Self::NeedKeyframe { .. } => VideoSinkFeedback::NeedKeyframe,
            Self::Stopped { joined, .. } => VideoSinkFeedback::Stopped { joined: *joined },
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessHeader {
    magic: [u8; 8],
    context: CompressedContext,
    delivery_sequence: u64,
    native_sequence: u64,
    pts_90khz: u64,
    due_qpc: u64,
    not_after_qpc: u64,
    keyframe: bool,
    repeated_source: bool,
    payload_bytes: usize,
}
pub struct CompressedAccessUnit {
    pub context: CompressedContext,
    pub delivery_sequence: u64,
    pub native_sequence: u64,
    pub pts_90khz: u64,
    pub due_qpc: u64,
    pub not_after_qpc: u64,
    pub keyframe: bool,
    pub repeated_source: bool,
    pub payload: Zeroizing<Vec<u8>>,
}

/// Same-machine monotonic QPC only; never serialize Rust Instant.
pub fn qpc() -> Result<(u64, u64), Error> {
    nestlink_app_core::native_video_qpc().map_err(|_| Error::Protocol)
}

fn due_qpc(due: Instant) -> Result<(u64, u64), Error> {
    let now = Instant::now();
    let (counter, frequency) = qpc()?;
    let delta = if due >= now {
        i128::try_from(due.duration_since(now).as_nanos()).map_err(|_| Error::Protocol)?
    } else {
        -i128::try_from(now.duration_since(due).as_nanos()).map_err(|_| Error::Protocol)?
    };
    let at = u64::try_from(i128::from(counter) + delta * i128::from(frequency) / 1_000_000_000)
        .map_err(|_| Error::Protocol)?;
    let end = at
        .checked_add(frequency * 40 / 1000)
        .ok_or(Error::Protocol)?;
    Ok((at, end))
}

struct Ticket {
    context: CompressedContext,
    created: Instant,
    active: Arc<AtomicBool>,
}
static TICKETS: OnceLock<Mutex<HashMap<[u8; 32], Ticket>>> = OnceLock::new();
fn tickets() -> &'static Mutex<HashMap<[u8; 32], Ticket>> {
    TICKETS.get_or_init(|| Mutex::new(HashMap::new()))
}
pub(crate) fn open(
    core: &CoreHandle,
    binding: NativeVideoBinding,
) -> Result<(CompressedContext, u32, u32, [u8; 32], Arc<AtomicBool>), Error> {
    qpc()?;
    if core.snapshot().generation != binding.ui_generation {
        return Err(Error::Protocol);
    }
    let session = NativeSessionBinding {
        request_id: binding.request_id.clone(),
        connection_generation: binding.connection_generation,
    };
    let mut entries = tickets().lock().map_err(|_| Error::Protocol)?;
    entries.retain(|_, v| v.created.elapsed() < Duration::from_secs(2));
    if entries.len() >= 8 {
        return Err(Error::Protocol);
    }
    let (domain, width, height) = core
        .open_native_compressed(&session, binding.source)
        .map_err(|_| Error::Protocol)?;
    let context = CompressedContext::from_domain(&binding, domain);
    let ticket = nestlink_auth::random_bytes();
    let active = Arc::new(AtomicBool::new(true));
    entries.insert(
        ticket,
        Ticket {
            context: context.clone(),
            created: Instant::now(),
            active: active.clone(),
        },
    );
    Ok((context, width, height, ticket, active))
}
pub(crate) fn take_ticket(
    ticket: [u8; 32],
    runtime: &str,
    generation: u64,
) -> Result<(CompressedContext, Arc<AtomicBool>), Error> {
    let t = tickets()
        .lock()
        .map_err(|_| Error::Protocol)?
        .remove(&ticket)
        .ok_or(Error::Protocol)?;
    if t.created.elapsed() > Duration::from_secs(2)
        || t.context.binding.runtime_id != runtime
        || t.context.binding.ui_generation != generation
    {
        return Err(Error::Protocol);
    }
    if !t.active.load(Ordering::Acquire) {
        return Err(Error::Protocol);
    }
    Ok((t.context, t.active))
}
fn current(
    core: &CoreHandle,
    context: &CompressedContext,
) -> Result<(CompressedContext, u32, u32), Error> {
    if core.snapshot().generation != context.binding.ui_generation {
        return Err(Error::Protocol);
    }
    let (c, w, h) = core
        .native_compressed_context(&context.session())
        .map_err(|_| Error::Protocol)?
        .ok_or(Error::Protocol)?;
    if c.stream_id != context.binding.stream_id || c.stream_epoch != context.binding.stream_epoch {
        return Err(Error::Protocol);
    }
    let binding = NativeVideoBinding {
        runtime_id: context.binding.runtime_id.clone(),
        ui_generation: context.binding.ui_generation,
        request_id: context.binding.request_id.clone(),
        connection_generation: context.binding.connection_generation,
        source: context.binding.source,
    };
    Ok((CompressedContext::from_domain(&binding, c), w, h))
}
pub(crate) async fn serve_control(
    connection: LocalStream,
    core: CoreHandle,
    initial: CompressedContext,
    ticket: [u8; 32],
    active: Arc<AtomicBool>,
) -> Result<(), Error> {
    let cleanup = core
        .native_compressed_cleanup(&initial.domain())
        .map_err(|_| Error::Protocol)?;
    struct Active(Arc<AtomicBool>, nestlink_app_core::ExternalVideoCleanup);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
            let _ = self.1.fence();
        }
    }
    let _active = Active(active, cleanup.clone());
    let (mut read, mut write, _owner) = connection.into_duplex()?;
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let reader = tokio::spawn(async move {
        loop {
            match read.receive::<ClientControl>().await {
                Ok(v) => {
                    if tx.send(v).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    struct Abort(tokio::task::JoinHandle<()>);
    impl Drop for Abort {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _reader = Abort(reader);
    let mut prepared = None;
    let mut sequence = 0u64;
    let mut closing = false;
    let mut preparation_deadline = Instant::now() + Duration::from_secs(2);
    let mut acknowledged = false;
    let mut closing_deadline = None;
    let result=async {
        loop {
            let (context,width,height)=match current(&core,&initial){Ok(v)=>v,Err(_)=>{
                _active.0.store(false,Ordering::Release);let _=cleanup.fence();
                let context=prepared.as_ref().unwrap_or(&initial).clone();
                let _=write.send(&ServerControl::Stop{context:context.clone()}).await;
                let deadline=tokio::time::Instant::now()+Duration::from_secs(2);
                loop{
                    if tokio::time::Instant::now()>=deadline{return Err(Error::Protocol);}
                    tokio::select!{biased;
                    feedback=rx.recv()=>{
                        let feedback=feedback.ok_or(Error::Protocol)?;
                        let ClientControl::Stopped{context:receipt,joined:true}=feedback else{continue;};
                        if receipt==context{cleanup.joined(&receipt.domain()).map_err(|_|Error::Protocol)?;return Ok(());}
                    }
                    _=tokio::time::sleep_until(deadline)=>return Err(Error::Protocol),
                }}
            }};
            if prepared.as_ref()!=Some(&context){
                let (_,frequency)=qpc()?;
                write.send(&ServerControl::Prepare{context:context.clone(),width,height,qpc_frequency:frequency}).await?;
                prepared=Some(context.clone());
                preparation_deadline=Instant::now()+Duration::from_secs(2);acknowledged=false;
            }
            if !closing && (!_active.0.load(Ordering::Acquire) || (!acknowledged && Instant::now()>=preparation_deadline)) {
                closing=true;closing_deadline=Some(Instant::now()+Duration::from_secs(2));
                _active.0.store(false,Ordering::Release);cleanup.fence().map_err(|_|Error::Protocol)?;
                write.send(&ServerControl::Stop{context:context.clone()}).await?;
            }
            if closing_deadline.is_some_and(|d|Instant::now()>=d){return Err(Error::Protocol);}
            sequence=sequence.checked_add(1).filter(|n|*n<=i64::MAX as u64).ok_or(Error::Protocol)?;
            let(now,freq)=qpc()?;
            let remaining=core.native_compressed_authority_remaining().map_err(|_|Error::Protocol)?.min(Duration::from_millis(150));
            let validity=u64::try_from(remaining.as_nanos()*u128::from(freq)/1_000_000_000).map_err(|_|Error::Protocol)?;
            if !closing {write.send(&ServerControl::Authority{context:context.clone(),sequence,not_after_qpc:now.checked_add(validity).ok_or(Error::Protocol)?}).await?;}
            let deadline=tokio::time::Instant::now()+Duration::from_millis(50);
            loop {
                if tokio::time::Instant::now()>=deadline{break;}
                tokio::select!{biased;
                    feedback=rx.recv()=>{
                        let feedback=feedback.ok_or(Error::Protocol)?;
                        if feedback.context()!=&context{
                            if stale_decode_context(feedback.context(),&context){continue;}
                            return Err(Error::Protocol);
                        }
                        let is_prepared=matches!(&feedback,ClientControl::Prepared{..});
                        let recovering=matches!(&feedback,ClientControl::NeedKeyframe{..});
                        let stopped=matches!(&feedback,ClientControl::Stopped{joined:true,..});
                        let fence=matches!(&feedback,ClientControl::Fence{..});
                        if stopped{cleanup.joined(&context.domain()).map_err(|_|Error::Protocol)?;return Ok(());}
                        // Once fenced, only the actual owner-join receipt can
                        // advance cleanup. Late decoder output cannot reset it.
                        if closing {continue;}
                        core.native_compressed_feedback(&context.session(),&context.domain(),feedback.domain()).map_err(|_|Error::Protocol)?;
                        if fence {closing=true;closing_deadline=Some(Instant::now()+Duration::from_secs(2));_active.0.store(false,Ordering::Release);write.send(&ServerControl::Stop{context:context.clone()}).await?;}
                        if is_prepared{acknowledged=true;write.send(&ServerControl::Activate{context:context.clone()}).await?;}
                        if recovering{break;}
                    }
                    _=tokio::time::sleep_until(deadline)=>break,
                }
            }
        }
    }.await;
    if let Ok(mut entries) = tickets().lock() {
        entries.remove(&ticket);
    }
    if result.is_err() {
        let context = prepared.as_ref().unwrap_or(&initial);
        let _ = core.native_compressed_feedback(
            &context.session(),
            &context.domain(),
            VideoSinkFeedback::Fence,
        );
    }
    // EOF does not fabricate joined ownership. The media sink stays fenced
    // until an actual join receipt or terminal session shutdown reclaims it.
    result
}
pub(crate) async fn serve_data(
    connection: LocalStream,
    core: CoreHandle,
    initial: CompressedContext,
    active: Arc<AtomicBool>,
) -> Result<(), Error> {
    struct Revoke(Arc<AtomicBool>);
    impl Drop for Revoke {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _revoke = Revoke(active.clone());
    let (mut read, mut write, _owner) = connection.into_duplex()?;
    let disconnected = read.wait_closed();
    tokio::pin!(disconnected);
    loop {
        if !active.load(Ordering::Acquire) {
            return Err(Error::Protocol);
        }
        let (context, _, _) = current(&core, &initial)?;
        let Some(unit) = core
            .poll_native_compressed(&context.session(), &context.domain())
            .map_err(|_| Error::Protocol)?
        else {
            tokio::select! {biased;_=&mut disconnected=>return Err(Error::Protocol),_=tokio::time::sleep(Duration::from_millis(4))=>{}};
            continue;
        };
        let (due_qpc, not_after_qpc) = due_qpc(unit.due)?;
        let h = AccessHeader {
            magic: *b"NLCMP001",
            context: context.clone(),
            delivery_sequence: unit.delivery_sequence,
            native_sequence: unit.native_sequence,
            pts_90khz: unit.pts_90khz,
            due_qpc,
            not_after_qpc,
            keyframe: unit.keyframe,
            repeated_source: unit.repeated_source,
            payload_bytes: unit.payload.len(),
        };
        let header = Zeroizing::new(serde_json::to_vec(&h).map_err(|_| Error::Protocol)?);
        if header.len() > 4096 || header.len().saturating_add(unit.payload.len()) > 8 * 1024 * 1024
        {
            return Err(Error::Protocol);
        }
        let authorized = || {
            active.load(Ordering::Acquire) && current(&core, &initial).is_ok_and(|v| v.0 == context)
        };
        write.send_bytes(&header, authorized).await?;
        write.send_bytes(&unit.payload, authorized).await?;
    }
}

pub struct CompressedVideoClient {
    read: LocalRead,
    write: LocalWrite,
    data: CompressedDataRx,
    owner: CompressedClientOwner,
    pub context: CompressedContext,
}
pub struct CompressedControlTx(LocalWrite);
pub struct CompressedControlRx(LocalRead);
pub struct CompressedDataRx {
    read: LocalRead,
    stream_id: [u8; 16],
    delivery: u64,
}
pub struct CompressedClientOwner {
    _control: LocalDuplexOwner,
    _data: LocalDuplexOwner,
}
async fn handshake(
    directory: &Path,
    generation: u64,
    command: Command,
) -> Result<(LocalStream, Reply), Error> {
    let mut connection = LocalStream::connect(directory).await?;
    let runtime = connection.runtime_id().to_owned();
    connection
        .send(&Request {
            version: nestlink_local_ipc::VERSION,
            runtime_id: runtime.clone(),
            sequence: 1,
            expected_generation: generation,
            command,
        })
        .await?;
    let response: Response = connection.receive().await?;
    if response.version != nestlink_local_ipc::VERSION
        || response.runtime_id != runtime
        || response.sequence != 1
        || response.snapshot.generation != generation
    {
        return Err(Error::Protocol);
    }
    Ok((connection, response.result))
}
impl CompressedVideoClient {
    pub async fn open(directory: &Path, open: NativeCompressedOpen) -> Result<Self, Error> {
        let generation = open.ui_generation;
        let (control, reply) = handshake(
            directory,
            generation,
            Command::OpenNativeCompressedVideo { open },
        )
        .await?;
        let Reply::CompressedVideoOpened { context, ticket } = reply else {
            return Err(Error::Protocol);
        };
        let (data, reply) = handshake(
            directory,
            generation,
            Command::OpenNativeCompressedData { ticket },
        )
        .await?;
        if !matches!(reply, Reply::CompressedDataOpened) {
            return Err(Error::Protocol);
        }
        let (read, write, control_owner) = control.into_duplex()?;
        let (data_read, _data_write, data_owner) = data.into_duplex()?;
        let stream_id = context.binding.stream_id;
        Ok(Self {
            read,
            write,
            data: CompressedDataRx {
                read: data_read,
                stream_id,
                delivery: 0,
            },
            owner: CompressedClientOwner {
                _control: control_owner,
                _data: data_owner,
            },
            context,
        })
    }
    pub fn split(
        self,
    ) -> (
        CompressedControlTx,
        CompressedControlRx,
        CompressedDataRx,
        CompressedClientOwner,
    ) {
        (
            CompressedControlTx(self.write),
            CompressedControlRx(self.read),
            self.data,
            self.owner,
        )
    }
}
impl CompressedControlTx {
    pub async fn send(&mut self, feedback: ClientControl) -> Result<(), Error> {
        self.0.send(&feedback).await?;
        Ok(())
    }
}
impl CompressedControlRx {
    pub async fn receive(&mut self) -> Result<ServerControl, Error> {
        Ok(self.0.receive().await?)
    }
}
impl CompressedDataRx {
    pub async fn receive(&mut self) -> Result<CompressedAccessUnit, Error> {
        let h: AccessHeader = self.read.receive().await?;
        if h.magic != *b"NLCMP001"
            || h.context.binding.stream_id != self.stream_id
            || h.delivery_sequence != self.delivery.checked_add(1).ok_or(Error::Protocol)?
            || h.native_sequence == 0
            || h.pts_90khz > i64::MAX as u64
            || h.payload_bytes == 0
            || h.payload_bytes > 8 * 1024 * 1024 - 4096
            || h.due_qpc > h.not_after_qpc
        {
            return Err(Error::Protocol);
        }
        let payload = self.read.receive_bytes(h.payload_bytes).await?;
        if payload.len() != h.payload_bytes {
            return Err(Error::Protocol);
        }
        self.delivery = h.delivery_sequence;
        Ok(CompressedAccessUnit {
            context: h.context,
            delivery_sequence: h.delivery_sequence,
            native_sequence: h.native_sequence,
            pts_90khz: h.pts_90khz,
            due_qpc: h.due_qpc,
            not_after_qpc: h.not_after_qpc,
            keyframe: h.keyframe,
            repeated_source: h.repeated_source,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_decode_requires_every_other_context_field_to_match() {
        let current = CompressedContext {
            binding: NativeCompressedBinding {
                runtime_id: "runtime".into(),
                ui_generation: 1,
                request_id: "request".into(),
                connection_generation: 1,
                source: 1,
                stream_id: [1; 16],
                stream_epoch: 1,
            },
            catalog_revision: 1,
            selection_sequence: 1,
            layout_epoch: 1,
            decode_epoch: 2,
            configuration_id: 1,
        };
        let mut old = current.clone();
        old.decode_epoch = 1;
        assert!(stale_decode_context(&old, &current));
        assert!(!stale_decode_context(&current, &current));
        let mut wrong = old.clone();
        wrong.binding.runtime_id.push('x');
        assert!(!stale_decode_context(&wrong, &current));
        wrong = old.clone();
        wrong.binding.ui_generation += 1;
        assert!(!stale_decode_context(&wrong, &current));
        wrong = old.clone();
        wrong.binding.source += 1;
        assert!(!stale_decode_context(&wrong, &current));
        wrong = old;
        wrong.selection_sequence += 1;
        assert!(!stale_decode_context(&wrong, &current));
    }
}
