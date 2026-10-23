//! Proved, permission-scoped WebRTC data channel owners.
use super::{WebRtcHostError, ensure_live};
use bytes::Bytes;
use nestlink_identity::VerifiedPermit;
use nestlink_protocol::{
    Permission,
    webrtc_data::{
        MAX_WEBRTC_DATA_FRAGMENT_BYTES, WebRtcDataBinding, WebRtcDataChannel, WebRtcDataFragmenter,
        WebRtcDataReassembler,
    },
};
use nestlink_remote::{
    ExternalChannelRuntime, ExternalDataChannelPort, LeaseControl, RemoteError,
    clipboard::{ClaimedClipboardTransport, ClipboardBinding, ClipboardDirections},
    files::ClaimedFileRead,
    upload::ClaimedFileWrite,
};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex, mpsc, watch},
    task::JoinHandle,
};
use webrtc::{
    data_channel::{
        RTCDataChannel, data_channel_message::DataChannelMessage,
        data_channel_state::RTCDataChannelState,
    },
    peer_connection::RTCPeerConnection,
};

const DATA_CHANNEL_QUEUE_CAPACITY: usize = 12;
const DATA_CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(3);
const DATA_WORKER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_SCTP_MAX_MESSAGE_SIZE: u64 = 65_536;

/// One-shot claims for every native service requested by the signed permit.
/// A provider must transfer each present claim to exactly one worker owner.
pub struct HostDataClaims {
    pub file_read: Option<ClaimedFileRead>,
    pub file_write: Option<ClaimedFileWrite>,
    pub clipboard: Option<ClaimedClipboardTransport>,
}

/// A provider owns platform file/clipboard workers started from proved claims.
/// It is retained by [`HostDataRuntime`] until shutdown succeeds.
pub trait HostDataOwner: Send {
    fn shutdown<'a>(
        &'a mut self,
        reason: StopReason,
    ) -> Pin<Box<dyn Future<Output = Result<(), RemoteError>> + Send + 'a>>;
}

/// Create the platform service owner after endpoint proof, using the one-shot
/// claims corresponding to the exact permission set on the signed permit.
pub type HostDataFactory = Box<
    dyn FnOnce(HostDataClaims) -> Result<Box<dyn HostDataOwner>, WebRtcHostError> + Send + 'static,
>;

pub(super) struct PendingDataChannel {
    channel: Arc<RTCDataChannel>,
    messages: mpsc::Receiver<Vec<u8>>,
}
impl PendingDataChannel {
    #[cfg(test)]
    pub(super) fn into_parts(self) -> (Arc<RTCDataChannel>, mpsc::Receiver<Vec<u8>>) {
        (self.channel, self.messages)
    }
}

/// Register one controller-created business channel before proof. It accepts
/// only the exact reliable ordered label and buffers at most twelve fragments;
/// data is not delivered into the session queues until proof has completed.
pub(super) async fn register_channel(
    kind: WebRtcDataChannel,
    channel: Arc<RTCDataChannel>,
    pending: Arc<Mutex<HashMap<WebRtcDataChannel, PendingDataChannel>>>,
    cancel: watch::Sender<bool>,
    proof_complete: Arc<AtomicBool>,
    weak_peer: std::sync::Weak<RTCPeerConnection>,
) -> Result<(), WebRtcHostError> {
    if kind == WebRtcDataChannel::Unspecified
        || channel.label() != kind.label()
        || !channel.ordered()
        || channel.max_retransmits().is_some()
        || channel.max_packet_lifetime().is_some()
        || channel.negotiated()
        || !channel.protocol().is_empty()
    {
        return Err(WebRtcHostError::BusinessDataChannel);
    }

    let (sender, receiver) = mpsc::channel(DATA_CHANNEL_QUEUE_CAPACITY);
    {
        let mut channels = pending.lock().await;
        if channels.contains_key(&kind) {
            return Err(WebRtcHostError::BusinessDataChannel);
        }
        channels.insert(
            kind,
            PendingDataChannel {
                channel: channel.clone(),
                messages: receiver,
            },
        );
    }

    let cancel_message = cancel.clone();
    let proof_complete_message = proof_complete;
    let weak_message_peer = weak_peer.clone();
    channel.on_message(Box::new(move |message: DataChannelMessage| {
        let sender = sender.clone();
        let cancel = cancel_message.clone();
        let proof_complete = proof_complete_message.clone();
        let weak_peer = weak_message_peer.clone();
        Box::pin(async move {
            if !queue_business_message(&proof_complete, &sender, message) {
                cancel.send_replace(true);
                if let Some(peer) = weak_peer.upgrade() {
                    let _ = peer.close().await;
                }
            }
        })
    }));
    let cancel_close = cancel;
    channel.on_close(Box::new(move || {
        let cancel = cancel_close.clone();
        Box::pin(async move {
            cancel.send_replace(true);
        })
    }));
    Ok(())
}

/// Queue a business fragment only after mutual endpoint proof. Channels can
/// be registered before proof, but their callbacks must never turn pre-proof
/// traffic into work that a post-proof worker could later consume.
fn queue_business_message(
    proof_complete: &AtomicBool,
    sender: &mpsc::Sender<Vec<u8>>,
    message: DataChannelMessage,
) -> bool {
    if !proof_complete.load(Ordering::Acquire)
        || message.is_string
        || message.data.is_empty()
        || message.data.len() > MAX_WEBRTC_DATA_FRAGMENT_BYTES
        || sender.try_send(message.data.to_vec()).is_err()
    {
        return false;
    }
    true
}

/// Own the external bounded queue bridge, one SCTP worker per business
/// channel, and the platform service workers that consume their claims.
pub(super) struct HostDataRuntime {
    external: ExternalChannelRuntime,
    workers: Vec<JoinHandle<Result<(), RemoteError>>>,
    owner: Option<Box<dyn HostDataOwner>>,
}

impl HostDataRuntime {
    pub(super) async fn start(
        peer: Arc<RTCPeerConnection>,
        lease: LeaseControl,
        proved_permit: VerifiedPermit,
        permit_rx: watch::Receiver<VerifiedPermit>,
        pending: Arc<Mutex<HashMap<WebRtcDataChannel, PendingDataChannel>>>,
        cancel: watch::Sender<bool>,
        mut factory: Option<HostDataFactory>,
    ) -> Result<Option<Self>, WebRtcHostError> {
        let kinds = authorized_channels(&proved_permit);
        if kinds.is_empty() {
            return Ok(None);
        }
        let factory = factory.take().ok_or(WebRtcHostError::BusinessDataChannel)?;
        // This identity is immutable across setup activation and later lease
        // renewals. The live lease and permit_rx still authorize each payload.
        let digest = permit_digest(&proved_permit)?;
        let bindings: Vec<_> = kinds
            .iter()
            .copied()
            .map(|kind| WebRtcDataBinding::for_permit(proved_permit.claims(), digest, kind))
            .collect::<Result<_, _>>()?;
        let mut channels = wait_for_channels(&kinds, pending, &cancel).await?;

        let transport_channels: Vec<_> = kinds.iter().copied().map(transport_channel).collect();
        let generation = proved_permit.claims().connection_generation;
        let (external, ports) =
            ExternalChannelRuntime::new(lease.clone(), generation, &transport_channels)?;
        let claims = make_claims(&external, &proved_permit)?;
        let owner = factory(claims)?;

        let mut workers = Vec::with_capacity(kinds.len());
        for ((kind, port), binding) in kinds.into_iter().zip(ports).zip(bindings) {
            let entry = channels
                .remove(&kind)
                .ok_or(WebRtcHostError::BusinessDataChannel)?;
            let channel = entry.channel;
            let incoming = entry.messages;
            workers.push(spawn_data_worker(
                peer.clone(),
                cancel.clone(),
                permit_rx.clone(),
                channel,
                incoming,
                port,
                binding,
            ));
        }

        Ok(Some(Self {
            external,
            workers,
            owner: Some(owner),
        }))
    }

    pub(super) async fn shutdown(&mut self, reason: StopReason) -> Result<(), RemoteError> {
        let deadline = tokio::time::Instant::now() + DATA_WORKER_CLEANUP_TIMEOUT;
        let owner_result = if let Some(owner) = self.owner.as_mut() {
            Some(tokio::time::timeout_at(deadline, owner.shutdown(reason)).await)
        } else {
            None
        };
        if let Some(result) = owner_result {
            match result {
                Ok(Ok(())) => {
                    self.owner = None;
                }
                Ok(Err(error)) => {
                    return Err(error);
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "WebRTC data service owners are still cleaning up",
                    )
                    .into());
                }
            }
        }

        while !self.workers.is_empty() {
            let mut worker = self.workers.remove(0);
            match tokio::time::timeout_at(deadline, &mut worker).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => {
                    return Err(error);
                }
                Ok(Err(_)) => {
                    return Err(io::Error::other("WebRTC data worker task failed").into());
                }
                Err(_) => {
                    self.workers.insert(0, worker);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "WebRTC data workers are still cleaning up",
                    )
                    .into());
                }
            }
        }

        match tokio::time::timeout_at(deadline, self.external.wait_stopped()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "external WebRTC queue workers are still cleaning up",
            )
            .into()),
        }
    }
}

pub(super) fn authorized_channels(permit: &VerifiedPermit) -> Vec<WebRtcDataChannel> {
    [
        WebRtcDataChannel::FileRead,
        WebRtcDataChannel::FileWrite,
        WebRtcDataChannel::ClipboardRead,
        WebRtcDataChannel::ClipboardWrite,
    ]
    .into_iter()
    .filter(|channel| {
        permit
            .claims()
            .permissions
            .contains(&(channel.permission() as i32))
    })
    .collect()
}

pub(super) fn transport_channel(kind: WebRtcDataChannel) -> Channel {
    match kind {
        WebRtcDataChannel::FileRead => Channel::FileRead,
        WebRtcDataChannel::FileWrite => Channel::FileWrite,
        WebRtcDataChannel::ClipboardRead => Channel::ClipboardRead,
        WebRtcDataChannel::ClipboardWrite => Channel::ClipboardWrite,
        WebRtcDataChannel::Unspecified => Channel::Control,
    }
}

fn make_claims(
    runtime: &ExternalChannelRuntime,
    permit: &VerifiedPermit,
) -> Result<HostDataClaims, WebRtcHostError> {
    let claims = permit.claims();
    let has = |permission: Permission| claims.permissions.contains(&(permission as i32));
    let file_read = has(Permission::FileRead)
        .then(|| runtime.claim_file_read())
        .transpose()?;
    let file_write = has(Permission::FileWrite)
        .then(|| runtime.claim_file_write())
        .transpose()?;
    let clipboard_directions = ClipboardDirections {
        read: has(Permission::ClipboardRead),
        write: has(Permission::ClipboardWrite),
    };
    let clipboard = (!clipboard_directions.is_empty())
        .then(|| {
            runtime.claim_clipboard_transport(
                ClipboardBinding {
                    session_id: claims.session_id.clone(),
                    connection_generation: claims.connection_generation,
                },
                clipboard_directions,
            )
        })
        .transpose()?;
    Ok(HostDataClaims {
        file_read,
        file_write,
        clipboard,
    })
}

pub(super) async fn wait_for_channels(
    kinds: &[WebRtcDataChannel],
    pending: Arc<Mutex<HashMap<WebRtcDataChannel, PendingDataChannel>>>,
    cancel: &watch::Sender<bool>,
) -> Result<HashMap<WebRtcDataChannel, PendingDataChannel>, WebRtcHostError> {
    let deadline = tokio::time::Instant::now() + DATA_CHANNEL_OPEN_TIMEOUT;
    let mut cancelled = cancel.subscribe();
    loop {
        if *cancel.borrow() {
            return Err(WebRtcHostError::Closed);
        }
        let ready = {
            let channels = pending.lock().await;
            kinds.iter().all(|kind| {
                channels
                    .get(kind)
                    .is_some_and(|entry| entry.channel.ready_state() == RTCDataChannelState::Open)
            })
        };
        if ready {
            let mut channels = pending.lock().await;
            let mut selected = HashMap::with_capacity(kinds.len());
            for kind in kinds {
                let entry = channels
                    .remove(kind)
                    .ok_or(WebRtcHostError::BusinessDataChannel)?;
                selected.insert(*kind, entry);
            }
            return Ok(selected);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(WebRtcHostError::BusinessDataChannel);
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            changed = cancelled.changed() => {
                if changed.is_err() || *cancelled.borrow() {
                    return Err(WebRtcHostError::Closed);
                }
            }
        }
    }
}

pub(super) fn permit_digest(permit: &VerifiedPermit) -> Result<[u8; 32], WebRtcHostError> {
    Ok(permit.digest())
}

pub(super) fn spawn_data_worker(
    peer: Arc<RTCPeerConnection>,
    cancel: watch::Sender<bool>,
    mut permit: watch::Receiver<VerifiedPermit>,
    channel: Arc<RTCDataChannel>,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    mut port: ExternalDataChannelPort,
    binding: WebRtcDataBinding,
) -> JoinHandle<Result<(), RemoteError>> {
    tokio::spawn(async move {
        let result = async {
            let mut fragmenter = WebRtcDataFragmenter::new(binding.clone());
            let mut reassembler = WebRtcDataReassembler::new(binding);
            let mut cancelled = cancel.subscribe();
            loop {
                if *cancelled.borrow() {
                    return Ok(());
                }
                ensure_live(&permit.borrow().clone())
                    .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
                if channel.ready_state() != RTCDataChannelState::Open {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "business DataChannel is not open",
                    )
                    .into());
                }
                tokio::select! {
                    biased;
                    changed = cancelled.changed() => {
                        if changed.is_err() || *cancelled.borrow() {
                            return Ok(());
                        }
                    }
                    changed = permit.changed() => {
                        if changed.is_err() {
                            return Err(RemoteError::Stopped);
                        }
                    }
                    message = incoming.recv() => {
                        let message = message.ok_or_else(|| io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "business DataChannel inbound queue closed",
                        ))?;
                        let complete = reassembler.push(&message).map_err(RemoteError::Authorization)?;
                        if let Some(complete) = complete {
                            port.deliver_inbound(complete.payload)?;
                        }
                    }
                    outbound = port.next_outbound() => {
                        let mut outbound = outbound?;
                        let payload = outbound.check_before_fragment()?;
                        let (_, fragments) = fragmenter
                            .fragment(payload)
                            .map_err(RemoteError::Authorization)?;
                        for fragment in fragments {
                            outbound.check_before_fragment()?;
                            if fragment.len() > MAX_WEBRTC_DATA_FRAGMENT_BYTES {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "encoded fragment exceeds SCTP maxMessageSize",
                                ).into());
                            }
                            ensure_live(&permit.borrow().clone())
                                .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
                            channel
                                .send(&Bytes::from(fragment))
                                .await
                                .map_err(|error| io::Error::other(error.to_string()))?;
                        }
                    }
                }
            }
        }
        .await;

        if result.is_err() {
            cancel.send_replace(true);
            let _ = peer.close().await;
        }
        result
    })
}

/// Validate both peers' advertised SCTP receive limits before a data channel
/// is used. RFC 8841 defines zero as unlimited and omission as 65,536 bytes.
pub(super) fn validate_sctp_message_size(sdp: &str) -> Result<(), WebRtcHostError> {
    let mut in_application = false;
    let mut application_sections = 0usize;
    let mut declared: Option<u64> = None;
    for line in sdp.lines() {
        if let Some(media) = line.strip_prefix("m=") {
            in_application = media.starts_with("application ");
            if in_application {
                application_sections += 1;
                declared = None;
            }
            continue;
        }
        if !in_application {
            continue;
        }
        if let Some(value) = line.strip_prefix("a=max-message-size:") {
            if declared.is_some() {
                return Err(WebRtcHostError::InvalidOffer);
            }
            declared = Some(
                value
                    .parse::<u64>()
                    .map_err(|_| WebRtcHostError::InvalidOffer)?,
            );
        }
    }
    let Some(maximum) =
        (application_sections == 1).then_some(declared.unwrap_or(DEFAULT_SCTP_MAX_MESSAGE_SIZE))
    else {
        return Err(WebRtcHostError::InvalidOffer);
    };
    if maximum != 0 && maximum < MAX_WEBRTC_DATA_FRAGMENT_BYTES as u64 {
        return Err(WebRtcHostError::DataMessageSize);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn business_data_before_endpoint_proof_is_rejected_not_buffered() {
        let (sender, mut receiver) = mpsc::channel(DATA_CHANNEL_QUEUE_CAPACITY);
        let proof_complete = AtomicBool::new(false);
        let payload = b"pre-proof payload".to_vec();

        assert!(!queue_business_message(
            &proof_complete,
            &sender,
            DataChannelMessage {
                is_string: false,
                data: Bytes::from(payload),
            },
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        proof_complete.store(true, Ordering::Release);
        let payload = b"post-proof payload".to_vec();
        assert!(queue_business_message(
            &proof_complete,
            &sender,
            DataChannelMessage {
                is_string: false,
                data: Bytes::from(payload.clone()),
            },
        ));
        assert_eq!(receiver.try_recv(), Ok(payload));
    }

    #[test]
    fn business_data_after_proof_still_uses_a_bounded_queue() {
        let (sender, mut receiver) = mpsc::channel(DATA_CHANNEL_QUEUE_CAPACITY);
        let proof_complete = AtomicBool::new(true);
        for _ in 0..DATA_CHANNEL_QUEUE_CAPACITY {
            assert!(queue_business_message(
                &proof_complete,
                &sender,
                DataChannelMessage {
                    is_string: false,
                    data: Bytes::from_static(b"fragment"),
                },
            ));
        }
        assert!(!queue_business_message(
            &proof_complete,
            &sender,
            DataChannelMessage {
                is_string: false,
                data: Bytes::from_static(b"overflow"),
            },
        ));
        for _ in 0..DATA_CHANNEL_QUEUE_CAPACITY {
            assert_eq!(receiver.try_recv(), Ok(b"fragment".to_vec()));
        }
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn sctp_max_message_size_has_rfc_default_and_unlimited_semantics() {
        let sdp = "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
        assert!(validate_sctp_message_size(sdp).is_ok());
        assert!(
            validate_sctp_message_size(&format!(
                "{sdp}a=max-message-size:{}\r\n",
                MAX_WEBRTC_DATA_FRAGMENT_BYTES
            ))
            .is_ok()
        );
        assert!(
            validate_sctp_message_size(&format!(
                "{sdp}a=max-message-size:{}\r\n",
                MAX_WEBRTC_DATA_FRAGMENT_BYTES - 1
            ))
            .is_err()
        );
        assert!(validate_sctp_message_size(&format!("{sdp}a=max-message-size:0\r\n")).is_ok());
        assert!(
            validate_sctp_message_size(&format!(
                "{sdp}a=max-message-size:{}\r\na=max-message-size:0\r\n",
                MAX_WEBRTC_DATA_FRAGMENT_BYTES
            ))
            .is_err()
        );
    }
}
