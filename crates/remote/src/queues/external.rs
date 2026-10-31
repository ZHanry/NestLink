//! Bounded bridges between one ordered WebRTC DataChannel per business channel
//! and the existing lease-gated queue/service owners.
use super::{
    ChannelReceiver, ChannelSender, Queue, Queued, StopOnDrop, lease_io, permission, stop_io_result,
};
use crate::{LeaseControl, RemoteError};
use crate::{
    clipboard::{ClaimedClipboardTransport, ClipboardBinding, ClipboardDirections},
    files::ClaimedFileRead,
    upload::ClaimedFileWrite,
};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{io, sync::Arc, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle};

/// A decoded native envelope crossing the bounded remote-to-SDK edge. File and
/// clipboard consent is checked once before the first fragment and again before
/// every subsequent SCTP send. Revocation mid-message fails the peer instead
/// of switching to a fallback halfway through a fragmented envelope.
pub struct ExternalDataEnvelope {
    queued: Queued,
    started: bool,
    lease: LeaseControl,
}

impl ExternalDataEnvelope {
    fn new(queued: Queued, lease: LeaseControl) -> Self {
        Self {
            queued,
            started: false,
            lease,
        }
    }

    pub fn channel(&self) -> Channel {
        self.queued.frame.channel
    }

    /// Check current local disclosure authority immediately before one SCTP
    /// fragment is sent. The returned bytes are valid only until the next await.
    pub fn check_before_fragment(&mut self) -> io::Result<&[u8]> {
        if self.started {
            if self
                .queued
                .file_disclosure
                .as_ref()
                .and_then(|disclosure| disclosure.fallback())
                .is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "original local disclosure was revoked mid-message",
                ));
            }
        } else {
            self.queued.check_file_delivery();
            self.lease.charge_business(self.queued.frame.channel, self.queued.frame.payload.len()).map_err(io::Error::other)?;
            self.started = true;
        }
        if !self.queued.check_delivery() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "external data delivery authority was revoked",
            ));
        }
        Ok(&self.queued.frame.payload)
    }
}

/// SDK-facing half of an external reliable data channel. Each instance owns a
/// separate bounded inbound queue and outbound consumer.
pub struct ExternalDataChannelPort {
    channel: Channel,
    generation: u64,
    lease: LeaseControl,
    inbound: mpsc::Sender<Vec<u8>>,
    outbound: mpsc::Receiver<ExternalDataEnvelope>,
}

impl ExternalDataChannelPort {
    pub fn channel(&self) -> Channel {
        self.channel
    }

    /// Deliver one complete, reassembled native envelope received on this exact
    /// DataChannel. Overflow is fatal to this connection; it never spills into
    /// another channel's queue.
    pub fn deliver_inbound(&self, envelope: Vec<u8>) -> Result<(), RemoteError> {
        self.lease
            .check_channel_binding(self.channel, self.generation)?;
        if envelope.is_empty() || envelope.len() > self.channel.budget() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "external native envelope exceeds its channel budget",
            )
            .into());
        }
        self.inbound.try_send(envelope).map_err(|error| {
            let kind = match error {
                mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock,
                mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe,
            };
            io::Error::new(
                kind,
                "external data channel inbound queue is full or closed",
            )
            .into()
        })
    }

    /// Wait for one native response. The original generation and current lease
    /// are checked both before and after the bounded wait.
    pub async fn next_outbound(&mut self) -> Result<ExternalDataEnvelope, RemoteError> {
        self.lease
            .check_channel_binding(self.channel, self.generation)?;
        let envelope = lease_io(
            async {
                self.outbound.recv().await.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "external data channel closed")
                })
            },
            &self.lease,
        )
        .await?;
        self.lease
            .check_channel_binding(self.channel, self.generation)?;
        Ok(envelope)
    }
}

/// Owner for all WebRTC business-channel bridge tasks. Queue claims remain
/// one-shot and lease-bound. Call `wait_stopped` after stopping the lease; a
/// timeout leaves task handles here so cleanup can be retried.
pub struct ExternalChannelRuntime {
    lease: LeaseControl,
    generation: u64,
    incoming: Arc<Queue>,
    outgoing: Arc<Queue>,
    channels: Vec<Channel>,
    tasks: Vec<JoinHandle<Result<(), RemoteError>>>,
    cleanup_failure: Option<io::ErrorKind>,
}

impl ExternalChannelRuntime {
    /// Create an isolated bounded queue/worker pair for every approved business
    /// direction. The caller must only invoke this after mutual endpoint proof.
    pub fn new(
        lease: LeaseControl,
        generation: u64,
        channels: &[Channel],
    ) -> Result<(Self, Vec<ExternalDataChannelPort>), RemoteError> {
        if channels.is_empty()
            || channels.len() > 4
            || channels.iter().any(|channel| {
                !matches!(
                    channel,
                    Channel::FileRead
                        | Channel::FileWrite
                        | Channel::ClipboardRead
                        | Channel::ClipboardWrite
                )
            })
            || channels
                .iter()
                .enumerate()
                .any(|(index, channel)| channels[..index].contains(channel))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid or duplicate external business channel",
            )
            .into());
        }
        for channel in channels {
            lease.check_channel_binding(*channel, generation)?;
        }

        let incoming = Queue::new();
        let outgoing = Queue::new();
        let mut ports = Vec::with_capacity(channels.len());
        let mut tasks = Vec::with_capacity(channels.len() * 2);
        for channel in channels.iter().copied() {
            let (inbound_tx, inbound_rx) = mpsc::channel(EXTERNAL_CHANNEL_CAPACITY);
            let (outbound_tx, outbound_rx) = mpsc::channel(EXTERNAL_CHANNEL_CAPACITY);
            ports.push(ExternalDataChannelPort {
                channel,
                generation,
                lease: lease.clone(),
                inbound: inbound_tx,
                outbound: outbound_rx,
            });
            tasks.push(spawn_external_reader(
                lease.clone(),
                generation,
                channel,
                inbound_rx,
                incoming.clone(),
            ));
            tasks.push(spawn_external_writer(
                lease.clone(),
                generation,
                channel,
                outgoing.clone(),
                outbound_tx,
            ));
        }

        Ok((
            Self {
                lease,
                generation,
                incoming,
                outgoing,
                channels: channels.to_vec(),
                tasks,
                cleanup_failure: None,
            },
            ports,
        ))
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn lease_control(&self) -> LeaseControl {
        self.lease.clone()
    }

    pub fn sender(&self) -> ChannelSender {
        ChannelSender {
            lease: self.lease.clone(),
            outgoing: self.outgoing.clone(),
        }
    }

    /// Claim one provisioned incoming business channel. A duplicate or
    /// unapproved claim fails closed and can never be reassigned.
    pub fn claim_channel(&self, channel: Channel) -> Result<ChannelReceiver, RemoteError> {
        if !self.channels.contains(&channel) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "external channel was not provisioned",
            )
            .into());
        }
        self.lease.check_channel_binding(channel, self.generation)?;
        let index = super::CHANNELS
            .iter()
            .position(|candidate| *candidate == channel)
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

    /// Start a server after Core has claimed this exact file-read channel.
    pub fn claim_file_read(&self) -> Result<ClaimedFileRead, RemoteError> {
        self.claim_file_read_for_generation(self.generation)
    }

    pub fn claim_file_read_for_generation(
        &self,
        generation: u64,
    ) -> Result<ClaimedFileRead, RemoteError> {
        if generation != self.generation {
            return Err(
                io::Error::new(io::ErrorKind::PermissionDenied, "stale data generation").into(),
            );
        }
        self.lease
            .check_channel_binding(Channel::FileRead, generation)?;
        Ok(ClaimedFileRead {
            receiver: self.claim_channel(Channel::FileRead)?,
            sender: self.sender(),
            lease: self.lease.clone(),
            generation,
        })
    }

    pub fn claim_file_write(&self) -> Result<ClaimedFileWrite, RemoteError> {
        self.lease
            .check_channel_binding(Channel::FileWrite, self.generation)?;
        Ok(ClaimedFileWrite {
            receiver: self.claim_channel(Channel::FileWrite)?,
            sender: self.sender(),
            lease: self.lease.clone(),
            generation: self.generation,
        })
    }

    pub fn claim_clipboard_transport(
        &self,
        binding: ClipboardBinding,
        directions: ClipboardDirections,
    ) -> Result<ClaimedClipboardTransport, RemoteError> {
        if directions.is_empty()
            || binding.connection_generation != self.generation
            || self.lease.clipboard_session_id(
                if directions.read {
                    Channel::ClipboardRead
                } else {
                    Channel::ClipboardWrite
                },
                self.generation,
            )? != binding.session_id
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "clipboard binding does not match the external session",
            )
            .into());
        }
        let read = if directions.read {
            Some(self.claim_channel(Channel::ClipboardRead)?)
        } else {
            None
        };
        let write = if directions.write {
            Some(self.claim_channel(Channel::ClipboardWrite)?)
        } else {
            None
        };
        ClaimedClipboardTransport::from_external_parts(
            self.lease.clone(),
            self.sender(),
            binding,
            directions,
            read,
            write,
        )
    }

    pub async fn wait_stopped(&mut self) -> Result<(), RemoteError> {
        if self.lease.subscribe_stopped().borrow().is_none() {
            let mut stopped = self.lease.subscribe_stopped();
            while stopped.borrow().is_none() {
                stopped.changed().await.map_err(|_| RemoteError::Stopped)?;
            }
        }
        self.incoming.close();
        self.outgoing.close();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while let Some(task) = self.tasks.first_mut() {
            match tokio::time::timeout_at(deadline, &mut *task).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => {
                    self.cleanup_failure.get_or_insert(io::ErrorKind::Other);
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "WebRTC data workers are still cleaning up",
                    )
                    .into());
                }
            }
            self.tasks.remove(0);
        }
        if let Some(failure) = self.cleanup_failure {
            return Err(io::Error::new(failure, "WebRTC data worker cleanup failed").into());
        }
        Ok(())
    }

    pub async fn shutdown(&mut self, reason: StopReason) -> Result<(), RemoteError> {
        self.lease.stop(reason)?;
        self.incoming.close();
        self.outgoing.close();
        self.wait_stopped().await
    }
}

impl Drop for ExternalChannelRuntime {
    fn drop(&mut self) {
        let _ = self.lease.stop(StopReason::ExplicitExit);
        self.incoming.close();
        self.outgoing.close();
        // Dropping JoinHandles detaches bounded bridge tasks which retain their
        // own leases and channel endpoints until the stop notification arrives.
        self.tasks.clear();
    }
}

const EXTERNAL_CHANNEL_CAPACITY: usize = 4;

fn spawn_external_reader(
    lease: LeaseControl,
    generation: u64,
    channel: Channel,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    queue: Arc<Queue>,
) -> JoinHandle<Result<(), RemoteError>> {
    tokio::spawn(async move {
        let _scope = StopOnDrop(lease.clone());
        let result = async {
            loop {
                let envelope = lease_io(
                    async {
                        inbound.recv().await.ok_or_else(|| {
                            io::Error::new(io::ErrorKind::BrokenPipe, "WebRTC data channel closed")
                        })
                    },
                    &lease,
                )
                .await?;
                lease.check_channel_binding(channel, generation)?;
                if envelope.is_empty() || envelope.len() > channel.budget() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "external native envelope exceeds channel budget",
                    )
                    .into());
                }
                lease.charge_business(channel, envelope.len())?;
                queue.put(&lease, channel, &envelope).await?;
            }
        }
        .await;
        stop_io_result(&lease, &result);
        queue.close();
        result
    })
}

fn spawn_external_writer(
    lease: LeaseControl,
    generation: u64,
    channel: Channel,
    queue: Arc<Queue>,
    outbound: mpsc::Sender<ExternalDataEnvelope>,
) -> JoinHandle<Result<(), RemoteError>> {
    tokio::spawn(async move {
        let _scope = StopOnDrop(lease.clone());
        let result = async {
            loop {
                let queued = queue.take_queued(&lease, Some(channel)).await?;
                lease.check_channel_binding(channel, generation)?;
                let envelope = ExternalDataEnvelope::new(queued, lease.clone());
                // Keep the original per-channel delivery guard attached across
                // the SDK's bounded SCTP send queue.
                lease_io(
                    async {
                        outbound.send(envelope).await.map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "WebRTC data channel writer closed",
                            )
                        })
                    },
                    &lease,
                )
                .await?;
            }
        }
        .await;
        stop_io_result(&lease, &result);
        queue.close();
        result
    })
}
