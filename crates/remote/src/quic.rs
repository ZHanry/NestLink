//! One bound unidirectional stream per reliable business channel and direction.
//! Audio uses bounded, expiring QUIC datagram fragments. The proof stream stays
//! owned until terminal stop; any extra stream or control payload fails closed.
use crate::{
    ChannelRuntime, LeaseControl, RemoteError, SessionSetup, controller_proof, host_proof,
    lease_io,
    queues::{CloseQuicOnDrop, Queue, Queued, StopOnDrop, stop_io_result, write_media_bounded},
};
use nestlink_identity::InstallationIdentity;
use nestlink_protocol::{
    AUDIO_FRAME_BYTES, NativeQuicAudioFragment, NativeQuicProfile, NativeQuicStream,
    QUIC_AUDIO_AGE_MS, QUIC_AUDIO_FRAGMENT_BYTES, QUIC_AUDIO_PENDING_PACKETS, QUIC_DATAGRAM_BYTES,
    QUIC_SETUP_BYTES, SCHEMA_VERSION, decode_bounded,
};
use nestlink_session::{EndpointRole, StopReason};
use nestlink_transport_stream::{Channel, Frame, read_channel_frame, write_frame};
use prost::Message;
use std::{
    collections::BTreeMap,
    future::Future,
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{io::AsyncReadExt, task::JoinHandle};

const AGE: Duration = Duration::from_millis(QUIC_AUDIO_AGE_MS);
const FRAGMENT: usize = QUIC_AUDIO_FRAGMENT_BYTES as usize;
const SETUP_BUDGET: Duration = Duration::from_secs(3);

struct SetupGuard {
    connection: Option<quinn::Connection>,
    lease: Option<LeaseControl>,
}
impl Drop for SetupGuard {
    fn drop(&mut self) {
        if let Some(lease) = &self.lease {
            let _ = lease.stop(StopReason::Revoked);
        }
        if let Some(connection) = &self.connection {
            connection.close(1u32.into(), b"native session ended");
        }
    }
}
fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
fn spawn(
    lease: &LeaseControl,
    incoming: &Arc<Queue>,
    outgoing: &Arc<Queue>,
    future: impl Future<Output = Result<(), RemoteError>> + Send + 'static,
) -> JoinHandle<Result<(), RemoteError>> {
    let lease = lease.clone();
    let incoming = incoming.clone();
    let outgoing = outgoing.clone();
    tokio::spawn(async move {
        let _stop = StopOnDrop(lease.clone());
        let result = future.await;
        stop_io_result(&lease, &result);
        incoming.close();
        outgoing.close();
        result
    })
}

/// Owns proof, profile negotiation and all business I/O. The optional endpoint
/// is retained for the lifetime of the session. No stream-mode fallback occurs.
pub async fn authorize(
    connection: quinn::Connection,
    endpoint: Option<quinn::Endpoint>,
    setup: SessionSetup,
    identity: &InstallationIdentity,
    peer_key: &[u8; 32],
) -> Result<ChannelRuntime, RemoteError> {
    let mut guard = SetupGuard {
        connection: Some(connection.clone()),
        lease: None,
    };
    let SessionSetup {
        mut session,
        path,
        role,
        clock,
        lifecycle,
    } = setup;
    let deadline = tokio::time::Instant::now() + SETUP_BUDGET;
    let proof = async {
        let (mut write, mut read) = match role {
            EndpointRole::Controller => connection.open_bi().await,
            EndpointRole::Host => connection.accept_bi().await,
        }
        .map_err(io::Error::other)?;
        match role {
            EndpointRole::Controller => {
                controller_proof(
                    &mut read,
                    &mut write,
                    &mut session,
                    identity,
                    peer_key,
                    &clock,
                )
                .await?
            }
            EndpointRole::Host => {
                host_proof(
                    &mut read,
                    &mut write,
                    &mut session,
                    identity,
                    peer_key,
                    &clock,
                )
                .await?
            }
        }
        Ok::<_, RemoteError>((write, read))
    };
    // Independent business streams/datagrams are forbidden before mutual proof.
    let (mut control_write, mut control_read) = tokio::time::timeout_at(deadline, async {
        tokio::select! { biased;
            _ = connection.accept_uni() => Err(invalid("business stream before endpoint proof").into()),
            _ = connection.read_datagram() => Err(invalid("datagram before endpoint proof").into()),
            result = proof => result,
        }
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC session setup budget exhausted"))??;
    let lease = LeaseControl::new(session, path, clock, lifecycle)?;
    guard.lease = Some(lease.clone());
    let renewal = if lease.native_renewal_required()? {
        crate::native_renewal::negotiate(&mut control_read, &mut control_write, &lease).await?;
        Some(crate::native_renewal::pair(&lease))
    } else {
        None
    };
    let (binding, generation, channels) = lease.transport_binding()?;
    let audio = channels.contains(&Channel::Audio);
    let reliable: Vec<_> = channels
        .into_iter()
        .filter(|channel| *channel != Channel::Audio)
        .collect();
    if audio
        && connection
            .max_datagram_size()
            .is_none_or(|size| size < QUIC_DATAGRAM_BYTES as usize)
    {
        return Err(invalid("approved audio requires QUIC datagram support and MTU").into());
    }
    let profile = NativeQuicProfile {
        schema_version: SCHEMA_VERSION,
        binding_sha256: binding.to_vec(),
        connection_generation: generation,
        reliable_channels: reliable.iter().map(|channel| *channel as u32).collect(),
        audio_fragment_bytes: if audio {
            QUIC_AUDIO_FRAGMENT_BYTES as u32
        } else {
            0
        },
    };
    let negotiated = async {
        lease_io(
            write_frame(
                &mut control_write,
                Channel::Control,
                &profile.encode_to_vec(),
            ),
            &lease,
        )
        .await?;
        let peer = lease_io(
            read_channel_frame(
                &mut control_read,
                Channel::Control,
                QUIC_SETUP_BYTES as usize,
            ),
            &lease,
        )
        .await?;
        let peer: NativeQuicProfile = decode_bounded(&peer.payload, QUIC_SETUP_BYTES)?;
        if peer != profile {
            return Err(invalid("QUIC profile, permission or binding mismatch").into());
        }
        let mut writes = Vec::new();
        for &channel in &reliable {
            let mut write = lease_io(
                async { connection.open_uni().await.map_err(io::Error::other) },
                &lease,
            )
            .await?;
            write
                .set_priority(match channel {
                    Channel::Input | Channel::VideoFeedback => 10,
                    Channel::FileRead | Channel::FileWrite => -10,
                    _ => 0,
                })
                .map_err(io::Error::other)?;
            let header = NativeQuicStream {
                schema_version: SCHEMA_VERSION,
                binding_sha256: binding.to_vec(),
                connection_generation: generation,
                channel: channel as u32,
            };
            lease_io(
                write_frame(&mut write, Channel::Control, &header.encode_to_vec()),
                &lease,
            )
            .await?;
            writes.push((channel, write));
        }
        let mut reads = Vec::new();
        while reads.len() < reliable.len() {
            let mut read = lease_io(
                async { connection.accept_uni().await.map_err(io::Error::other) },
                &lease,
            )
            .await?;
            let header = lease_io(
                read_channel_frame(&mut read, Channel::Control, QUIC_SETUP_BYTES as usize),
                &lease,
            )
            .await?;
            let header: NativeQuicStream = decode_bounded(&header.payload, QUIC_SETUP_BYTES)?;
            let channel = Channel::decode(
                u8::try_from(header.channel).map_err(|_| invalid("unknown QUIC stream channel"))?,
            )?;
            if header.schema_version != SCHEMA_VERSION
                || header.binding_sha256 != binding
                || header.connection_generation != generation
                || !reliable.contains(&channel)
                || reads.iter().any(|(existing, _)| *existing == channel)
            {
                return Err(
                    invalid("unapproved, duplicate or incorrectly bound QUIC stream").into(),
                );
            }
            lease.authorize(channel)?;
            reads.push((channel, read));
        }
        Ok::<_, RemoteError>((writes, reads))
    };
    let (writes, reads) = tokio::time::timeout_at(deadline, negotiated)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "QUIC channel negotiation budget exhausted",
            )
        })??;
    let incoming = Queue::new();
    let outgoing = Queue::new();
    let mut tasks = Vec::new();
    for (channel, mut read) in reads {
        let reader_lease = lease.clone();
        let queue = incoming.clone();
        tasks.push(spawn(&lease, &incoming, &outgoing, async move {
            loop {
                let frame = lease_io(
                    read_channel_frame(&mut read, channel, channel.budget()),
                    &reader_lease,
                )
                .await?;
                reader_lease.authorize(channel)?;
                queue.put(&reader_lease, channel, &frame.payload).await?;
            }
        }));
    }
    for (channel, mut write) in writes {
        let writer_lease = lease.clone();
        let queue = outgoing.clone();
        tasks.push(spawn(&lease, &incoming, &outgoing, async move {
            loop {
                let mut queued = queue.take_queued(&writer_lease, Some(channel)).await?;
                writer_lease.authorize(channel)?;
                queued.check_file_delivery();
                if !queued.check_delivery() {
                    continue;
                }
                let delivery_guard = queued.delivery_guard();
                let written = lease_io(
                    async {
                        if delivery_guard
                            .as_ref()
                            .is_some_and(|guard| guard.check().is_err())
                        {
                            return Ok(false);
                        }
                        write_media_bounded(
                            &mut write,
                            channel,
                            &queued.frame.payload,
                            queued.arrived,
                        )
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
        }));
    }
    if audio {
        let writer_lease = lease.clone();
        let queue = outgoing.clone();
        let connection = connection.clone();
        tasks.push(spawn(&lease, &incoming, &outgoing, async move {
            let mut sequence = 0u64;
            loop {
                let queued = queue
                    .take_queued(&writer_lease, Some(Channel::Audio))
                    .await?;
                sequence = sequence
                    .checked_add(1)
                    .filter(|sequence| *sequence <= i64::MAX as u64)
                    .ok_or_else(|| invalid("QUIC audio sequence exhausted"))?;
                let fragments =
                    fragment_audio(binding, generation, sequence, &queued.frame.payload)?;
                // Drop congestion/MTU losses without waiting behind reliable
                // files or delivering a partial packet to a media decoder.
                if queued.arrived.elapsed() >= AGE
                    || fragments.iter().any(|bytes| {
                        connection
                            .max_datagram_size()
                            .is_none_or(|max| bytes.len() > max)
                    })
                    || connection.datagram_send_buffer_space()
                        < fragments.iter().map(Vec::len).sum::<usize>()
                {
                    continue;
                }
                for fragment in fragments {
                    if queued.arrived.elapsed() >= AGE {
                        break;
                    }
                    writer_lease.operation(nestlink_protocol::Permission::Audio, || {
                        connection
                            .send_datagram(fragment.into())
                            .map_err(io::Error::other)
                    })?;
                }
            }
        }));
    }
    let reader_lease = lease.clone();
    let queue = incoming.clone();
    let datagrams = connection.clone();
    tasks.push(spawn(&lease, &incoming, &outgoing, async move {
        let mut assembler = AudioAssembler::new(binding, generation);
        loop {
            let bytes = lease_io(
                async { datagrams.read_datagram().await.map_err(io::Error::other) },
                &reader_lease,
            )
            .await?;
            reader_lease.authorize(Channel::Audio)?;
            if let Some(queued) = assembler.push(&bytes, Instant::now())? {
                queue
                    .put_at(
                        &reader_lease,
                        Channel::Audio,
                        &queued.frame.payload,
                        queued.arrived,
                    )
                    .await?;
            }
        }
    }));
    let mut reserved_read = Some(control_read);
    let mut reserved_write = Some(control_write);
    let renewal_port = if let Some((port, mut io)) = renewal {
        let mut read = reserved_read
            .take()
            .ok_or_else(|| invalid("renewal read owner missing"))?;
        let mut write = reserved_write
            .take()
            .ok_or_else(|| invalid("renewal write owner missing"))?;
        let reader_lease = lease.clone();
        tasks.push(spawn(&lease, &incoming, &outgoing, async move {
            loop {
                let frame = lease_io(
                    read_channel_frame(
                        &mut read,
                        Channel::Control,
                        nestlink_protocol::native_renewal::MAX_BYTES,
                    ),
                    &reader_lease,
                )
                .await?;
                io.incoming
                    .try_send(frame.payload)
                    .map_err(|_| invalid("native control queue overflow or closed"))?;
            }
        }));
        let writer_lease = lease.clone();
        tasks.push(spawn(&lease, &incoming, &outgoing, async move {
            loop {
                let bytes = lease_io(
                    async {
                        io.outgoing
                            .recv()
                            .await
                            .ok_or_else(|| invalid("native control owner closed"))
                    },
                    &writer_lease,
                )
                .await?;
                lease_io(
                    write_frame(&mut write, Channel::Control, &bytes),
                    &writer_lease,
                )
                .await?;
            }
        }));
        Some(port)
    } else {
        None
    };
    // Failure, idle revoke, network change, drop or panic closes the actual
    // connection, including blocked streams and queued native datagrams.
    let monitor_lease = lease.clone();
    let monitor = connection.clone();
    tasks.push(spawn(&lease, &incoming, &outgoing, async move {
        let _guard = CloseQuicOnDrop(monitor.clone(), monitor_lease.clone());
        let _write = reserved_write;
        lease_io(async {
            tokio::select! { biased;
                error = monitor.closed() => Err(io::Error::other(error)),
                result = monitor.accept_uni() => match result { Ok(_) => Err(invalid("unexpected extra QUIC business stream")), Err(error) => Err(io::Error::other(error)) },
                result = monitor.accept_bi() => match result { Ok(_) => Err(invalid("unexpected extra QUIC control stream")), Err(error) => Err(io::Error::other(error)) },
                result = async {match &mut reserved_read {Some(read)=>read.read_u8().await,None=>std::future::pending().await}} => match result { Ok(_) => Err(invalid("reserved proof stream received extra data")), Err(error) => Err(error) },
            }
        }, &monitor_lease).await
    }));
    guard.lease = None;
    guard.connection = None;
    Ok(
        ChannelRuntime::quic(lease, incoming, outgoing, tasks, connection, endpoint)
            .with_native_renewal(renewal_port),
    )
}

fn fragment_audio(
    binding: [u8; 32],
    generation: u64,
    sequence: u64,
    payload: &[u8],
) -> io::Result<Vec<Vec<u8>>> {
    if payload.is_empty() || payload.len() > AUDIO_FRAME_BYTES as usize {
        return Err(invalid("invalid QUIC audio packet size"));
    }
    let count = payload.len().div_ceil(FRAGMENT) as u32;
    Ok(payload
        .chunks(FRAGMENT)
        .enumerate()
        .map(|(index, payload_fragment)| {
            NativeQuicAudioFragment {
                schema_version: SCHEMA_VERSION,
                binding_sha256: binding.to_vec(),
                connection_generation: generation,
                packet_sequence: sequence,
                fragment_index: index as u32,
                fragment_count: count,
                packet_bytes: payload.len() as u32,
                payload: payload_fragment.to_vec(),
            }
            .encode_to_vec()
        })
        .collect())
}
struct PartialAudio {
    arrived: Instant,
    bytes: usize,
    fragments: Vec<Option<Vec<u8>>>,
}
struct AudioAssembler {
    binding: [u8; 32],
    generation: u64,
    floor: u64,
    packets: BTreeMap<u64, PartialAudio>,
}
impl AudioAssembler {
    fn new(binding: [u8; 32], generation: u64) -> Self {
        Self {
            binding,
            generation,
            floor: 0,
            packets: BTreeMap::new(),
        }
    }
    fn push(&mut self, bytes: &[u8], now: Instant) -> Result<Option<Queued>, RemoteError> {
        let fragment: NativeQuicAudioFragment = decode_bounded(bytes, QUIC_DATAGRAM_BYTES)?;
        let size = fragment.packet_bytes as usize;
        let index = fragment.fragment_index as usize;
        let count = size.div_ceil(FRAGMENT);
        if fragment.schema_version != SCHEMA_VERSION
            || fragment.binding_sha256 != self.binding
            || fragment.connection_generation != self.generation
            || fragment.packet_sequence == 0
            || fragment.packet_sequence > i64::MAX as u64
            || size == 0
            || size > AUDIO_FRAME_BYTES as usize
            || fragment.fragment_count as usize != count
            || index >= count
            || fragment.payload.len() != (size.saturating_sub(index * FRAGMENT)).min(FRAGMENT)
        {
            return Err(invalid("malformed or incorrectly bound QUIC audio fragment").into());
        }
        // Duplicates never renew first arrival. Expired or evicted sequences
        // cannot be reassembled later; stale audio cannot refill the queue.
        for (&sequence, packet) in &self.packets {
            if now.saturating_duration_since(packet.arrived) >= AGE {
                self.floor = self.floor.max(sequence);
            }
        }
        self.packets.retain(|sequence, _| *sequence > self.floor);
        if fragment.packet_sequence <= self.floor {
            return Ok(None);
        }
        if !self.packets.contains_key(&fragment.packet_sequence)
            && self.packets.len() >= QUIC_AUDIO_PENDING_PACKETS as usize
        {
            if let Some((sequence, _)) = self.packets.pop_first() {
                self.floor = self.floor.max(sequence);
            }
            if fragment.packet_sequence <= self.floor {
                return Ok(None);
            }
        }
        let packet = self
            .packets
            .entry(fragment.packet_sequence)
            .or_insert_with(|| PartialAudio {
                arrived: now,
                bytes: size,
                fragments: vec![None; count],
            });
        if packet.bytes != size || packet.fragments.len() != count {
            return Err(invalid("conflicting QUIC audio packet metadata").into());
        }
        if let Some(existing) = &packet.fragments[index] {
            if *existing != fragment.payload {
                return Err(invalid("conflicting QUIC audio duplicate").into());
            }
            return Ok(None);
        }
        packet.fragments[index] = Some(fragment.payload);
        if packet.fragments.iter().any(Option::is_none) {
            return Ok(None);
        }
        let payload = packet
            .fragments
            .iter_mut()
            .filter_map(Option::take)
            .flatten()
            .collect();
        let arrived = packet.arrived;
        self.floor = fragment.packet_sequence;
        self.packets.retain(|sequence, _| *sequence > self.floor);
        Ok(Some(Queued {
            frame: Frame {
                channel: Channel::Audio,
                payload,
            },
            arrived,
            file_disclosure: None,
            delivery_guard: None,
        }))
    }
}

#[cfg(test)]
mod tests;
