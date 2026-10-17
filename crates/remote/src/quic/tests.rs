use super::*;
use crate::{RuntimeClock, SessionLifecycle, TransportMode};
use nestlink_auth::random_id;
use nestlink_identity::{PermitSigner, verify_permit};
use nestlink_policy::PathSet;
use nestlink_protocol::{Path, Permission, PermitClaims};
use nestlink_session::{Session, SessionBinding};
use nestlink_transport_quic::{connect, connector, listener};
use tokio::sync::watch;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn datagrams_reassemble_reordered_fragments_once_and_bound_memory_and_age() -> Result {
    let binding = [7; 32];
    let now = Instant::now();
    let payload = vec![17; AUDIO_FRAME_BYTES as usize];
    let fragments = fragment_audio(binding, 9, 1, &payload)?;
    assert_eq!(fragments.len(), 3);
    assert!(
        fragments
            .iter()
            .all(|bytes| bytes.len() <= QUIC_DATAGRAM_BYTES as usize)
    );
    let mut assembler = AudioAssembler::new(binding, 9);
    assert!(assembler.push(&fragments[2], now)?.is_none());
    assert!(assembler.push(&fragments[0], now)?.is_none());
    assert!(assembler.push(&fragments[0], now + AGE / 2)?.is_none());
    let complete = assembler
        .push(&fragments[1], now + AGE / 2)?
        .ok_or("missing packet")?;
    assert_eq!(complete.frame.payload, payload);
    assert_eq!(complete.arrived, now);
    assert!(assembler.push(&fragments[1], now + AGE / 2)?.is_none());
    for sequence in 2..=20 {
        let packet = fragment_audio(binding, 9, sequence, &payload)?;
        assert!(assembler.push(&packet[0], now)?.is_none());
        assert!(assembler.packets.len() <= QUIC_AUDIO_PENDING_PACKETS as usize);
    }
    let expired = fragment_audio(binding, 9, 20, &payload)?;
    for fragment in &expired {
        assert!(assembler.push(fragment, now + AGE)?.is_none());
    }
    assert!(assembler.packets.is_empty());
    let next = fragment_audio(binding, 9, 21, b"new packet")?;
    assert_eq!(
        assembler
            .push(&next[0], now + AGE)?
            .ok_or("new packet dropped")?
            .frame
            .payload,
        b"new packet"
    );
    // A completed later packet makes reordered older packets harmless losses.
    let older = fragment_audio(binding, 9, 19, &payload)?;
    assert!(assembler.push(&older[0], now + AGE)?.is_none());
    Ok(())
}

#[test]
fn datagrams_reject_wrong_binding_geometry_conflicting_duplicates_and_budget() -> Result {
    let now = Instant::now();
    let original = fragment_audio([7; 32], 9, 1, &vec![1; 1000])?;
    for mutation in 0..10 {
        let mut fragment = NativeQuicAudioFragment::decode(original[0].as_slice())?;
        match mutation {
            0 => fragment.schema_version = 2,
            1 => fragment.binding_sha256[0] = 6,
            2 => fragment.connection_generation = 8,
            3 => fragment.packet_sequence = 0,
            4 => fragment.packet_sequence = u64::MAX,
            5 => fragment.fragment_index = u32::MAX,
            6 => fragment.fragment_count = u32::MAX,
            7 => fragment.packet_bytes = u32::MAX,
            8 => fragment.payload.clear(),
            _ => fragment.payload.push(2),
        }
        assert!(
            AudioAssembler::new([7; 32], 9)
                .push(&fragment.encode_to_vec(), now)
                .is_err()
        );
    }
    let mut assembler = AudioAssembler::new([7; 32], 9);
    assert!(assembler.push(&original[0], now)?.is_none());
    let mut duplicate = NativeQuicAudioFragment::decode(original[0].as_slice())?;
    duplicate.payload[0] = 2;
    assert!(assembler.push(&duplicate.encode_to_vec(), now).is_err());
    assert!(
        assembler
            .push(&vec![0; QUIC_DATAGRAM_BYTES as usize + 1], now)
            .is_err()
    );
    assert!(fragment_audio([7; 32], 9, 1, &[]).is_err());
    assert!(fragment_audio([7; 32], 9, 1, &vec![0; AUDIO_FRAME_BYTES as usize + 1]).is_err());
    let maximum = fragment_audio(
        [255; 32],
        i64::MAX as u64,
        i64::MAX as u64,
        &vec![0; AUDIO_FRAME_BYTES as usize],
    )?;
    assert!(
        maximum
            .iter()
            .all(|bytes| bytes.len() <= QUIC_DATAGRAM_BYTES as usize)
    );
    Ok(())
}

struct Fixture {
    host: InstallationIdentity,
    controller: InstallationIdentity,
    clock: RuntimeClock,
    signer: PermitSigner,
    claims: PermitClaims,
    binding: SessionBinding,
    server: quinn::Endpoint,
    client: quinn::Endpoint,
}
impl Fixture {
    fn new(permissions: Vec<Permission>) -> Result<Self> {
        let host = InstallationIdentity::generate();
        let controller = InstallationIdentity::generate();
        let clock = RuntimeClock::default();
        let binding = SessionBinding {
            deployment_id: random_id(),
            security_epoch: 1,
            session_id: random_id(),
            account_id: random_id(),
            controller_device_id: random_id(),
            host_device_id: random_id(),
            controller_key_sha256: controller.fingerprint(),
            host_key_sha256: host.fingerprint(),
            resource_id: random_id(),
            policy_revision: 1,
            connection_generation: 7,
            capability_sha256: [9; 32],
            granted_permissions: permissions.clone(),
            supported_capabilities: vec!["vp8".into()],
            local_paths: PathSet::DIRECT,
        };
        let now = clock.sample()?;
        let claims = PermitClaims {
            schema_version: 1,
            deployment_id: binding.deployment_id.clone(),
            security_epoch: 1,
            session_id: binding.session_id.clone(),
            account_id: binding.account_id.clone(),
            controller_device_id: binding.controller_device_id.clone(),
            host_device_id: binding.host_device_id.clone(),
            controller_key_sha256: controller.fingerprint().to_vec(),
            host_key_sha256: host.fingerprint().to_vec(),
            resource_id: binding.resource_id.clone(),
            permissions: permissions
                .iter()
                .map(|permission| *permission as i32)
                .collect(),
            paths: vec![Path::Direct as i32],
            policy_revision: 1,
            connection_generation: 7,
            lease_sequence: 1,
            issued_at_unix_ms: now.unix_ms,
            expires_at_unix_ms: now.unix_ms + 15000,
            capability_sha256: vec![9; 32],
            required_capabilities: vec!["vp8".into()],
        };
        let server = listener("127.0.0.1:0".parse()?, &host, controller.fingerprint())?;
        let client = connector("127.0.0.1:0".parse()?, &controller, host.fingerprint())?;
        Ok(Self {
            host,
            controller,
            clock,
            signer: PermitSigner::generate(),
            claims,
            binding,
            server,
            client,
        })
    }
    fn setup(
        &self,
        role: EndpointRole,
        stop: watch::Receiver<Option<StopReason>>,
    ) -> Result<SessionSetup> {
        let session = Session::activate(
            verify_permit(
                &self.signer.sign(&self.claims)?.encode_to_vec(),
                &self.signer.public_key(),
            )?,
            self.binding.clone(),
            Path::Direct,
            0,
            self.clock.sample()?,
        )?;
        Ok(SessionSetup {
            session,
            path: Path::Direct,
            role,
            clock: self.clock.clone(),
            lifecycle: SessionLifecycle::new(stop),
        })
    }
    async fn connections(&self) -> Result<(quinn::Connection, quinn::Connection)> {
        let accept = async {
            self.server
                .accept()
                .await
                .ok_or("missing QUIC request")?
                .await
                .map_err(Into::into)
        };
        let (c, h) = tokio::try_join!(
            connect(
                &self.client,
                self.server.local_addr()?,
                Duration::from_secs(2)
            ),
            accept
        )?;
        Ok((c, h))
    }
    async fn runtimes(
        &self,
        c_stop: watch::Receiver<Option<StopReason>>,
        h_stop: watch::Receiver<Option<StopReason>>,
    ) -> Result<(ChannelRuntime, ChannelRuntime, quinn::Connection)> {
        let (c, h) = self.connections().await?;
        let retained = c.clone();
        let host_key = self.host.public_key();
        let controller_key = self.controller.public_key();
        let (c, h) = tokio::try_join!(
            authorize(
                c,
                Some(self.client.clone()),
                self.setup(EndpointRole::Controller, c_stop)?,
                &self.controller,
                &host_key
            ),
            authorize(
                h,
                Some(self.server.clone()),
                self.setup(EndpointRole::Host, h_stop)?,
                &self.host,
                &controller_key
            )
        )?;
        Ok((c, h, retained))
    }
}

#[tokio::test]
async fn actual_quic_blocked_file_does_not_block_input_audio_renewal_or_revoke() -> Result {
    let mut fixture = Fixture::new(vec![
        Permission::View,
        Permission::Input,
        Permission::Audio,
        Permission::FileWrite,
    ])?;
    let (_c_keep, c_stop) = watch::channel(None);
    let (h_revoke, h_stop) = watch::channel(None);
    let (mut c, mut h, connection) = fixture.runtimes(c_stop, h_stop).await?;
    assert_eq!(c.mode(), TransportMode::QuicStreamsAndDatagrams);
    let mut input = h.claim_channel(Channel::Input)?;
    let mut audio = h.claim_channel(Channel::Audio)?;
    let sender = c.sender();
    // More than the per-stream receive window, sender window and bounded queue.
    let file = tokio::spawn(async move {
        let bytes = vec![42; Channel::FileWrite.budget()];
        for _ in 0..512 {
            sender.send(Channel::FileWrite, &bytes).await?;
        }
        Ok::<_, RemoteError>(())
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !file.is_finished(),
        "file must actually encounter backpressure"
    );
    c.send(Channel::Input, b"independent input").await?;
    c.send(Channel::Audio, &vec![3; AUDIO_FRAME_BYTES as usize])
        .await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), input.receive())
            .await??
            .payload,
        b"independent input"
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), audio.receive())
            .await??
            .payload,
        vec![3; AUDIO_FRAME_BYTES as usize]
    );
    // The original stream/datagram binding stays fixed across signed renewal.
    let started = fixture.clock.monotonic_ms().max(1);
    fixture.claims.lease_sequence = 2;
    fixture.claims.issued_at_unix_ms = fixture.clock.sample()?.unix_ms;
    fixture.claims.expires_at_unix_ms = fixture.claims.issued_at_unix_ms + 15000;
    let renewed = verify_permit(
        &fixture.signer.sign(&fixture.claims)?.encode_to_vec(),
        &fixture.signer.public_key(),
    )?;
    c.lease_control().renew(renewed.clone(), started)?;
    h.lease_control().renew(renewed, started)?;
    c.send(Channel::Input, b"after renewal").await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), input.receive())
            .await??
            .payload,
        b"after renewal"
    );
    h_revoke.send_replace(Some(StopReason::Revoked));
    tokio::time::timeout(Duration::from_secs(2), h.wait_stopped()).await??;
    tokio::time::timeout(Duration::from_secs(2), c.wait_stopped()).await??;
    assert!(file.await?.is_err());
    assert!(connection.close_reason().is_some());
    assert!(input.receive().await.is_err());
    assert!(audio.receive().await.is_err());
    Ok(())
}

#[tokio::test]
async fn actual_quic_rejects_unapproved_audio_and_extra_streams() -> Result {
    for attack in 0..3 {
        let fixture = Fixture::new(vec![Permission::View])?;
        let (_c_keep, c_stop) = watch::channel(None);
        let (_h_keep, h_stop) = watch::channel(None);
        let (mut c, mut h, connection) = fixture.runtimes(c_stop, h_stop).await?;
        assert!(c.send(Channel::Input, b"no consent").await.is_err());
        match attack {
            0 => connection.send_datagram(vec![1, 2, 3].into())?,
            1 => {
                let mut stream = connection.open_uni().await?;
                stream.write_all(b"extra").await?;
            }
            _ => {
                let (mut stream, _read) = connection.open_bi().await?;
                stream.write_all(b"extra").await?;
            }
        }
        tokio::time::timeout(Duration::from_secs(2), h.wait_stopped()).await??;
        tokio::time::timeout(Duration::from_secs(2), c.wait_stopped()).await??;
    }
    Ok(())
}

#[tokio::test]
async fn preproof_business_data_and_cancelled_setup_close_actual_connection() -> Result {
    for datagram in [false, true] {
        let fixture = Fixture::new(vec![Permission::View])?;
        let (c, h) = fixture.connections().await?;
        if datagram {
            c.send_datagram(vec![1].into())?;
        } else {
            let mut stream = c.open_uni().await?;
            stream.write_all(b"premature").await?;
        }
        let (_keep, stop) = watch::channel(None);
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                authorize(
                    h,
                    None,
                    fixture.setup(EndpointRole::Host, stop)?,
                    &fixture.host,
                    &fixture.controller.public_key()
                )
            )
            .await?
            .is_err()
        );
        tokio::time::timeout(Duration::from_secs(1), c.closed()).await?;
    }
    let fixture = Fixture::new(vec![Permission::View])?;
    let (c, h) = fixture.connections().await?;
    let (_keep, stop) = watch::channel(None);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            authorize(
                h,
                None,
                fixture.setup(EndpointRole::Host, stop)?,
                &fixture.host,
                &fixture.controller.public_key()
            )
        )
        .await
        .is_err()
    );
    tokio::time::timeout(Duration::from_secs(1), c.closed()).await?;
    Ok(())
}

#[tokio::test]
async fn actual_quic_negotiation_rejects_mismatched_profiles_and_stream_bindings() -> Result {
    for attack in 0..6 {
        let fixture = Fixture::new(vec![Permission::View, Permission::Input])?;
        let (c, h) = fixture.connections().await?;
        let (_keep, stop) = watch::channel(None);
        let (_c_keep, c_stop) = watch::channel(None);
        let controller_key = fixture.controller.public_key();
        let honest = authorize(
            h,
            None,
            fixture.setup(EndpointRole::Host, stop)?,
            &fixture.host,
            &controller_key,
        );
        let malicious = async {
            let mut setup = fixture.setup(EndpointRole::Controller, c_stop)?;
            let (mut write, mut read) = c.open_bi().await?;
            controller_proof(
                &mut read,
                &mut write,
                &mut setup.session,
                &fixture.controller,
                &fixture.host.public_key(),
                &fixture.clock,
            )
            .await?;
            let frame =
                read_channel_frame(&mut read, Channel::Control, QUIC_SETUP_BYTES as usize).await?;
            let mut profile: NativeQuicProfile = decode_bounded(&frame.payload, QUIC_SETUP_BYTES)?;
            if attack == 0 {
                profile.binding_sha256[0] ^= 1;
            }
            if attack == 1 {
                profile.reliable_channels.push(Channel::FileWrite as u32);
            }
            write_frame(&mut write, Channel::Control, &profile.encode_to_vec()).await?;
            let mut streams = Vec::new();
            if attack >= 2 {
                for (index, &channel) in profile.reliable_channels.iter().enumerate() {
                    let mut header = NativeQuicStream {
                        schema_version: SCHEMA_VERSION,
                        binding_sha256: profile.binding_sha256.clone(),
                        connection_generation: profile.connection_generation,
                        channel,
                    };
                    match attack {
                        2 => header.connection_generation += 1,
                        3 => header.binding_sha256[0] ^= 1,
                        4 => header.channel = Channel::FileWrite as u32,
                        _ => header.channel = profile.reliable_channels[0],
                    }
                    let mut stream = c.open_uni().await?;
                    write_frame(&mut stream, Channel::Control, &header.encode_to_vec()).await?;
                    streams.push(stream);
                    if attack != 5 || index == 1 {
                        break;
                    }
                }
            }
            tokio::time::timeout(Duration::from_secs(1), c.closed()).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let (outcome, attack_result) = tokio::join!(honest, malicious);
        assert!(outcome.is_err());
        attack_result?;
    }
    Ok(())
}

#[tokio::test]
async fn bound_stream_header_is_rejected_before_reading_body() -> Result {
    use tokio::io::AsyncWriteExt;
    for bytes in [
        vec![1, Channel::Video as u8],
        vec![1, Channel::Control as u8, 0, 0, 2, 1],
    ] {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.write_all(&bytes).await?;
        let channel = if bytes.len() == 2 {
            Channel::Input
        } else {
            Channel::Control
        };
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                read_channel_frame(&mut reader, channel, QUIC_SETUP_BYTES as usize)
            )
            .await?
            .is_err()
        );
    }
    Ok(())
}
