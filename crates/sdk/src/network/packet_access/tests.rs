use super::*;
use crate::DeviceIdentity;
use etherparse::PacketBuilder;
use nestlink_identity::network::{NetworkAuthoritySigner, verify_network_grant};
use nestlink_protocol::{
    network::{
        ConnectivityClaims, GrantScope, MembershipClaims, NetworkRule, PathClaims, PathPolicy,
        PeerPair, SpaceRole,
    },
    spaces::{SpaceView, addressing::SpaceAddressView},
};
use std::collections::BTreeSet;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const DEPLOYMENT: &str = "10000000-0000-4000-8000-000000000001";
const SPACE: &str = "20000000-0000-4000-8000-000000000002";

struct Fixture {
    signer: NetworkAuthoritySigner,
    issuer: [u8; 32],
    revoked: BTreeSet<String>,
    now: u64,
    members: [VerifiedMembership; 2],
    directory: SpaceAddressDirectory,
}
impl Fixture {
    fn new() -> Result<Self> {
        let signer = NetworkAuthoritySigner::from_master_seed(&[68; 32])?;
        let issuer = signer.public_key();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
        let revoked = BTreeSet::new();
        let context = NetworkVerification {
            authority_key: &issuer,
            deployment_id: DEPLOYMENT,
            space_id: SPACE,
            policy_epoch: 1,
            now_ms: now,
            revoked_grant_ids: &revoked,
        };
        let mut members = Vec::new();
        let mut addresses = Vec::new();
        for index in 0..2 {
            let device = DeviceIdentity::generate();
            let claims = MembershipClaims {
                scope: scope(now, index + 1),
                installation_id: device.device_id.clone(),
                peer: PeerId(device.identity.fingerprint()),
                public_key: device.identity.public_key(),
                membership_epoch: 1,
                role: SpaceRole::Member,
            };
            members.push(VerifiedMembership::from_grant(
                verify_network_grant(
                    &signer.sign(&GrantClaims::Membership(claims.clone()))?,
                    &context,
                )?,
                &context,
                &device.device_id,
                &claims.public_key,
                1,
            )?);
            addresses.push(SpaceAddressView {
                installation_id: device.device_id,
                account_id: nestlink_auth::random_id(),
                public_key: URL_SAFE_NO_PAD.encode(claims.public_key),
                account_member_epoch: 1,
                membership_epoch: 1,
                address_epoch: 1,
                name: format!("peer{index}"),
                fqdn: format!("peer{index}.s-{SPACE}.nestlink.internal"),
                ipv4: format!("10.44.0.{}", index + 2),
                ipv6: format!("fd44::{}", index + 2),
                reserved: false,
                revoked: false,
                active: true,
            });
        }
        Ok(Self {
            signer,
            issuer,
            revoked,
            now,
            members: [members.remove(0), members.remove(0)],
            directory: SpaceAddressDirectory {
                space: SpaceView {
                    space_id: SPACE.into(),
                    deployment_id: DEPLOYMENT.into(),
                    authority_public_key: URL_SAFE_NO_PAD.encode(issuer),
                    name: "Packet access test".into(),
                    archived: false,
                    revision: 1,
                    policy_epoch: 1,
                    observed_at_unix_ms: now,
                    role: SpaceRole::Member,
                    member_epoch: 1,
                },
                revision: 1,
                suffix: format!("s-{SPACE}.nestlink.internal"),
                ipv4_pool: "10.44.0.0/24".into(),
                ipv6_pool: "fd44::/64".into(),
                cache_max_age_seconds: 0,
                addresses,
            },
        })
    }
    fn context(&self) -> NetworkVerification<'_> {
        NetworkVerification {
            authority_key: &self.issuer,
            deployment_id: DEPLOYMENT,
            space_id: SPACE,
            policy_epoch: 1,
            now_ms: self.now,
            revoked_grant_ids: &self.revoked,
        }
    }
    fn prefix_authorities(&self) -> Result<[PacketPeerAuthority; 2]> {
        Ok([
            PacketPeerAuthority::from_directory(
                &self.context(),
                self.members[0].clone(),
                &self.directory,
                vec![],
            )?,
            PacketPeerAuthority::from_directory(
                &self.context(),
                self.members[1].clone(),
                &self.directory,
                vec![],
            )?,
        ])
    }
    fn owner(&self, byte_limit: u64) -> Result<VerifiedPacketAccess> {
        let context = self.context();
        let [source, destination] = self.prefix_authorities()?;
        let claims = NetworkAccessClaims {
            scope: scope(self.now, 3),
            source: source.peer(),
            destination: destination.peer(),
            source_prefixes: vec![
                IpPrefix {
                    network: "10.44.0.2".parse()?,
                    prefix_len: 32,
                },
                IpPrefix {
                    network: "fd44::2".parse()?,
                    prefix_len: 128,
                },
            ],
            destination_prefixes: vec![
                IpPrefix {
                    network: "10.44.0.3".parse()?,
                    prefix_len: 32,
                },
                IpPrefix {
                    network: "fd44::3".parse()?,
                    prefix_len: 128,
                },
            ],
            rules: vec![
                NetworkRule {
                    protocol: IpProtocol::Udp,
                    direction: Direction::Inbound,
                    ports: Some([53, 53]),
                },
                NetworkRule {
                    protocol: IpProtocol::Tcp,
                    direction: Direction::Inbound,
                    ports: Some([22, 22]),
                },
                NetworkRule {
                    protocol: IpProtocol::IcmpV6,
                    direction: Direction::Inbound,
                    ports: None,
                },
            ],
            byte_limit,
        };
        let access = verify_network_grant(
            &self.signer.sign(&GrantClaims::NetworkAccess(claims))?,
            &context,
        )?;
        let mut members = self.members.clone();
        members.sort_by_key(VerifiedMembership::peer);
        let peers = PeerPair::new(source.peer(), destination.peer())?;
        let connectivity = verify_network_grant(
            &self
                .signer
                .sign(&GrantClaims::Connectivity(ConnectivityClaims {
                    scope: scope(self.now, 4),
                    peers,
                    purpose: Purpose::NetworkPacket,
                    membership_digests: [members[0].digest(), members[1].digest()],
                    business_grant_digest: access.digest(),
                }))?,
            &context,
        )?;
        let path_grant = verify_network_grant(
            &self.signer.sign(&GrantClaims::Path(PathClaims {
                scope: scope(self.now, 5),
                peers,
                purpose: Purpose::NetworkPacket,
                connectivity_grant_digest: connectivity.digest(),
                policy: PathPolicy {
                    allow_direct: true,
                    relays: vec![],
                    max_hops: 0,
                },
            }))?,
            &context,
        )?;
        let path = VerifiedNetworkPath::from_grants(
            &context,
            members,
            connectivity.clone(),
            path_grant,
            access.digest(),
        )?;
        Ok(VerifiedPacketAccess::new(
            &context,
            path,
            connectivity,
            access,
            source.peer(),
            source,
            destination,
        )?)
    }
}
fn scope(now: u64, index: u8) -> GrantScope {
    GrantScope {
        schema_version: 1,
        deployment_id: DEPLOYMENT.into(),
        space_id: SPACE.into(),
        grant_id: format!("30000000-0000-4000-8000-{index:012x}"),
        policy_epoch: 1,
        not_before_ms: now,
        expires_at_ms: now + 60_000,
    }
}
fn udp(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    PacketBuilder::ipv4(source, destination, 64)
        .udp(source_port, destination_port)
        .write(&mut bytes, b"request")?;
    Ok(bytes)
}
fn udp6(payload: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    PacketBuilder::ipv6(
        "fd44::2".parse::<std::net::Ipv6Addr>()?.octets(),
        "fd44::3".parse::<std::net::Ipv6Addr>()?.octets(),
        64,
    )
    .udp(41000, 53)
    .write(&mut bytes, &vec![7; payload])?;
    Ok(bytes)
}

#[test]
fn ordinary_udp_and_exact_reverse_are_charged_to_one_original_budget() -> Result {
    let fixture = Fixture::new()?;
    let mut owner = fixture.owner(4096)?;
    let request = udp([10, 44, 0, 2], [10, 44, 0, 3], 41000, 53)?;
    let reply = udp([10, 44, 0, 3], [10, 44, 0, 2], 53, 41000)?;
    assert!(
        owner
            .admit_remote(&fixture.context(), owner.remote_peer(), &reply)
            .is_err()
    );
    let admitted = owner.admit_local(&fixture.context(), &request)?;
    assert_eq!(admitted.direction, PacketDirection::SourceToDestination);
    assert!(!admitted.reply);
    assert!(
        owner
            .admit_remote(&fixture.context(), owner.remote_peer(), &reply)?
            .reply
    );
    assert_eq!(owner.spent_bytes(), (request.len() + reply.len()) as u64);
    assert!(
        owner
            .admit_remote(&fixture.context(), PeerId([3; 32]), &reply)
            .is_err()
    );
    assert!(
        owner
            .admit_remote(
                &fixture.context(),
                owner.remote_peer(),
                &udp([10, 44, 0, 3], [10, 44, 0, 2], 53, 41001)?
            )
            .is_err()
    );
    assert_eq!(owner.flows.len(), 1);
    Ok(())
}
#[test]
fn spoofed_prefix_and_wrong_destination_port_do_not_consume_authority() -> Result {
    let fixture = Fixture::new()?;
    let mut owner = fixture.owner(4096)?;
    for packet in [
        udp([10, 44, 0, 8], [10, 44, 0, 3], 41000, 53)?,
        udp([10, 44, 0, 2], [10, 44, 0, 3], 41000, 54)?,
        udp([10, 44, 0, 2], [10, 44, 0, 8], 41000, 53)?,
    ] {
        assert!(owner.admit_local(&fixture.context(), &packet).is_err());
    }
    assert_eq!(owner.spent_bytes(), 0);
    assert!(owner.flows.is_empty());
    Ok(())
}
#[test]
fn reverse_echo_request_cannot_borrow_the_original_echo_reply_right() -> Result {
    let fixture = Fixture::new()?;
    let mut owner = fixture.owner(4096)?;
    let source = "fd44::2".parse::<std::net::Ipv6Addr>()?.octets();
    let destination = "fd44::3".parse::<std::net::Ipv6Addr>()?.octets();
    let mut request = Vec::new();
    PacketBuilder::ipv6(source, destination, 64)
        .icmpv6_echo_request(123, 456)
        .write(&mut request, b"echo")?;
    let mut reverse_request = Vec::new();
    PacketBuilder::ipv6(destination, source, 64)
        .icmpv6_echo_request(456, 123)
        .write(&mut reverse_request, b"echo")?;
    let mut reply = Vec::new();
    PacketBuilder::ipv6(destination, source, 64)
        .icmpv6_echo_reply(123, 456)
        .write(&mut reply, b"echo")?;
    assert!(
        owner
            .admit_remote(&fixture.context(), owner.remote_peer(), &reply)
            .is_err()
    );
    owner.admit_local(&fixture.context(), &request)?;
    let spent = owner.spent_bytes();
    assert!(
        owner
            .admit_remote(&fixture.context(), owner.remote_peer(), &reverse_request)
            .is_err()
    );
    assert_eq!(owner.spent_bytes(), spent);
    assert!(
        owner
            .admit_remote(&fixture.context(), owner.remote_peer(), &reply)?
            .reply
    );
    assert_eq!(owner.spent_bytes(), (request.len() + reply.len()) as u64);
    Ok(())
}
#[test]
fn full_ipv6_minimum_mtu_packet_is_supported_and_charged() -> Result {
    let fixture = Fixture::new()?;
    let mut owner = fixture.owner(4096)?;
    let packet = udp6(1232)?;
    assert_eq!(packet.len(), 1280);
    owner.admit_local(&fixture.context(), &packet)?;
    assert_eq!(owner.spent_bytes(), 1280);
    assert!(owner.admit_local(&fixture.context(), &udp6(1233)?).is_err());
    Ok(())
}
#[test]
fn ip_fragments_atomic_fragments_and_opaque_extension_headers_are_closed() -> Result {
    let request = udp([10, 44, 0, 2], [10, 44, 0, 3], 41000, 53)?;
    for flags in [0x2000u16, 1] {
        let mut fragmented = request.clone();
        fragmented[6..8].copy_from_slice(&flags.to_be_bytes());
        let checksum = etherparse::Ipv4HeaderSlice::from_slice(&fragmented)?
            .to_header()
            .calc_header_checksum();
        fragmented[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert!(parse::packet(&fragmented).is_err());
    }
    let original = udp6(32)?;
    for next_header in [0, 43, 44, 60, 50] {
        let mut extended = original[..40].to_vec();
        extended[6] = next_header;
        extended[4..6].copy_from_slice(&((original.len() - 40 + 8) as u16).to_be_bytes());
        extended.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
        extended.extend_from_slice(&original[40..]);
        assert!(parse::packet(&extended).is_err(), "extension {next_header}");
    }
    let mut zero_jumbo = original;
    zero_jumbo[4..6].copy_from_slice(&[0, 0]);
    assert!(parse::packet(&zero_jumbo).is_err());
    Ok(())
}
#[test]
fn packet_length_and_checksums_have_no_lax_authorization_fallback() -> Result {
    let packet = udp6(32)?;
    for corrupted in [
        packet[..packet.len() - 1].to_vec(),
        {
            let mut value = packet.clone();
            value.push(0);
            value
        },
        {
            let mut value = packet.clone();
            value[46..48].copy_from_slice(&[0, 0]);
            value
        },
        {
            let mut value = packet.clone();
            let last = value.len() - 1;
            value[last] ^= 1;
            value
        },
    ] {
        assert!(parse::packet(&corrupted).is_err());
    }
    Ok(())
}
#[test]
fn revocation_and_observation_gap_are_terminal_even_after_fresh_refresh() -> Result {
    let mut fixture = Fixture::new()?;
    let mut owner = fixture.owner(4096)?;
    let packet = udp([10, 44, 0, 2], [10, 44, 0, 3], 41000, 53)?;
    owner.source.fresh_until = Instant::now();
    assert!(owner.admit_local(&fixture.context(), &packet).is_err());
    let [source, destination] = fixture.prefix_authorities()?;
    assert!(
        owner
            .refresh_addresses(&fixture.context(), source, destination)
            .is_err()
    );
    let mut owner = fixture.owner(4096)?;
    fixture
        .revoked
        .insert(owner.access.claims().scope().grant_id.clone());
    assert!(owner.admit_local(&fixture.context(), &packet).is_err());
    fixture.revoked.clear();
    assert!(owner.admit_local(&fixture.context(), &packet).is_err());
    Ok(())
}
#[test]
fn directory_cannot_rebind_an_assigned_address_to_a_different_peer() -> Result {
    let mut fixture = Fixture::new()?;
    fixture.directory.addresses[0].public_key = fixture.directory.addresses[1].public_key.clone();
    assert!(fixture.prefix_authorities().is_err());
    fixture.directory.addresses[0].public_key =
        URL_SAFE_NO_PAD.encode(fixture.members[0].claims().public_key);
    fixture
        .directory
        .addresses
        .push(fixture.directory.addresses[0].clone());
    assert!(fixture.prefix_authorities().is_err());
    Ok(())
}

#[test]
fn contradictory_tcp_control_flags_cannot_create_or_reuse_a_flow() -> Result {
    let fixture = Fixture::new()?;
    let mut owner = fixture.owner(4096)?;
    for flags in [0x03, 0x06, 0x05] {
        let mut packet = Vec::new();
        PacketBuilder::ipv4([10, 44, 0, 2], [10, 44, 0, 3], 64)
            .tcp(41000, 22, 1, 4096)
            .write(&mut packet, b"")?;
        packet[33] = flags;
        let checksum = etherparse::TcpHeaderSlice::from_slice(&packet[20..])?
            .to_header()
            .calc_checksum_ipv4_raw([10, 44, 0, 2], [10, 44, 0, 3], b"")?;
        packet[36..38].copy_from_slice(&checksum.to_be_bytes());
        assert!(owner.admit_local(&fixture.context(), &packet).is_err());
    }
    assert!(owner.flows.is_empty());
    assert_eq!(owner.spent_bytes(), 0);
    Ok(())
}
