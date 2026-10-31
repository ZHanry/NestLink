//! Fixed signed mechanism credentials. These deliberately do not impersonate
//! management HTTP or online one-use starts, which have separate real tests.
use super::*;
use nestlink_identity::{
    InstallationIdentity,
    network::{
        NetworkAuthoritySigner, NetworkVerification, SignedNetworkGrant, VerifiedMembership,
        VerifiedNetworkPath, verify_network_grant,
    },
    subnet::{SubnetGatewayState, verify_subnet_mapping},
};
use nestlink_protocol::network_access::NetworkAccessView;
use nestlink_protocol::{
    api::{NetworkGrantView, NetworkPolicyView},
    network::{
        ConnectivityClaims, Direction, GrantClaims, GrantScope, IpPrefix, IpProtocol,
        MembershipClaims, NetworkAccessClaims, NetworkRule, PathClaims, PathPolicy, PeerId,
        PeerPair, Purpose, RouteExportClaims, SpaceRole,
    },
    network_topology::BootIncarnation,
    spaces::{
        SpaceView,
        addressing::{SpaceAddressDirectory, SpaceAddressView},
    },
    subnet::{
        SubnetMappingClaims,
        management::{SubnetGatewayView, SubnetMappingView},
    },
};
use nestlink_sdk::network::packet_access::{PacketPeerAuthority, VerifiedPacketAccess};
use std::collections::BTreeSet;

pub(super) const DEPLOYMENT: &str = "eebf5d3b-7986-4f10-942c-bbe5da0b1b12";
pub(super) const SPACE: &str = "30e08183-c6bc-4994-a116-51c7066cb11c";
pub(super) const UDP: u16 = 45123;
pub(super) const TCP: u16 = 45124;
pub(super) const DENIED: u16 = 45125;
pub(super) const ORIGINAL: &str = "192.168.1.0";
pub(super) const TARGET: &str = "192.168.1.42";
pub(super) const ALIASES: [&str; 2] = ["10.211.1.0", "10.211.2.0"];
pub(super) const DESTINATIONS: [&str; 2] = ["10.211.1.42", "10.211.2.42"];

pub(super) struct Fixture {
    pub view: NetworkAccessView,
    pub authority: [u8; 32],
    pub created: u64,
    pub expires: u64,
    pub access: [u8; 32],
    pub mappings: [[u8; 32]; 2],
}
fn scope(created: u64, expires: u64, index: u16) -> GrantScope {
    GrantScope {
        schema_version: 1,
        deployment_id: DEPLOYMENT.into(),
        space_id: SPACE.into(),
        grant_id: format!("30000000-0000-4000-8000-{index:012x}"),
        policy_epoch: 1,
        not_before_ms: created,
        expires_at_ms: expires,
    }
}
fn view(signed: SignedNetworkGrant) -> Result<NetworkGrantView> {
    let claims = GrantClaims::decode_canonical(&signed.claims)?;
    Ok(NetworkGrantView {
        schema_version: 1,
        grant_id: claims.scope().grant_id.clone(),
        claims: URL_SAFE_NO_PAD.encode(signed.claims),
        signature: URL_SAFE_NO_PAD.encode(signed.signature),
    })
}
pub(super) fn identity(index: usize) -> InstallationIdentity {
    InstallationIdentity::from_seed([if index == 0 { 61 } else { 62 }; 32])
}
impl Fixture {
    pub fn new() -> Result<Self> {
        let created = system_wall_ms()?;
        let expires = created + 40_000;
        let signer = NetworkAuthoritySigner::from_master_seed(&[89; 32])?;
        let authority = signer.public_key();
        let revoked = BTreeSet::new();
        let context = NetworkVerification {
            authority_key: &authority,
            deployment_id: DEPLOYMENT,
            space_id: SPACE,
            policy_epoch: 1,
            now_ms: created,
            revoked_grant_ids: &revoked,
        };
        let identities = [identity(0), identity(1)];
        let peers = identities
            .each_ref()
            .map(|identity| PeerId(identity.fingerprint()));
        let mut memberships = Vec::new();
        let mut addresses = Vec::new();
        let mut mappings = Vec::new();
        let mut mapping_digests = Vec::new();
        for index in 0..2 {
            let public = identities[index].public_key();
            let installation = format!("40000000-0000-4000-8000-{:012x}", index + 1);
            memberships.push(view(signer.sign(&GrantClaims::Membership(
                MembershipClaims {
                    scope: scope(created, expires, index as u16 + 1),
                    installation_id: installation.clone(),
                    peer: peers[index],
                    public_key: public,
                    membership_epoch: 1,
                    role: SpaceRole::Member,
                },
            ))?)?);
            addresses.push(SpaceAddressView {
                installation_id: installation,
                account_id: format!("50000000-0000-4000-8000-{:012x}", index + 1),
                public_key: URL_SAFE_NO_PAD.encode(public),
                account_member_epoch: 1,
                membership_epoch: 1,
                address_epoch: 1,
                name: format!("site{index}"),
                fqdn: format!("site{index}.s-{SPACE}.nestlink.internal"),
                ipv4: format!("10.44.0.{}", index + 2),
                ipv6: format!("fd44::{}", index + 2),
                reserved: false,
                revoked: false,
                active: true,
            });
            let original = IpPrefix {
                network: ORIGINAL.parse()?,
                prefix_len: 24,
            };
            let alias = IpPrefix {
                network: ALIASES[index].parse()?,
                prefix_len: 24,
            };
            let export = signer.sign(&GrantClaims::RouteExport(RouteExportClaims {
                scope: scope(created, expires, 10 + index as u16),
                gateway: peers[index],
                prefixes: vec![alias, original],
            }))?;
            let verified_export = verify_network_grant(&export, &context)?;
            let claims = SubnetMappingClaims {
                mapping_version: 1,
                scope: scope(created, expires, 20 + index as u16),
                gateway_node_id: format!("60000000-0000-4000-8000-{:012x}", index + 1),
                gateway_public_key: public,
                gateway: peers[index],
                gateway_incarnation: BootIncarnation {
                    runtime_generation: 1,
                    runtime_id: format!("70000000-0000-4000-8000-{:012x}", index + 1),
                },
                original,
                alias,
                route_export_digest: verified_export.digest(),
                mapping_revision: 1,
            };
            let gateway = SubnetGatewayView {
                node_id: claims.gateway_node_id.clone(),
                public_key: public,
                incarnation: claims.gateway_incarnation.clone(),
                mapping_revision: 1,
                lease_expires_at_ms: expires,
            };
            let signed = signer.sign_subnet_mapping(&claims)?;
            mapping_digests.push(
                verify_subnet_mapping(
                    &signed,
                    &context,
                    verified_export,
                    &SubnetGatewayState {
                        node_id: &gateway.node_id,
                        public_key: &gateway.public_key,
                        incarnation: &gateway.incarnation,
                        mapping_revision: 1,
                        lease_expires_at_ms: expires,
                    },
                )?
                .digest(),
            );
            mappings.push(SubnetMappingView {
                mapping: signed,
                route_export: view(export)?,
                gateway,
                policy: NetworkPolicyView {
                    schema_version: 1,
                    deployment_id: DEPLOYMENT.into(),
                    space_id: SPACE.into(),
                    authority_public_key: URL_SAFE_NO_PAD.encode(authority),
                    revision: 1,
                    policy_epoch: 1,
                    observed_at_unix_ms: created,
                },
            });
        }
        let access = signer.sign(&GrantClaims::NetworkAccess(NetworkAccessClaims {
            scope: scope(created, expires, 30),
            source: peers[0],
            destination: peers[1],
            source_prefixes: vec![IpPrefix {
                network: ALIASES[0].parse()?,
                prefix_len: 24,
            }],
            destination_prefixes: vec![IpPrefix {
                network: ALIASES[1].parse()?,
                prefix_len: 24,
            }],
            rules: vec![
                NetworkRule {
                    protocol: IpProtocol::Udp,
                    direction: Direction::Inbound,
                    ports: Some([UDP, UDP]),
                },
                NetworkRule {
                    protocol: IpProtocol::Tcp,
                    direction: Direction::Inbound,
                    ports: Some([TCP, TCP]),
                },
            ],
            byte_limit: 1_048_576,
        }))?;
        let access_digest = verify_network_grant(&access, &context)?.digest();
        let mut members = memberships
            .iter()
            .map(|view| -> Result<_> {
                Ok(verify_network_grant(
                    &nestlink_sdk::network_management::decode_network_grant(view)?,
                    &context,
                )?)
            })
            .collect::<Result<Vec<_>>>()?;
        members.sort_by_key(|member| match member.claims() {
            GrantClaims::Membership(claims) => claims.peer,
            _ => PeerId([0; 32]),
        });
        let pair = PeerPair::new(peers[0], peers[1])?;
        let connectivity = signer.sign(&GrantClaims::Connectivity(ConnectivityClaims {
            scope: scope(created, expires, 31),
            peers: pair,
            purpose: Purpose::NetworkPacket,
            membership_digests: [members[0].digest(), members[1].digest()],
            business_grant_digest: access_digest,
        }))?;
        let connectivity_digest = verify_network_grant(&connectivity, &context)?.digest();
        let path = signer.sign(&GrantClaims::Path(PathClaims {
            scope: scope(created, expires, 32),
            peers: pair,
            purpose: Purpose::NetworkPacket,
            connectivity_grant_digest: connectivity_digest,
            policy: PathPolicy {
                allow_direct: true,
                relays: vec![],
                max_hops: 0,
            },
        }))?;
        let view = NetworkAccessView {
            source_membership: memberships.remove(0),
            destination_membership: memberships.remove(0),
            access: view(access)?,
            connectivity: view(connectivity)?,
            path: view(path)?,
            address_directory: SpaceAddressDirectory {
                space: SpaceView {
                    space_id: SPACE.into(),
                    deployment_id: DEPLOYMENT.into(),
                    authority_public_key: URL_SAFE_NO_PAD.encode(authority),
                    name: "isolated subnet kernel lab".into(),
                    archived: false,
                    revision: 1,
                    policy_epoch: 1,
                    observed_at_unix_ms: created,
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
            subnet_mappings: mappings,
        };
        Ok(Self {
            view,
            authority,
            created,
            expires,
            access: access_digest,
            mappings: [mapping_digests[0], mapping_digests[1]],
        })
    }
    pub async fn plan(&self, index: usize, path: PathBuf, lan_name: String) -> Result<Plan> {
        let link = kernel::local_link(&lan_name).await?;
        Ok(Plan {
            schema_version: 1,
            owner_id: nestlink_auth::random_id(),
            process: process_identity(std::process::id()).await?,
            uid: rustix::process::geteuid().as_raw(),
            path,
            created_at_ms: self.created,
            expires_at_ms: self.expires,
            deployment_id: DEPLOYMENT.into(),
            space_id: SPACE.into(),
            authority: self.authority,
            local_public: identity(index).public_key(),
            approved_access: self.access,
            approved_mapping: self.mappings[index],
            lan_name,
            lan_index: u32::try_from(
                link["ifindex"]
                    .as_u64()
                    .ok_or_else(|| io::Error::other("test LAN index missing"))?,
            )?,
            lan_gateway: "192.168.1.254".parse()?,
            lan_prefix_len: 24,
            physical_endpoints: vec!["127.0.0.1".parse()?],
            credentials: self.view.clone(),
            wireguard: None,
        })
    }
}
pub(super) fn context<'a>(
    plan: &'a Plan,
    revoked: &'a BTreeSet<String>,
) -> Result<NetworkVerification<'a>> {
    Ok(NetworkVerification {
        authority_key: &plan.authority,
        deployment_id: &plan.deployment_id,
        space_id: &plan.space_id,
        policy_epoch: 1,
        now_ms: system_wall_ms()?,
        revoked_grant_ids: revoked,
    })
}
pub(super) fn authorities(plan: &Plan) -> Result<[PacketPeerAuthority; 2]> {
    let revoked = BTreeSet::new();
    let context = context(plan, &revoked)?;
    let mut directory = plan.credentials.address_directory.clone();
    directory.space.observed_at_unix_ms = context.now_ms;
    let mut result = Vec::new();
    for (index, grant) in [
        &plan.credentials.source_membership,
        &plan.credentials.destination_membership,
    ]
    .into_iter()
    .enumerate()
    {
        let member = verify_network_grant(
            &nestlink_sdk::network_management::decode_network_grant(grant)?,
            &context,
        )?;
        let row = &directory.addresses[index];
        let public = identity(index).public_key();
        let member =
            VerifiedMembership::from_grant(member, &context, &row.installation_id, &public, 1)?;
        let export = verify_network_grant(
            &nestlink_sdk::network_management::decode_network_grant(
                &plan.credentials.subnet_mappings[index].route_export,
            )?,
            &context,
        )?;
        result.push(PacketPeerAuthority::from_directory(
            &context,
            member,
            &directory,
            vec![export],
        )?);
    }
    Ok([result.remove(0), result.remove(0)])
}
pub(super) fn policy(plan: &Plan) -> Result<VerifiedPacketAccess> {
    let revoked = BTreeSet::new();
    let context = context(plan, &revoked)?;
    let [source, destination] = authorities(plan)?;
    let mut members = Vec::new();
    for (index, view) in [
        &plan.credentials.source_membership,
        &plan.credentials.destination_membership,
    ]
    .into_iter()
    .enumerate()
    {
        let public = identity(index).public_key();
        let row = &plan.credentials.address_directory.addresses[index];
        members.push(VerifiedMembership::from_grant(
            verify_network_grant(
                &nestlink_sdk::network_management::decode_network_grant(view)?,
                &context,
            )?,
            &context,
            &row.installation_id,
            &public,
            1,
        )?);
    }
    members.sort_by_key(VerifiedMembership::peer);
    let access = verify_network_grant(
        &nestlink_sdk::network_management::decode_network_grant(&plan.credentials.access)?,
        &context,
    )?;
    let connectivity = verify_network_grant(
        &nestlink_sdk::network_management::decode_network_grant(&plan.credentials.connectivity)?,
        &context,
    )?;
    let path = verify_network_grant(
        &nestlink_sdk::network_management::decode_network_grant(&plan.credentials.path)?,
        &context,
    )?;
    let path = VerifiedNetworkPath::from_grants(
        &context,
        [members.remove(0), members.remove(0)],
        connectivity.clone(),
        path,
        access.digest(),
    )?;
    Ok(VerifiedPacketAccess::new(
        &context,
        path,
        connectivity,
        access,
        PeerId::from_public_key(&plan.local_public),
        source,
        destination,
    )?)
}
