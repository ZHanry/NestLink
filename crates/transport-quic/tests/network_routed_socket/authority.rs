//! Thin signed-fixture provisioning; production code verifies every object.
use super::{Result, identity};
use nestlink_identity::{
    PermitSigner, VerifiedPermit, digest,
    network::{
        NetworkAuthoritySigner, NetworkVerification, SignedNetworkGrant, VerifiedMembership,
        VerifiedNetworkGrant, VerifiedNetworkPath, verify_network_grant,
    },
    verify_permit,
};
use nestlink_protocol::{Path as NetworkPath, Permission, PermitClaims, network::*};
use nestlink_transport_quic::routed::{RouteAuthorization, RouteRevocation};
use prost::Message;
use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const DEPLOYMENT: &str = "10000000-0000-4000-8000-000000000001";
const SPACE: &str = "20000000-0000-4000-8000-000000000002";
const INSTALLATIONS: [&str; 2] = [
    "40000000-0000-4000-8000-000000000004",
    "50000000-0000-4000-8000-000000000005",
];
fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn key(root: &Path, name: &str) -> Result<[u8; 32]> {
    fs::read(root.join(format!("{name}.public")))?
        .try_into()
        .map_err(|_| "invalid public fixture key".into())
}
fn write_grant(root: &Path, name: &str, signed: SignedNetworkGrant) -> Result {
    fs::write(
        root.join(format!("{name}.grant")),
        serde_json::to_vec(&(signed.claims, signed.signature))?,
    )?;
    Ok(())
}
fn read_grant(
    root: &Path,
    name: &str,
    context: &NetworkVerification<'_>,
) -> Result<VerifiedNetworkGrant> {
    let (claims, signature): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&fs::read(root.join(format!("{name}.grant")))?)?;
    Ok(verify_network_grant(
        &SignedNetworkGrant { claims, signature },
        context,
    )?)
}
pub fn prepare(root: &Path) -> Result {
    let mut first = identity(root, "first")?;
    let mut second = identity(root, "second")?;
    if first.fingerprint() > second.fingerprint() {
        let a = fs::read(root.join("first.seed"))?;
        let b = fs::read(root.join("second.seed"))?;
        fs::write(root.join("first.seed"), b)?;
        fs::write(root.join("second.seed"), a)?;
        std::mem::swap(&mut first, &mut second);
    }
    let relay = identity(root, "relay")?;
    for (name, device) in [("first", &first), ("second", &second), ("relay", &relay)] {
        fs::write(root.join(format!("{name}.public")), device.public_key())?;
    }
    let now = now_ms()?;
    let permit_signer = PermitSigner::generate();
    let business = PermitClaims {
        schema_version: nestlink_protocol::SCHEMA_VERSION,
        deployment_id: DEPLOYMENT.into(),
        security_epoch: 1,
        session_id: "a1000000-0000-4000-8000-000000000001".into(),
        account_id: "a2000000-0000-4000-8000-000000000002".into(),
        controller_device_id: INSTALLATIONS[0].into(),
        host_device_id: INSTALLATIONS[1].into(),
        controller_key_sha256: first.fingerprint().to_vec(),
        host_key_sha256: second.fingerprint().to_vec(),
        resource_id: "a3000000-0000-4000-8000-000000000003".into(),
        permissions: vec![Permission::FileRead as i32],
        paths: vec![NetworkPath::Relay as i32],
        policy_revision: 1,
        connection_generation: 1,
        lease_sequence: 1,
        issued_at_unix_ms: now,
        expires_at_unix_ms: now + 15_000,
        capability_sha256: digest(b"routed-network-namespace-fixture").to_vec(),
        required_capabilities: vec!["vp8".into()],
        media_format_version: 0,
        media_formats: Vec::new(),
        media_format_sha256: Vec::new(),
    };
    let permit_bytes = permit_signer.sign(&business)?.encode_to_vec();
    let permit = verify_permit(&permit_bytes, &permit_signer.public_key())?;
    fs::write(root.join("permit.bin"), permit_bytes)?;
    fs::write(root.join("business.public"), permit_signer.public_key())?;
    let mut seed: [u8; 32] = fs::read(root.join("authority.seed"))?
        .try_into()
        .map_err(|_| "invalid authority seed")?;
    let signer = NetworkAuthoritySigner::from_master_seed(&seed)?;
    seed.fill(0);
    let issuer = signer.public_key();
    fs::write(root.join("authority.public"), issuer)?;
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: &issuer,
        deployment_id: DEPLOYMENT,
        space_id: SPACE,
        policy_epoch: 9,
        now_ms: now,
        revoked_grant_ids: &revoked,
    };
    let scope = |id: u8| GrantScope {
        schema_version: 1,
        deployment_id: DEPLOYMENT.into(),
        space_id: SPACE.into(),
        grant_id: format!("30000000-0000-4000-8000-{id:012x}"),
        policy_epoch: 9,
        not_before_ms: now,
        expires_at_ms: now + 12_000,
    };
    let mut memberships = Vec::new();
    for (index, (name, device)) in [("first", &first), ("second", &second)]
        .into_iter()
        .enumerate()
    {
        let claims = MembershipClaims {
            scope: scope(index as u8 + 1),
            installation_id: INSTALLATIONS[index].into(),
            peer: PeerId(device.fingerprint()),
            public_key: device.public_key(),
            membership_epoch: 1,
            role: SpaceRole::Member,
        };
        let signed = signer.sign(&GrantClaims::Membership(claims))?;
        memberships.push(VerifiedMembership::from_grant(
            verify_network_grant(&signed, &context)?,
            &context,
            INSTALLATIONS[index],
            &device.public_key(),
            1,
        )?);
        write_grant(root, name, signed)?;
    }
    let memberships = [memberships.remove(0), memberships.remove(0)];
    let peers = PeerPair::new(PeerId(first.fingerprint()), PeerId(second.fingerprint()))?;
    let signed = signer.sign(&GrantClaims::Connectivity(ConnectivityClaims {
        scope: scope(3),
        peers,
        purpose: Purpose::RemoteControl,
        membership_digests: [memberships[0].digest(), memberships[1].digest()],
        business_grant_digest: permit.digest(),
    }))?;
    let connectivity = verify_network_grant(&signed, &context)?;
    write_grant(root, "connectivity", signed)?;
    let signed = signer.sign(&GrantClaims::Path(PathClaims {
        scope: scope(4),
        peers,
        purpose: Purpose::RemoteControl,
        connectivity_grant_digest: connectivity.digest(),
        policy: PathPolicy {
            allow_direct: false,
            relays: vec![PeerId(relay.fingerprint())],
            max_hops: 1,
        },
    }))?;
    let path = VerifiedNetworkPath::from_grants(
        &context,
        memberships,
        connectivity.clone(),
        verify_network_grant(&signed, &context)?,
        permit.digest(),
    )?;
    write_grant(root, "path", signed)?;
    write_grant(
        root,
        "transit",
        signer.sign(&GrantClaims::Transit(TransitClaims {
            scope: scope(5),
            peers,
            transport_group: path.transport_group_id(),
            route_id: "60000000-0000-4000-8000-000000000006".into(),
            relay: PeerId(relay.fingerprint()),
            previous: peers.first,
            next: peers.second,
            remaining_hops: 1,
            byte_limit: 4_000_000,
        }))?,
    )?;
    println!(
        "NESTLINK_ROUTED provisioned=true route_lifetime_ms=12000 business_lease_ms=15000 business_proof_exercised=false"
    );
    Ok(())
}
pub struct Authority {
    issuer: [u8; 32],
    revoked: BTreeSet<String>,
    pub permit: VerifiedPermit,
    pub path: VerifiedNetworkPath,
    pub connectivity: VerifiedNetworkGrant,
    pub transit: VerifiedNetworkGrant,
}
impl Authority {
    pub fn load(root: &Path) -> Result<Self> {
        let issuer = key(root, "authority")?;
        let revoked = BTreeSet::new();
        let context = NetworkVerification {
            authority_key: &issuer,
            deployment_id: DEPLOYMENT,
            space_id: SPACE,
            policy_epoch: 9,
            now_ms: now_ms()?,
            revoked_grant_ids: &revoked,
        };
        let permit = verify_permit(&fs::read(root.join("permit.bin"))?, &key(root, "business")?)?;
        let mut memberships = Vec::new();
        for (index, name) in ["first", "second"].into_iter().enumerate() {
            memberships.push(VerifiedMembership::from_grant(
                read_grant(root, name, &context)?,
                &context,
                INSTALLATIONS[index],
                &key(root, name)?,
                1,
            )?);
        }
        let connectivity = read_grant(root, "connectivity", &context)?;
        let path = VerifiedNetworkPath::from_grants(
            &context,
            [memberships.remove(0), memberships.remove(0)],
            connectivity.clone(),
            read_grant(root, "path", &context)?,
            permit.digest(),
        )?;
        let transit = read_grant(root, "transit", &context)?;
        Ok(Self {
            issuer,
            revoked,
            permit,
            path,
            connectivity,
            transit,
        })
    }
    pub fn authorize(&self) -> Result<(RouteAuthorization, RouteRevocation)> {
        let context = NetworkVerification {
            authority_key: &self.issuer,
            deployment_id: DEPLOYMENT,
            space_id: SPACE,
            policy_epoch: 9,
            now_ms: now_ms()?,
            revoked_grant_ids: &self.revoked,
        };
        Ok(RouteAuthorization::remote(
            &context,
            &self.path,
            &self.connectivity,
            &self.transit,
            &self.permit,
        )?)
    }
}
