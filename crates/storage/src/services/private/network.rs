//! Service paths reuse the independent network signer, typed membership chain
//! and signed path policies. No remote-control permit is created or borrowed.
use super::*;
use nestlink_identity::network::{
    NetworkAuthoritySigner, SignedNetworkGrant, VerifiedNetworkPath, private_service_path_peers,
    verify_network_grant,
};
use nestlink_protocol::network::{
    ConnectivityClaims, GrantClaims, GrantScope, MembershipClaims, PathClaims, PathPolicy, PeerId,
    PeerPair, Purpose,
};

pub(super) fn view(signed: SignedNetworkGrant) -> Result<NetworkGrantView, StorageError> {
    let claims = GrantClaims::decode_canonical(&signed.claims)?;
    Ok(NetworkGrantView {
        schema_version: nestlink_protocol::network::SCHEMA_VERSION,
        grant_id: claims.scope().grant_id.clone(),
        claims: URL_SAFE_NO_PAD.encode(signed.claims),
        signature: URL_SAFE_NO_PAD.encode(signed.signature),
    })
}
pub(super) fn signed(view: &NetworkGrantView) -> Result<SignedNetworkGrant, StorageError> {
    let decode = |value: &str| -> Result<Vec<u8>, StorageError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| StorageError::Forbidden)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != value {
            return Err(StorageError::Forbidden);
        }
        Ok(bytes)
    };
    let signed = SignedNetworkGrant {
        claims: decode(&view.claims)?,
        signature: decode(&view.signature)?,
    };
    let claims = GrantClaims::decode_canonical(&signed.claims)?;
    if view.schema_version != nestlink_protocol::network::SCHEMA_VERSION
        || view.grant_id != claims.scope().grant_id
    {
        return Err(StorageError::Forbidden);
    }
    Ok(signed)
}
pub(super) fn verify(
    snapshot: &crate::network_policy::TrustedNetworkPolicySnapshot,
    view: &PrivateServiceNetworkPath,
    lease: &VerifiedPrivateServiceLease,
) -> Result<VerifiedNetworkPath, StorageError> {
    let grant: ServiceUsageBudgetGrantClaims = decode_service_message(
        &lease.lease().claims().usage_grant.claims,
        SERVICE_USAGE_BYTES,
    )?;
    if grant.grant_id != view.grant_id {
        return Err(StorageError::Forbidden);
    }
    let consumer = snapshot.verify_member(
        &signed(&view.consumer_membership)?,
        &lease.claims().consumer_device_id,
    )?;
    let host = snapshot.verify_member(
        &signed(&view.host_membership)?,
        &lease.lease().claims().definition.host_device_id,
    )?;
    let context = snapshot.verification();
    let connection = verify_network_grant(&signed(&view.connectivity)?, &context)?;
    let path = VerifiedNetworkPath::from_grants(
        &context,
        [consumer, host],
        connection.clone(),
        verify_network_grant(&signed(&view.path)?, &context)?,
        lease.digest(),
    )?;
    private_service_path_peers(&context, &path, &connection, lease)?;
    match &view.relay {
        None => path.check_route(&context, &[])?,
        Some(route) => {
            let transits = route
                .transits
                .iter()
                .map(|v| Ok(verify_network_grant(&signed(v)?, &context)?))
                .collect::<Result<Vec<_>, StorageError>>()?;
            if transits.len() == 1 {
                nestlink_identity::network::private_service_route_binding(
                    &context,
                    &path,
                    &connection,
                    &transits[0],
                    lease,
                )?;
            } else {
                nestlink_identity::network::private_service_chain_binding(
                    &context,
                    &path,
                    &connection,
                    &transits,
                    lease,
                )?;
            }
        }
    }
    Ok(path)
}
impl Store {
    pub fn issue_private_service_network_path(
        &mut self,
        actor: &Principal,
        service: &str,
        grant_id: &str,
        service_signer: &ServiceLeaseSigner,
        network_signer: &NetworkAuthoritySigner,
        now: u64,
    ) -> Result<PrivateServiceNetworkPath, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let lease = self.private_service_lease(actor, service, grant_id, service_signer, now)?;
        let lease = verify_private_service_lease(&lease, &service_signer.public_key())?;
        let path = self.issue_private_service_network_path_in_transaction(
            &tx,
            actor,
            grant_id,
            &lease,
            network_signer,
            PathPolicy {
                allow_direct: true,
                relays: Vec::new(),
                max_hops: 0,
            },
            now,
        )?;
        tx.commit()?;
        Ok(path)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn issue_private_service_network_path_in_transaction(
        &self,
        tx: &Transaction<'_>,
        actor: &Principal,
        grant_id: &str,
        lease: &VerifiedPrivateServiceLease,
        network_signer: &NetworkAuthoritySigner,
        policy: PathPolicy,
        now: u64,
    ) -> Result<PrivateServiceNetworkPath, StorageError> {
        let binding = lease.claims();
        let base = lease.lease().claims();
        if actor.account_id != binding.consumer_account_id {
            return Err(StorageError::Forbidden);
        }
        let snapshot = crate::network_policy::read_snapshot(tx, &binding.space_id, now)?;
        if network_signer.public_key() != binding.network_authority_key
            || snapshot.verification().authority_key != &binding.network_authority_key
        {
            return Err(StorageError::Forbidden);
        }
        let existing: Option<String> = tx.query_row(
            "SELECT network_json FROM private_service_leases WHERE grant_id=?1",
            [grant_id],
            |r| r.get(0),
        )?;
        if let Some(json) = existing {
            let path = serde_json::from_str(&json)?;
            verify(&snapshot, &path, lease)?;
            return Ok(path);
        }
        let scope = || GrantScope {
            schema_version: nestlink_protocol::network::SCHEMA_VERSION,
            deployment_id: base.deployment_id.clone(),
            space_id: binding.space_id.clone(),
            grant_id: random_id(),
            policy_epoch: binding.space_policy_epoch,
            not_before_ms: now,
            expires_at_ms: base.expires_at_unix_ms,
        };
        let member =
            |id: &str, key: [u8; 32], epoch: u64| -> Result<SignedNetworkGrant, StorageError> {
                let current = snapshot
                    .member(id)
                    .filter(|m| m.active())
                    .ok_or(StorageError::Forbidden)?;
                if current.public_key() != key || current.membership_epoch() != epoch {
                    return Err(StorageError::Forbidden);
                }
                Ok(
                    network_signer.sign(&GrantClaims::Membership(MembershipClaims {
                        scope: scope(),
                        installation_id: id.into(),
                        peer: PeerId::from_public_key(&key),
                        public_key: key,
                        membership_epoch: epoch,
                        role: current.role(),
                    }))?,
                )
            };
        let consumer = member(
            &binding.consumer_device_id,
            binding.consumer_public_key,
            binding.consumer_membership_epoch,
        )?;
        let host = member(
            &base.definition.host_device_id,
            binding.host_public_key,
            binding.host_membership_epoch,
        )?;
        let c = snapshot.verify_member(&consumer, &binding.consumer_device_id)?;
        let h = snapshot.verify_member(&host, &base.definition.host_device_id)?;
        let peers = PeerPair::new(c.peer(), h.peer())?;
        let membership_digests = if c.peer() == peers.first {
            [c.digest(), h.digest()]
        } else {
            [h.digest(), c.digest()]
        };
        let connectivity = network_signer.sign(&GrantClaims::Connectivity(ConnectivityClaims {
            scope: scope(),
            peers,
            purpose: Purpose::PrivateService,
            membership_digests,
            business_grant_digest: lease.digest(),
        }))?;
        let verified_connectivity = verify_network_grant(&connectivity, &snapshot.verification())?;
        let path = network_signer.sign(&GrantClaims::Path(PathClaims {
            scope: scope(),
            peers,
            purpose: Purpose::PrivateService,
            connectivity_grant_digest: verified_connectivity.digest(),
            policy,
        }))?;
        let path = PrivateServiceNetworkPath {
            grant_id: grant_id.into(),
            consumer_membership: view(consumer)?,
            host_membership: view(host)?,
            connectivity: view(connectivity)?,
            path: view(path)?,
            relay: None,
        };
        if path.relay.is_none()
            && GrantClaims::decode_canonical(&signed(&path.path)?.claims)
                .is_ok_and(|c| matches!(c,GrantClaims::Path(p) if p.policy.allow_direct))
        {
            verify(&snapshot, &path, lease)?;
        }
        tx.execute("UPDATE private_service_leases SET network_json=?1 WHERE grant_id=?2 AND network_json IS NULL",params![serde_json::to_string(&path)?,grant_id])?;
        Ok(path)
    }
    pub fn private_service_network_path(
        &self,
        actor: &Principal,
        service: &str,
        grant_id: &str,
        signer: &ServiceLeaseSigner,
        now: u64,
    ) -> Result<PrivateServiceNetworkPath, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let lease = self.private_service_lease(actor, service, grant_id, signer, now)?;
        let lease = verify_private_service_lease(&lease, &signer.public_key())?;
        let snapshot = crate::network_policy::read_snapshot(&tx, &lease.claims().space_id, now)?;
        let json: Option<String> = tx.query_row(
            "SELECT network_json FROM private_service_leases WHERE grant_id=?1",
            [grant_id],
            |r| r.get(0),
        )?;
        let path = serde_json::from_str(&json.ok_or(StorageError::Forbidden)?)?;
        verify(&snapshot, &path, &lease)?;
        self.private_service_relay_current(&tx, grant_id, &lease, now)?;
        tx.commit()?;
        Ok(path)
    }
}
