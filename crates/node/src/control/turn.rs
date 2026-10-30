//! Signed TURN resource polling and installation into the shared listener authority.
use super::{Error, NodeConfig, NodeIdentity, Runtime, sample};
use futures_util::StreamExt;
use nestlink_identity::{
    digest,
    turn::{verify_turn_peer_binding, verify_turn_resource_snapshot},
};
use nestlink_protocol::{
    ContractError, ErrorCode, NODE_RESOURCE_MESSAGE_BYTES, NODE_RESOURCE_POLL_MS,
    NODE_RESOURCE_TTL_MS, SCHEMA_VERSION, SignedTurnResourceQuery, SignedTurnResourceSnapshot,
    TurnGrantClaims, TurnPeerBindingClaims, TurnResourceQueryClaims, TurnResourceSnapshotClaims,
    decode_bounded, turn::TURN_BINDING_BYTES,
};
use nestlink_session::ClockSample;
use nestlink_traversal::turn::{
    TurnAllocationGrant, TurnAuthorization, TurnGrantError, TurnPeerBindingActivation,
    TurnPurpose as ManagedTurnPurpose,
};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const MAX_TRACKED_GRANTS: usize = 4096;

struct PollState {
    request_sequence: u64,
    snapshot_sequence: u64,
    grants: HashMap<String, TrackedGrant>,
}

struct TrackedGrant {
    claims: TurnGrantClaims,
    activated_binding: Option<TrackedBinding>,
    pending_binding: Option<TrackedBinding>,
    last_binding: Option<BindingWatermark>,
    revoked: bool,
    /// A local socket close is terminal for this allocation, not the node.
    ended: bool,
}

#[derive(Clone)]
struct TrackedBinding {
    claims: Vec<u8>,
    digest: [u8; 32],
    issued_at_unix_ms: u64,
    deadline: Instant,
    peer_strings: Vec<String>,
}

#[derive(Clone, Copy)]
struct BindingWatermark {
    digest: [u8; 32],
    issued_at_unix_ms: u64,
}

struct PollContext<'a> {
    state: &'a Arc<Mutex<Runtime>>,
    started: Instant,
    identity: &'a NodeIdentity,
    authorization: &'a TurnAuthorization,
}

struct PreparedActivation {
    allocation_id: String,
    session_id: String,
    temporary_identity: String,
    generation: u64,
    connection_generation: u64,
    grant_sequence: u64,
    lease_sequence: u64,
    binding_claims: Vec<u8>,
    binding_sha256: [u8; 32],
    binding_issued_at_unix_ms: u64,
    binding_deadline: Instant,
    peers: Vec<SocketAddr>,
    peer_strings: Vec<String>,
}

pub(super) async fn poll(
    config: NodeConfig,
    identity: Arc<NodeIdentity>,
    state: Arc<Mutex<Runtime>>,
    authorization: Arc<TurnAuthorization>,
    started: Instant,
) -> Result<(), Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(700))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| Error::Control)?;
    let url = format!(
        "{}/api/v3/nodes/{}/turn-resources",
        config.control_origin, config.node_id
    );
    let issuer = config.issuer()?;
    let mut local = PollState {
        request_sequence: 0,
        snapshot_sequence: 0,
        grants: HashMap::new(),
    };
    let mut tick = tokio::time::interval(Duration::from_millis(NODE_RESOURCE_POLL_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let (query, request_started) = {
            let mut runtime = state.lock().map_err(|_| Error::Control)?;
            if !runtime.ready {
                continue;
            }
            let now = sample(started)?;
            let lease = runtime.gate.current(now)?.clone();
            local.request_sequence = local
                .request_sequence
                .checked_add(1)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(Error::Control)?;
            (
                TurnResourceQueryClaims {
                    schema_version: SCHEMA_VERSION,
                    deployment_id: lease.deployment_id,
                    security_epoch: lease.security_epoch,
                    node_id: lease.node_id,
                    runtime_id: lease.runtime_id,
                    runtime_generation: lease.runtime_generation,
                    policy_revision: lease.policy_revision,
                    lease_sequence: lease.lease_sequence,
                    request_id: uuid::Uuid::new_v4().hyphenated().to_string(),
                    request_sequence: local.request_sequence,
                    issued_at_unix_ms: now.unix_ms,
                    expires_at_unix_ms: now
                        .unix_ms
                        .checked_add(NODE_RESOURCE_TTL_MS)
                        .ok_or(Error::Control)?
                        .min(lease.expires_at_unix_ms),
                },
                now.monotonic_ms,
            )
        };
        let signed = identity.sign_turn_resource_query(&query)?;
        let response = tokio::time::timeout(
            Duration::from_millis(700),
            receive_snapshot(&client, &url, &signed, &issuer),
        )
        .await;
        let snapshot = match response {
            Ok(Ok(snapshot)) => snapshot,
            Ok(Err(Error::Authorization(error))) => {
                // An authenticated but invalid authority response must not leave
                // earlier grants live while the node keeps serving TURN.
                authorization.revoke_all();
                return Err(Error::Authorization(error));
            }
            Ok(Err(_)) | Err(_) => continue,
        };
        let context = PollContext {
            state: &state,
            started,
            identity: &identity,
            authorization: &authorization,
        };
        accept_snapshot(&context, &query, request_started, snapshot, &mut local)?;
    }
}

async fn receive_snapshot(
    client: &reqwest::Client,
    url: &str,
    request: &SignedTurnResourceQuery,
    issuer: &[u8; 32],
) -> Result<TurnResourceSnapshotClaims, Error> {
    let response = client
        .post(url)
        .json(request)
        .send()
        .await
        .map_err(|_| Error::Control)?;
    if !response.status().is_success() {
        return Err(Error::TurnResourceStatus(response.status().as_u16()));
    }
    let mut chunks = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|_| Error::Control)?;
        if bytes.len() + chunk.len() > (NODE_RESOURCE_MESSAGE_BYTES * 4 + 512) as usize {
            return Err(Error::Authorization(ContractError::new(
                ErrorCode::CapacityExceeded,
                "TURN snapshot response exceeded its budget",
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    let signed: SignedTurnResourceSnapshot = serde_json::from_slice(&bytes).map_err(|_| {
        Error::Authorization(ContractError::new(
            ErrorCode::InvalidMessage,
            "malformed TURN snapshot response",
        ))
    })?;
    Ok(verify_turn_resource_snapshot(&signed, issuer, request)?)
}

fn accept_snapshot(
    context: &PollContext<'_>,
    query: &TurnResourceQueryClaims,
    request_started: u64,
    snapshot: TurnResourceSnapshotClaims,
    local: &mut PollState,
) -> Result<(), Error> {
    let now = sample(context.started)?;
    if snapshot.snapshot_sequence <= local.snapshot_sequence
        || snapshot.issued_at_unix_ms > now.unix_ms.saturating_add(1000)
        || snapshot.expires_at_unix_ms <= now.unix_ms
        || snapshot.issued_at_unix_ms.saturating_add(1000) < query.issued_at_unix_ms
        || request_started > now.monotonic_ms
    {
        return Err(authorization_error(ErrorCode::ReplayRejected));
    }
    {
        let mut runtime = context.state.lock().map_err(|_| Error::Control)?;
        if !runtime.ready {
            return Err(Error::Control);
        }
        let lease = runtime.gate.current(now)?.clone();
        if query.deployment_id != lease.deployment_id
            || query.security_epoch != lease.security_epoch
            || query.node_id != lease.node_id
            || query.runtime_id != lease.runtime_id
            || query.runtime_generation != lease.runtime_generation
            || query.policy_revision != lease.policy_revision
            || query.lease_sequence > lease.lease_sequence
        {
            return Err(authorization_error(ErrorCode::IdentityMismatch));
        }
    }

    // Validate every grant and peer transcript before changing shared state.
    let node_key = digest(&context.identity.public_key());
    let mut prepared = HashMap::with_capacity(snapshot.grants.len());
    for claims in &snapshot.grants {
        let managed = managed_grant(claims, &node_key, request_started, now)?;
        prepared.insert(claims.allocation_id.clone(), (claims.clone(), managed));
    }
    let activations = verify_peer_bindings(&snapshot, request_started, now)?;
    let new_grants = prepared
        .keys()
        .filter(|id| !local.grants.contains_key(*id))
        .count();
    if local.grants.len().saturating_add(new_grants) > MAX_TRACKED_GRANTS {
        return Err(authorization_error(ErrorCode::CapacityExceeded));
    }
    for (id, (claims, _)) in &prepared {
        if let Some(old) = local.grants.get(id) {
            if old.revoked || claims.grant_sequence < old.claims.grant_sequence {
                return Err(authorization_error(ErrorCode::ReplayRejected));
            }
            if claims.grant_sequence == old.claims.grant_sequence && claims != &old.claims {
                return Err(authorization_error(ErrorCode::ReplayRejected));
            }
        }
    }

    let current_ids: HashSet<String> = prepared.keys().cloned().collect();
    for (id, (claims, grant)) in prepared {
        let (activated_binding, pending_binding, last_binding) =
            local.grants.get(&id).map_or((None, None, None), |old| {
                (
                    (old.claims.lease_sequence == claims.lease_sequence)
                        .then(|| old.activated_binding.clone())
                        .flatten(),
                    (old.claims.lease_sequence == claims.lease_sequence)
                        .then(|| old.pending_binding.clone())
                        .flatten(),
                    old.last_binding,
                )
            });
        match local.grants.get(&id) {
            Some(old) if old.ended => {
                // Retain a tombstone through the newest signed expiry. Never
                // reinstall a credential whose socket has already closed.
                if let Some(tracked) = local.grants.get_mut(&id) {
                    tracked.claims = claims;
                }
                continue;
            }
            Some(old) if claims.grant_sequence == old.claims.grant_sequence => continue,
            Some(_) => match context.authorization.renew_grant(grant) {
                Ok(()) => {}
                Err(TurnGrantError::AllocationEnded) => {
                    if let Some(tracked) = local.grants.get_mut(&id) {
                        tracked.ended = true;
                        tracked.claims = claims;
                        tracked.activated_binding = None;
                        tracked.pending_binding = None;
                    }
                    continue;
                }
                Err(_) => return Err(Error::Control),
            },
            None => context
                .authorization
                .install_grant(grant)
                .map_err(|_| Error::Control)?,
        }
        local.grants.insert(
            id.clone(),
            TrackedGrant {
                claims: claims.clone(),
                activated_binding,
                pending_binding,
                last_binding,
                revoked: false,
                ended: false,
            },
        );
    }

    for (id, tracked) in &mut local.grants {
        if !current_ids.contains(id) && !tracked.revoked {
            match context.authorization.revoke(id) {
                Ok(_) | Err(TurnGrantError::GrantNotFound) => {}
                Err(_) => return Err(Error::Control),
            }
            tracked.revoked = true;
        }
    }

    let binding_allocations = activations
        .iter()
        .map(|activation| activation.allocation_id.clone())
        .collect::<HashSet<_>>();
    for activation in activations {
        let Some(tracked) = local.grants.get_mut(&activation.allocation_id) else {
            return Err(Error::Control);
        };
        if tracked.revoked {
            return Err(authorization_error(ErrorCode::ReplayRejected));
        }
        if tracked.ended {
            continue;
        }
        let reused = if let Some(existing) = &tracked.activated_binding {
            if existing.digest == activation.binding_sha256 {
                if existing.claims != activation.binding_claims
                    || existing.peer_strings != activation.peer_strings
                {
                    return Err(authorization_error(ErrorCode::ReplayRejected));
                }
                Some(existing.deadline)
            } else {
                if activation.binding_issued_at_unix_ms <= existing.issued_at_unix_ms {
                    return Err(authorization_error(ErrorCode::ReplayRejected));
                }
                None
            }
        } else if let Some(pending) = &tracked.pending_binding {
            if pending.digest == activation.binding_sha256 {
                if pending.claims != activation.binding_claims
                    || pending.peer_strings != activation.peer_strings
                {
                    return Err(authorization_error(ErrorCode::ReplayRejected));
                }
                Some(pending.deadline)
            } else {
                if activation.binding_issued_at_unix_ms <= pending.issued_at_unix_ms {
                    return Err(authorization_error(ErrorCode::ReplayRejected));
                }
                None
            }
        } else if let Some(previous) = tracked.last_binding {
            if previous.digest == activation.binding_sha256
                || activation.binding_issued_at_unix_ms <= previous.issued_at_unix_ms
            {
                return Err(authorization_error(ErrorCode::ReplayRejected));
            }
            None
        } else {
            None
        };
        let binding_deadline = reused.unwrap_or(activation.binding_deadline);
        match context
            .authorization
            .activate_peer_binding(TurnPeerBindingActivation {
                allocation_id: &activation.allocation_id,
                session_id: &activation.session_id,
                temporary_identity: &activation.temporary_identity,
                generation: activation.generation,
                connection_generation: activation.connection_generation,
                grant_sequence: activation.grant_sequence,
                lease_sequence: activation.lease_sequence,
                binding_sha256: activation.binding_sha256,
                issued_at_unix_ms: activation.binding_issued_at_unix_ms,
                deadline: binding_deadline,
                peers: &activation.peers,
            }) {
            Ok(()) => {
                let binding = TrackedBinding {
                    claims: activation.binding_claims,
                    digest: activation.binding_sha256,
                    issued_at_unix_ms: activation.binding_issued_at_unix_ms,
                    deadline: binding_deadline,
                    peer_strings: activation.peer_strings,
                };
                tracked.last_binding = Some(BindingWatermark {
                    digest: binding.digest,
                    issued_at_unix_ms: binding.issued_at_unix_ms,
                });
                tracked.activated_binding = Some(binding);
                tracked.pending_binding = None;
            }
            // Candidate gathering happens before CreatePermission. The paired
            // binding may arrive first and will be retried on the next poll.
            Err(TurnGrantError::InvalidGrant) => {
                if tracked
                    .activated_binding
                    .as_ref()
                    .is_some_and(|binding| binding.deadline <= Instant::now())
                {
                    tracked.activated_binding = None;
                } else if tracked.activated_binding.is_none() && binding_deadline > Instant::now() {
                    tracked.pending_binding = Some(TrackedBinding {
                        claims: activation.binding_claims,
                        digest: activation.binding_sha256,
                        issued_at_unix_ms: activation.binding_issued_at_unix_ms,
                        deadline: binding_deadline,
                        peer_strings: activation.peer_strings,
                    });
                }
            }
            Err(_) => return Err(Error::Control),
        }
    }

    // The snapshot is authoritative about which signed candidate pair is
    // current. Removing the binding immediately removes its forwarding
    // allowlist while leaving the allocation's grant lease intact.
    for (id, tracked) in &mut local.grants {
        if tracked.revoked || !current_ids.contains(id) || binding_allocations.contains(id) {
            continue;
        }
        if tracked.activated_binding.take().is_some() {
            match context
                .authorization
                .clear_peer_binding(id, tracked.claims.lease_sequence)
            {
                Ok(()) | Err(TurnGrantError::GrantNotFound) => {}
                Err(_) => return Err(Error::Control),
            }
        }
        if let Some(pending) = tracked.pending_binding.take() {
            tracked.last_binding = Some(BindingWatermark {
                digest: pending.digest,
                issued_at_unix_ms: pending.issued_at_unix_ms,
            });
        }
    }
    local
        .grants
        .retain(|_, grant| grant.claims.expires_at_unix_ms > now.unix_ms);
    local.snapshot_sequence = snapshot.snapshot_sequence;
    Ok(())
}

fn managed_grant(
    claims: &TurnGrantClaims,
    node_key: &[u8; 32],
    request_started: u64,
    now: ClockSample,
) -> Result<TurnAllocationGrant, Error> {
    if claims.node_key_sha256.as_slice() != node_key {
        return Err(authorization_error(ErrorCode::IdentityMismatch));
    }
    let auth_key: [u8; 16] = claims
        .auth_key
        .as_slice()
        .try_into()
        .map_err(|_| authorization_error(ErrorCode::InvalidMessage))?;
    let expires_in = claims
        .expires_at_unix_ms
        .checked_sub(now.unix_ms)
        .filter(|duration| *duration > 0)
        .ok_or_else(|| authorization_error(ErrorCode::LeaseExpired))?;
    let lifetime = claims
        .expires_at_unix_ms
        .checked_sub(claims.issued_at_unix_ms)
        .filter(|duration| *duration > 0)
        .ok_or_else(|| authorization_error(ErrorCode::InvalidMessage))?;
    let monotonic_deadline = request_started
        .checked_add(expires_in.min(lifetime))
        .filter(|deadline| *deadline > now.monotonic_ms)
        .ok_or_else(|| authorization_error(ErrorCode::LeaseExpired))?;
    let deadline = context_instant(monotonic_deadline, now.monotonic_ms)?;
    Ok(TurnAllocationGrant {
        deployment_id: claims.deployment_id.clone(),
        node_id: claims.node_id.clone(),
        runtime_id: claims.runtime_id.clone(),
        allocation_id: claims.allocation_id.clone(),
        session_id: claims.session_id.clone(),
        temporary_identity: claims.temporary_identity.clone(),
        purpose: ManagedTurnPurpose::BrowserWebRtc,
        generation: claims.network_generation,
        connection_generation: claims.connection_generation,
        grant_sequence: claims.grant_sequence,
        lease_sequence: claims.lease_sequence,
        node_key_sha256: *node_key,
        device_id: claims.device_id.clone(),
        controller_device_id: claims.controller_device_id.clone(),
        host_device_id: claims.host_device_id.clone(),
        controller_key_sha256: claims
            .controller_key_sha256
            .as_slice()
            .try_into()
            .map_err(|_| authorization_error(ErrorCode::InvalidMessage))?,
        host_key_sha256: claims
            .host_key_sha256
            .as_slice()
            .try_into()
            .map_err(|_| authorization_error(ErrorCode::InvalidMessage))?,
        permit_sha256: claims
            .permit_sha256
            .as_slice()
            .try_into()
            .map_err(|_| authorization_error(ErrorCode::InvalidMessage))?,
        session_binding_sha256: claims
            .session_binding_sha256
            .as_slice()
            .try_into()
            .map_err(|_| authorization_error(ErrorCode::InvalidMessage))?,
        policy_revision: claims.policy_revision,
        quota_revision: claims.quota_revision,
        endpoint_revision: claims.endpoint_revision,
        username: claims.username.clone(),
        realm: claims.realm.clone(),
        auth_key,
        peer_allowlist: Vec::new(),
        max_peers: claims.max_peers as usize,
        expires_at_unix_ms: claims.expires_at_unix_ms,
        deadline,
        max_total_bytes: claims.bytes_per_allocation,
        max_bytes_per_second: claims.bytes_per_second,
    })
}

fn context_instant(deadline: u64, now: u64) -> Result<Instant, Error> {
    Instant::now()
        .checked_add(Duration::from_millis(deadline.saturating_sub(now)))
        .ok_or(Error::Control)
}

fn verify_peer_bindings(
    snapshot: &TurnResourceSnapshotClaims,
    request_started: u64,
    now: ClockSample,
) -> Result<Vec<PreparedActivation>, Error> {
    let mut activations = Vec::new();
    for signed in &snapshot.peer_bindings {
        let binding: TurnPeerBindingClaims = decode_bounded(&signed.claims, TURN_BINDING_BYTES)?;
        binding.validate()?;
        let grant = snapshot
            .grants
            .iter()
            .find(|grant| binding.matches_grant(grant))
            .ok_or_else(|| authorization_error(ErrorCode::IdentityMismatch))?;
        let controller_key: [u8; 32] = grant
            .controller_public_key
            .as_slice()
            .try_into()
            .map_err(|_| authorization_error(ErrorCode::InvalidMessage))?;
        let host_key: [u8; 32] = grant
            .host_public_key
            .as_slice()
            .try_into()
            .map_err(|_| authorization_error(ErrorCode::InvalidMessage))?;
        if digest(&controller_key) != binding.controller_key_sha256.as_slice()
            || digest(&host_key) != binding.host_key_sha256.as_slice()
        {
            return Err(authorization_error(ErrorCode::IdentityMismatch));
        }
        let verified = verify_turn_peer_binding(signed, &controller_key, &host_key)?;
        let expires_in = verified
            .expires_at_unix_ms
            .checked_sub(now.unix_ms)
            .filter(|duration| *duration > 0)
            .ok_or_else(|| authorization_error(ErrorCode::LeaseExpired))?;
        let lifetime = verified
            .expires_at_unix_ms
            .checked_sub(verified.issued_at_unix_ms)
            .filter(|duration| *duration > 0)
            .ok_or_else(|| authorization_error(ErrorCode::InvalidMessage))?;
        let monotonic_deadline = request_started
            .checked_add(expires_in.min(lifetime))
            .filter(|deadline| *deadline > now.monotonic_ms)
            .ok_or_else(|| authorization_error(ErrorCode::LeaseExpired))?;
        let binding_deadline = context_instant(monotonic_deadline, now.monotonic_ms)?;
        let binding_sha256 = digest(&signed.claims);
        for local_grant in snapshot
            .grants
            .iter()
            .filter(|grant| verified.matches_grant(grant))
        {
            let peer_strings = verified.peers_for(local_grant).to_vec();
            let peers = peer_strings
                .iter()
                .map(|value| {
                    value
                        .parse::<SocketAddr>()
                        .map_err(|_| authorization_error(ErrorCode::InvalidMessage))
                })
                .collect::<Result<Vec<_>, _>>()?;
            activations.push(PreparedActivation {
                allocation_id: local_grant.allocation_id.clone(),
                session_id: local_grant.session_id.clone(),
                temporary_identity: local_grant.temporary_identity.clone(),
                generation: local_grant.network_generation,
                connection_generation: local_grant.connection_generation,
                grant_sequence: local_grant.grant_sequence,
                lease_sequence: local_grant.lease_sequence,
                binding_claims: signed.claims.clone(),
                binding_sha256,
                binding_issued_at_unix_ms: verified.issued_at_unix_ms,
                binding_deadline,
                peers,
                peer_strings,
            });
        }
    }
    Ok(activations)
}

fn authorization_error(code: ErrorCode) -> Error {
    Error::Authorization(ContractError::new(code, "invalid TURN resource authority"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{gate::NodeGate, meter::Meter};
    use nestlink_identity::{InstallationIdentity, PermitSigner, nodes::NodePolicySigner};
    use nestlink_protocol::{
        NODE_RESOURCE_TTL_MS, NodeChallenge, NodeLeaseClaims, NodeRole, SCHEMA_VERSION,
        SignedTurnPeerBinding, SignedTurnResourceQuery, TurnPeerBindingClaims, TurnPurpose,
    };
    use prost::Message;
    use std::sync::Mutex;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    struct TestNode {
        started: Instant,
        identity: NodeIdentity,
        signer: NodePolicySigner,
        state: Arc<Mutex<Runtime>>,
        authorization: Arc<TurnAuthorization>,
    }

    impl TestNode {
        fn new() -> TestResult<Self> {
            let started = Instant::now();
            let identity = NodeIdentity::from_seed(&[1; 32]);
            let signer = PermitSigner::from_seed([2; 32]).node_policy_signer()?;
            let now = sample(started)?;
            let deployment_id = test_id(1);
            let node_id = test_id(2);
            let runtime_id = test_id(3);
            let request_id = test_id(4);
            let challenge = NodeChallenge {
                schema_version: SCHEMA_VERSION,
                deployment_id: deployment_id.clone(),
                security_epoch: 1,
                node_id: node_id.clone(),
                node_key_sha256: digest(&identity.public_key()).to_vec(),
                request_id: request_id.clone(),
                nonce: vec![9; 32],
                expires_at_unix_ms: now.unix_ms + 5_000,
            };
            let lease = NodeLeaseClaims {
                schema_version: SCHEMA_VERSION,
                deployment_id: deployment_id.clone(),
                security_epoch: 1,
                node_id: node_id.clone(),
                node_key_sha256: digest(&identity.public_key()).to_vec(),
                request_id,
                nonce: challenge.nonce.clone(),
                roles: vec![NodeRole::NodeRelay as i32],
                policy_revision: 1,
                lease_sequence: 1,
                issued_at_unix_ms: now.unix_ms,
                expires_at_unix_ms: now.unix_ms + 10_000,
                server_forwarding_allowed: true,
                public_ingress_allowed: false,
                max_connections: 8,
                bytes_per_second: 1024,
                runtime_id: runtime_id.clone(),
                runtime_generation: 1,
            };
            let mut gate = NodeGate::new(
                deployment_id,
                node_id,
                runtime_id,
                identity.public_key(),
                signer.public_key(),
                vec![NodeRole::NodeRelay],
            )?;
            gate.accept(
                &signer.sign(&lease)?.encode_to_vec(),
                &challenge,
                now.monotonic_ms,
                now,
            )?;
            Ok(Self {
                started,
                identity,
                signer,
                state: Arc::new(Mutex::new(Runtime {
                    gate,
                    meter: Meter::default(),
                    ready: true,
                    service_shutdown: false,
                    resources: super::super::resources::Resources::default(),
                    service_resource_owner: None,
                    service_usage: Arc::new(crate::service_usage::ServiceUsageStore::for_test()?),
                    topology: Default::default(),
                })),
                authorization: Arc::new(TurnAuthorization::new(4)?),
            })
        }

        fn query(&self) -> TestResult<(TurnResourceQueryClaims, SignedTurnResourceQuery, u64)> {
            let now = sample(self.started)?;
            let lease = {
                let mut state = self.state.lock().map_err(|_| "poisoned node state")?;
                state.gate.current(now)?.clone()
            };
            let claims = TurnResourceQueryClaims {
                schema_version: SCHEMA_VERSION,
                deployment_id: lease.deployment_id,
                security_epoch: lease.security_epoch,
                node_id: lease.node_id,
                runtime_id: lease.runtime_id,
                runtime_generation: lease.runtime_generation,
                policy_revision: lease.policy_revision,
                lease_sequence: lease.lease_sequence,
                request_id: test_id(5),
                request_sequence: 1,
                issued_at_unix_ms: now.unix_ms,
                expires_at_unix_ms: now
                    .unix_ms
                    .saturating_add(NODE_RESOURCE_TTL_MS)
                    .min(lease.expires_at_unix_ms),
            };
            let signed = self.identity.sign_turn_resource_query(&claims)?;
            Ok((claims, signed, now.monotonic_ms))
        }

        fn snapshot(
            &self,
            query: &TurnResourceQueryClaims,
            sequence: u64,
        ) -> TestResult<TurnResourceSnapshotClaims> {
            let now = sample(self.started)?;
            let controller_key = [3; 32];
            let host_key = [4; 32];
            let claims = TurnGrantClaims {
                schema_version: SCHEMA_VERSION,
                deployment_id: query.deployment_id.clone(),
                security_epoch: query.security_epoch,
                allocation_id: test_id(6),
                session_id: test_id(7),
                temporary_identity: test_id(8),
                purpose: TurnPurpose::BrowserWebRtc as i32,
                node_id: query.node_id.clone(),
                runtime_id: query.runtime_id.clone(),
                runtime_generation: query.runtime_generation,
                node_key_sha256: digest(&self.identity.public_key()).to_vec(),
                device_id: test_id(8),
                controller_device_id: test_id(8),
                host_device_id: test_id(9),
                controller_key_sha256: digest(&controller_key).to_vec(),
                host_key_sha256: digest(&host_key).to_vec(),
                network_generation: 1,
                connection_generation: 1,
                lease_sequence: 1,
                permit_sha256: vec![10; 32],
                policy_revision: query.policy_revision,
                quota_revision: 1,
                grant_sequence: 1,
                issued_at_unix_ms: now.unix_ms,
                expires_at_unix_ms: now.unix_ms.saturating_add(5_000),
                username: format!("nl:{}", test_id(6)),
                realm: "deployment.example".to_owned(),
                auth_key: vec![0x5a; 16],
                bytes_per_second: 1024,
                bytes_per_allocation: 10_000,
                max_peers: 1,
                endpoint_revision: 1,
                controller_public_key: controller_key.to_vec(),
                host_public_key: host_key.to_vec(),
                session_binding_sha256: vec![11; 32],
            };
            let snapshot = TurnResourceSnapshotClaims {
                query: Some(query.clone()),
                query_sha256: digest(&self.identity.sign_turn_resource_query(query)?.claims)
                    .to_vec(),
                snapshot_sequence: sequence,
                quota_revision: 1,
                issued_at_unix_ms: now.unix_ms,
                expires_at_unix_ms: query
                    .expires_at_unix_ms
                    .min(now.unix_ms.saturating_add(1_000)),
                grants: vec![claims],
                peer_bindings: Vec::new(),
            };
            snapshot.validate()?;
            Ok(snapshot)
        }

        fn accept(
            &self,
            query: &TurnResourceQueryClaims,
            request: &SignedTurnResourceQuery,
            request_started: u64,
            signed: &SignedTurnResourceSnapshot,
            local: &mut PollState,
        ) -> Result<(), Error> {
            let claims = verify_turn_resource_snapshot(signed, &self.signer.public_key(), request)?;
            let context = PollContext {
                state: &self.state,
                started: self.started,
                identity: &self.identity,
                authorization: &self.authorization,
            };
            accept_snapshot(&context, query, request_started, claims, local)
        }

        fn install_initial_grant(&self) -> TestResult<PollState> {
            let (query, request, request_started) = self.query()?;
            let claims = self.snapshot(&query, 1)?;
            let signed = self.signer.sign_turn_resource_snapshot(&claims)?;
            let mut local = PollState {
                request_sequence: 1,
                snapshot_sequence: 0,
                grants: HashMap::new(),
            };
            self.accept(&query, &request, request_started, &signed, &mut local)?;
            Ok(local)
        }

        fn paired_grants(
            &self,
            query: &TurnResourceQueryClaims,
            controller: &InstallationIdentity,
            host: &InstallationIdentity,
        ) -> TestResult<Vec<TurnGrantClaims>> {
            let mut controller_grant = self.snapshot(query, 1)?.grants.remove(0);
            let controller_key = controller.public_key();
            let host_key = host.public_key();
            controller_grant.controller_key_sha256 = digest(&controller_key).to_vec();
            controller_grant.host_key_sha256 = digest(&host_key).to_vec();
            controller_grant.controller_public_key = controller_key.to_vec();
            controller_grant.host_public_key = host_key.to_vec();

            let mut host_grant = controller_grant.clone();
            host_grant.allocation_id = test_id(10);
            host_grant.device_id = host_grant.host_device_id.clone();
            host_grant.username = format!("nl:{}", host_grant.allocation_id);
            host_grant.auth_key = vec![0x6b; 16];
            let mut grants = vec![controller_grant, host_grant];
            grants.sort_by(|left, right| left.allocation_id.cmp(&right.allocation_id));
            Ok(grants)
        }

        fn peer_binding(
            &self,
            grants: &[TurnGrantClaims],
            controller: &InstallationIdentity,
            host: &InstallationIdentity,
            issued_at_unix_ms: u64,
            controller_candidate: &str,
            host_candidate: &str,
        ) -> TestResult<SignedTurnPeerBinding> {
            let controller_grant = grants
                .iter()
                .find(|grant| grant.device_id == grant.controller_device_id)
                .ok_or("controller grant missing")?;
            let host_grant = grants
                .iter()
                .find(|grant| grant.device_id == grant.host_device_id)
                .ok_or("host grant missing")?;
            let claims = TurnPeerBindingClaims {
                schema_version: SCHEMA_VERSION,
                deployment_id: controller_grant.deployment_id.clone(),
                security_epoch: controller_grant.security_epoch,
                session_id: controller_grant.session_id.clone(),
                temporary_identity: controller_grant.temporary_identity.clone(),
                purpose: TurnPurpose::BrowserWebRtc as i32,
                controller_allocation_id: controller_grant.allocation_id.clone(),
                host_allocation_id: host_grant.allocation_id.clone(),
                controller_device_id: controller_grant.controller_device_id.clone(),
                host_device_id: controller_grant.host_device_id.clone(),
                controller_key_sha256: controller_grant.controller_key_sha256.clone(),
                host_key_sha256: controller_grant.host_key_sha256.clone(),
                controller_network_generation: controller_grant.network_generation,
                host_network_generation: host_grant.network_generation,
                connection_generation: controller_grant.connection_generation,
                lease_sequence: controller_grant.lease_sequence,
                permit_sha256: controller_grant.permit_sha256.clone(),
                controller_candidates: vec![controller_candidate.to_owned()],
                host_candidates: vec![host_candidate.to_owned()],
                issued_at_unix_ms,
                expires_at_unix_ms: controller_grant
                    .expires_at_unix_ms
                    .min(host_grant.expires_at_unix_ms),
            };
            Ok(SignedTurnPeerBinding {
                claims: claims.encode_to_vec(),
                controller_signature: controller.sign_turn_peer_binding(&claims)?,
                host_signature: host.sign_turn_peer_binding(&claims)?,
            })
        }

        fn peer_snapshot(
            &self,
            query: &TurnResourceQueryClaims,
            sequence: u64,
            grants: Vec<TurnGrantClaims>,
            binding: Option<SignedTurnPeerBinding>,
        ) -> TestResult<TurnResourceSnapshotClaims> {
            let now = sample(self.started)?;
            let signed_query = self.identity.sign_turn_resource_query(query)?;
            let snapshot = TurnResourceSnapshotClaims {
                query: Some(query.clone()),
                query_sha256: digest(&signed_query.claims).to_vec(),
                snapshot_sequence: sequence,
                quota_revision: 1,
                issued_at_unix_ms: now.unix_ms,
                expires_at_unix_ms: query
                    .expires_at_unix_ms
                    .min(now.unix_ms.saturating_add(1_000)),
                grants,
                peer_bindings: binding.into_iter().collect(),
            };
            snapshot.validate()?;
            Ok(snapshot)
        }
    }

    fn test_id(value: u8) -> String {
        format!("{value:08x}-1111-4111-8111-111111111111")
    }

    #[test]
    fn renewing_a_closed_allocation_keeps_other_sessions_and_the_node_alive() -> TestResult {
        let node = TestNode::new()?;
        let mut local = node.install_initial_grant()?;
        let first_id = test_id(6);
        let first_username = format!("nl:{first_id}");
        let client = SocketAddr::from(([192, 0, 2, 10], 55000));
        assert!(node.authorization.authorize_allocation(
            &first_username,
            "deployment.example",
            client,
        ));
        assert!(node.authorization.allocation_ready(&first_username, client));
        node.authorization
            .allocation_closed(&first_username, client);

        let mut closed = local
            .grants
            .get(&first_id)
            .ok_or("missing grant")?
            .claims
            .clone();
        closed.grant_sequence += 1;
        closed.expires_at_unix_ms += 1_000;
        let mut other = closed.clone();
        other.allocation_id = test_id(10);
        other.session_id = test_id(11);
        other.username = format!("nl:{}", other.allocation_id);
        other.grant_sequence = 1;
        let other_username = other.username.clone();
        let (query, request, request_started) = node.query()?;
        let claims = node.peer_snapshot(&query, 2, vec![closed.clone(), other.clone()], None)?;
        let signed = node.signer.sign_turn_resource_snapshot(&claims)?;
        node.accept(&query, &request, request_started, &signed, &mut local)?;
        assert!(local.grants.get(&first_id).is_some_and(|grant| grant.ended));
        assert!(!node.authorization.authorize_allocation(
            &first_username,
            "deployment.example",
            client,
        ));
        assert!(node.authorization.authorize_allocation(
            &other_username,
            "deployment.example",
            client,
        ));
        assert!(node.authorization.allocation_ready(&other_username, client));

        // A subsequent control renewal cannot revive the closed socket or
        // truncate the local replay tombstone to its original expiry.
        closed.grant_sequence += 1;
        closed.expires_at_unix_ms += 1_000;
        let (query, request, request_started) = node.query()?;
        let claims = node.peer_snapshot(&query, 3, vec![closed.clone(), other], None)?;
        let signed = node.signer.sign_turn_resource_snapshot(&claims)?;
        node.accept(&query, &request, request_started, &signed, &mut local)?;
        let tracked = local.grants.get(&first_id).ok_or("tombstone lost")?;
        assert!(tracked.ended);
        assert_eq!(tracked.claims.expires_at_unix_ms, closed.expires_at_unix_ms);
        assert_eq!(node.authorization.active_allocations(), 1);
        assert!(node.state.lock().map_err(|_| "node state poisoned")?.ready);
        Ok(())
    }

    #[test]
    fn old_snapshot_sequence_is_rejected_without_replacing_the_current_grant() -> TestResult {
        let node = TestNode::new()?;
        let mut local = node.install_initial_grant()?;
        let username = format!("nl:{}", test_id(6));
        assert!(
            node.authorization
                .auth_key(&username, "deployment.example")
                .is_some()
        );

        let (query, request, request_started) = node.query()?;
        let replay = node.snapshot(&query, 1)?;
        let replay = node.signer.sign_turn_resource_snapshot(&replay)?;
        assert!(matches!(
            node.accept(&query, &request, request_started, &replay, &mut local),
            Err(Error::Authorization(ContractError {
                code: ErrorCode::ReplayRejected,
                ..
            }))
        ));
        assert!(
            node.authorization
                .auth_key(&username, "deployment.example")
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn wrong_snapshot_issuer_key_cannot_install_a_turn_grant() -> TestResult {
        let node = TestNode::new()?;
        let (query, request, request_started) = node.query()?;
        let claims = node.snapshot(&query, 1)?;
        let wrong_signer = PermitSigner::from_seed([12; 32]).node_policy_signer()?;
        let signed = wrong_signer.sign_turn_resource_snapshot(&claims)?;
        let mut local = PollState {
            request_sequence: 1,
            snapshot_sequence: 0,
            grants: HashMap::new(),
        };
        assert!(
            node.accept(&query, &request, request_started, &signed, &mut local)
                .is_err()
        );
        assert!(
            node.authorization
                .auth_key(
                    "nl:00000006-1111-4111-8111-111111111111",
                    "deployment.example"
                )
                .is_none()
        );
        assert!(local.grants.is_empty());
        Ok(())
    }

    #[test]
    fn snapshot_with_a_different_security_epoch_cannot_install_a_grant() -> TestResult {
        let node = TestNode::new()?;
        let (mut query, _, request_started) = node.query()?;
        query.security_epoch += 1;
        let request = node.identity.sign_turn_resource_query(&query)?;
        let claims = node.snapshot(&query, 1)?;
        let signed = node.signer.sign_turn_resource_snapshot(&claims)?;
        let mut local = PollState {
            request_sequence: 1,
            snapshot_sequence: 0,
            grants: HashMap::new(),
        };
        assert!(matches!(
            node.accept(&query, &request, request_started, &signed, &mut local),
            Err(Error::Authorization(ContractError {
                code: ErrorCode::IdentityMismatch,
                ..
            }))
        ));
        assert!(local.grants.is_empty());
        assert!(
            node.authorization
                .auth_key(
                    "nl:00000006-1111-4111-8111-111111111111",
                    "deployment.example"
                )
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn signed_peer_binding_replacement_and_omission_update_forwarding_authority() -> TestResult {
        let node = TestNode::new()?;
        let controller = InstallationIdentity::from_seed([31; 32]);
        let host = InstallationIdentity::from_seed([32; 32]);
        let (query, request, request_started) = node.query()?;
        let grants = node.paired_grants(&query, &controller, &host)?;
        let initial = node.peer_snapshot(&query, 1, grants.clone(), None)?;
        let signed = node.signer.sign_turn_resource_snapshot(&initial)?;
        let mut local = PollState {
            request_sequence: 1,
            snapshot_sequence: 0,
            grants: HashMap::new(),
        };
        node.accept(&query, &request, request_started, &signed, &mut local)?;

        let issue_time = sample(node.started)?.unix_ms;
        let first_binding = node.peer_binding(
            &grants,
            &controller,
            &host,
            issue_time,
            "1.1.1.1:50000",
            "8.8.8.8:40000",
        )?;
        let retry_binding = first_binding.clone();
        let (query, request, request_started) = node.query()?;
        let first = node.peer_snapshot(&query, 2, grants.clone(), Some(first_binding))?;
        let signed = node.signer.sign_turn_resource_snapshot(&first)?;
        node.accept(&query, &request, request_started, &signed, &mut local)?;
        let controller_id = test_id(6);
        let original_binding_deadline = local
            .grants
            .get(&controller_id)
            .and_then(|grant| grant.pending_binding.as_ref())
            .map(|binding| binding.deadline)
            .ok_or("binding should remain pending until allocation is open")?;

        let controller_client = SocketAddr::from(([192, 0, 2, 10], 55000));
        let host_client = SocketAddr::from(([192, 0, 2, 11], 55001));
        for grant in &grants {
            let client = if grant.device_id == grant.controller_device_id {
                controller_client
            } else {
                host_client
            };
            assert!(
                node.authorization
                    .authorize_allocation(&grant.username, &grant.realm, client)
            );
            assert!(node.authorization.allocation_ready(&grant.username, client));
        }

        let (query, request, request_started) = node.query()?;
        let first_retry = node.peer_snapshot(&query, 3, grants.clone(), Some(retry_binding))?;
        let signed = node.signer.sign_turn_resource_snapshot(&first_retry)?;
        node.accept(&query, &request, request_started, &signed, &mut local)?;
        assert_eq!(
            local
                .grants
                .get(&controller_id)
                .and_then(|grant| grant.activated_binding.as_ref())
                .map(|binding| binding.deadline),
            Some(original_binding_deadline)
        );
        let controller_grant = grants
            .iter()
            .find(|grant| grant.device_id == grant.controller_device_id)
            .ok_or("controller grant missing")?;
        let old_peer = SocketAddr::from(([8, 8, 8, 8], 40000));
        assert!(node.authorization.authorize_action(
            &controller_grant.username,
            &controller_grant.realm,
            controller_client,
            nestlink_traversal::turn::TurnAction::SendIndication,
            Some(old_peer),
            1,
        ));

        std::thread::sleep(Duration::from_millis(2));
        let replacement_issue = sample(node.started)?.unix_ms;
        let replacement_binding = node.peer_binding(
            &grants,
            &controller,
            &host,
            replacement_issue,
            "4.2.2.2:50001",
            "9.9.9.9:40001",
        )?;
        let replay_candidate = replacement_binding.clone();
        let (query, request, request_started) = node.query()?;
        let replacement =
            node.peer_snapshot(&query, 4, grants.clone(), Some(replacement_binding))?;
        let signed = node.signer.sign_turn_resource_snapshot(&replacement)?;
        node.accept(&query, &request, request_started, &signed, &mut local)?;
        assert!(!node.authorization.authorize_action(
            &controller_grant.username,
            &controller_grant.realm,
            controller_client,
            nestlink_traversal::turn::TurnAction::SendIndication,
            Some(old_peer),
            1,
        ));
        let replacement_peer = SocketAddr::from(([9, 9, 9, 9], 40001));
        assert!(node.authorization.authorize_action(
            &controller_grant.username,
            &controller_grant.realm,
            controller_client,
            nestlink_traversal::turn::TurnAction::SendIndication,
            Some(replacement_peer),
            1,
        ));

        let (query, request, request_started) = node.query()?;
        let omitted = node.peer_snapshot(&query, 5, grants.clone(), None)?;
        let signed = node.signer.sign_turn_resource_snapshot(&omitted)?;
        node.accept(&query, &request, request_started, &signed, &mut local)?;
        assert!(!node.authorization.authorize_action(
            &controller_grant.username,
            &controller_grant.realm,
            controller_client,
            nestlink_traversal::turn::TurnAction::SendIndication,
            Some(replacement_peer),
            1,
        ));
        assert!(
            node.authorization
                .auth_key(&controller_grant.username, &controller_grant.realm)
                .is_some()
        );

        let (query, request, request_started) = node.query()?;
        let replay = node.peer_snapshot(&query, 6, grants, Some(replay_candidate))?;
        let signed = node.signer.sign_turn_resource_snapshot(&replay)?;
        assert!(matches!(
            node.accept(&query, &request, request_started, &signed, &mut local),
            Err(Error::Authorization(ContractError {
                code: ErrorCode::ReplayRejected,
                ..
            }))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn stopping_node_control_immediately_revokes_turn_authority() -> TestResult {
        let node = TestNode::new()?;
        let _local = node.install_initial_grant()?;
        let username = format!("nl:{}", test_id(6));
        assert!(
            node.authorization
                .auth_key(&username, "deployment.example")
                .is_some()
        );

        let (sender, stopped) = tokio::sync::watch::channel(false);
        let pump = tokio::spawn(std::future::pending::<Result<(), Error>>());
        let control = super::super::NodeControl {
            state: node.state.clone(),
            started: node.started,
            stopped,
            stop_signal: sender,
            turn_authorization: node.authorization.clone(),
            pump,
            _usage_pump: tokio::spawn(async { Ok(()) }),
            runtime_id: test_id(3),
        };
        control.stop();
        assert!(*control.stopped().borrow());
        assert!(
            node.authorization
                .auth_key(&username, "deployment.example")
                .is_none()
        );
        Ok(())
    }
}
