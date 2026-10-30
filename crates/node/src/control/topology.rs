//! Short-lived signed observations from an already authorized adjacency owner.
//! Nothing in a publication grants forwarding, prefix or business access.
use super::{Error, NodeConfig, NodeControl, NodeIdentity, sample};
use futures_util::StreamExt;
use nestlink_identity::{
    digest,
    network::{NetworkVerification, VerifiedNetworkGrant},
    network_topology::{
        VerifiedTopologyAdvertisement, VerifiedTopologyPublisher, VerifiedTopologyReport,
        verify_topology_advertisement, verify_topology_publisher, verify_topology_report,
    },
};
use nestlink_protocol::{
    ContractError, ErrorCode, NodeLeaseClaims,
    network_topology::{
        BootIncarnation, MAX_ADVERTISEMENT_BYTES, MAX_NEIGHBORS, MAX_PREFIXES, SCHEMA_VERSION,
        SignedTopologyAdvertisement, SignedTopologyPublisher, SignedTopologyReport,
        TopologyNeighbor, TopologyReport,
    },
};
use std::{collections::BTreeMap, time::Duration};

const MAX_SPACES: usize = 64;
const REPORT_TTL_MS: u64 = 1000;
const HTTP_DEADLINE_MS: u64 = 700;
const MAX_RESPONSE_BYTES: usize = MAX_ADVERTISEMENT_BYTES * 4 + 512;

/// Watermarks belong to the control runtime, rather than a reporter object or
/// a publisher credential. Never evict one and accidentally reuse a sequence.
#[derive(Default)]
pub(super) struct ReporterState {
    sequences: BTreeMap<String, u64>,
}
impl ReporterState {
    fn next(&mut self, space: &str) -> Result<u64, Error> {
        if !self.sequences.contains_key(space) && self.sequences.len() >= MAX_SPACES {
            return Err(rejected(
                ErrorCode::CapacityExceeded,
                "topology space limit reached",
            ));
        }
        let sequence = self.sequences.entry(space.into()).or_default();
        *sequence = sequence
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or_else(|| rejected(ErrorCode::CapacityExceeded, "topology sequence exhausted"))?;
        Ok(*sequence)
    }

    fn is_current(&self, report: &TopologyReport) -> bool {
        self.sequences.get(&report.space_id) == Some(&report.sequence)
    }
}

/// The caller supplies observations from its actual adjacency resource owner
/// and a current, independently authenticated space policy. This client does
/// not probe peers, infer live edges or turn publication rights into routes.
pub struct TopologyReporter {
    config: NodeConfig,
    identity: NodeIdentity,
    client: reqwest::Client,
}

struct PreparedReport {
    lease: NodeLeaseClaims,
    publisher: VerifiedTopologyPublisher,
    report: VerifiedTopologyReport,
    signed: SignedTopologyReport,
    deadline_ms: u64,
}

impl TopologyReporter {
    /// Only an authority still present in the original current resource snapshot
    /// may supply observations. A detached copy cannot renew or revive it.
    pub async fn publish_authority(
        &self, control: &NodeControl,
        authority: &nestlink_protocol::api::NetworkNodeTopologyAuthority,
        neighbors: Vec<TopologyNeighbor>,
    ) -> Result<VerifiedTopologyAdvertisement, Error> {
        let claims = nestlink_protocol::network_topology::TopologyPublisherClaims::decode_canonical(&authority.publisher.claims)?;
        control.check_network_topology_authority(authority)?;
        if neighbors.iter().any(|observation| {
            observation.local!=claims.peer || observation.local_endpoint_revision!=authority.local.revision
                || !authority.neighbors.iter().any(|neighbor| {
                    observation.remote==nestlink_protocol::network::PeerId::from_public_key(&neighbor.public_key)
                        && observation.remote_endpoint_revision==neighbor.node.revision
                })
        }) {return Err(rejected(ErrorCode::PermissionRequired,"observation differs from current delegated neighbor"));}
        let revoked = std::collections::BTreeSet::new();
        let context = NetworkVerification {
            authority_key: &authority.authority_key,
            deployment_id: &claims.scope.deployment_id,
            space_id: &claims.scope.space_id,
            policy_epoch: claims.scope.policy_epoch,
            now_ms: sample(control.started)?.unix_ms,
            revoked_grant_ids: &revoked,
        };
        let exports = authority.route_exports.iter().map(|signed| {
            nestlink_identity::network::verify_network_grant(&nestlink_identity::network::SignedNetworkGrant {
                claims:signed.claims.clone(),signature:signed.signature.clone(),
            }, &context)
        }).collect::<Result<Vec<_>,_>>()?;
        let result = self.publish_with_route_exports(control,&authority.publisher,&context,&exports,neighbors).await?;
        control.check_network_topology_authority(authority)?;
        Ok(result)
    }
    pub fn new(config: NodeConfig, identity: NodeIdentity) -> Result<Self, Error> {
        // Reuse the existing HTTPS / explicitly enabled loopback HTTP policy.
        config.validate()?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(HTTP_DEADLINE_MS))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| Error::Control)?;
        Ok(Self {
            config,
            identity,
            client,
        })
    }

    /// Publish only these caller-owned neighbor observations. Cancellation,
    /// timeout or an HTTP error is not proof the authority did not receive the
    /// report. The consumed sequence is never reused; another call safely
    /// allocates a new sequence even after an ambiguous outcome.
    pub async fn publish(
        &self,
        control: &NodeControl,
        publisher: &SignedTopologyPublisher,
        context: &NetworkVerification<'_>,
        neighbors: Vec<TopologyNeighbor>,
    ) -> Result<VerifiedTopologyAdvertisement, Error> {
        self.publish_with_route_exports(control, publisher, context, &[], neighbors)
            .await
    }

    /// RouteExport proofs are needed to authenticate a publisher credential
    /// that also carries prefix publication rights. This observation API still
    /// publishes no prefixes: reachability must come from a real prefix owner.
    pub async fn publish_with_route_exports(
        &self,
        control: &NodeControl,
        publisher: &SignedTopologyPublisher,
        context: &NetworkVerification<'_>,
        route_exports: &[VerifiedNetworkGrant],
        neighbors: Vec<TopologyNeighbor>,
    ) -> Result<VerifiedTopologyAdvertisement, Error> {
        let prepared = self.prepare(control, publisher, context, route_exports, neighbors)?;
        let url = format!(
            "{}/api/v3/network/spaces/{}/topology/reports/{}",
            self.config.control_origin, context.space_id, self.config.node_id
        );
        let remaining = prepared
            .deadline_ms
            .checked_sub(sample(control.started)?.monotonic_ms)
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                rejected(
                    ErrorCode::LeaseExpired,
                    "topology report expired before send",
                )
            })?;
        let mut stopped = control.stopped();
        if *stopped.borrow() {
            return Err(Error::Control);
        }
        let response = tokio::select! {
            biased;
            _ = stopped.changed() => return Err(Error::Control),
            result = tokio::time::timeout(
                Duration::from_millis(remaining.min(HTTP_DEADLINE_MS)),
                self.send(&url, &prepared.signed),
            ) => result.map_err(|_| Error::Control)??,
        };
        self.accept(control, context, &prepared, &response)
    }

    fn prepare(
        &self,
        control: &NodeControl,
        signed_publisher: &SignedTopologyPublisher,
        context: &NetworkVerification<'_>,
        route_exports: &[VerifiedNetworkGrant],
        mut neighbors: Vec<TopologyNeighbor>,
    ) -> Result<PreparedReport, Error> {
        if neighbors.len() > MAX_NEIGHBORS || route_exports.len() > MAX_PREFIXES {
            return Err(rejected(
                ErrorCode::CapacityExceeded,
                "topology publication exceeded its budget",
            ));
        }
        let mut state = control.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *control.stopped.borrow() {
            return Err(Error::Control);
        }
        let now = sample(control.started)?;
        let lease = state.gate.current(now)?.clone();
        if lease.deployment_id != self.config.deployment_id
            || lease.deployment_id != context.deployment_id
            || lease.node_id != self.config.node_id
            || lease.runtime_id != control.runtime_id
            || lease.node_key_sha256.as_slice() != digest(&self.identity.public_key()).as_slice()
            || state.gate.trusted_policy_issuer() != self.config.issuer()?
        {
            return Err(rejected(
                ErrorCode::IdentityMismatch,
                "topology reporter differs from current node",
            ));
        }
        let incarnation = incarnation(&lease);
        let current = at(context, now.unix_ms);
        let publisher = verify_topology_publisher(
            signed_publisher,
            &current,
            &lease.node_id,
            &self.identity.public_key(),
            &incarnation,
            route_exports,
        )?;
        neighbors.sort_by_key(|neighbor| neighbor.remote);
        for neighbor in &neighbors {
            neighbor.validate()?;
            if neighbor.local != publisher.claims().peer
                || publisher
                    .claims()
                    .allowed_neighbors
                    .binary_search(&neighbor.remote)
                    .is_err()
            {
                return Err(rejected(
                    ErrorCode::PermissionRequired,
                    "topology neighbor is not authorized",
                ));
            }
        }
        if neighbors
            .windows(2)
            .any(|pair| pair[0].remote == pair[1].remote)
        {
            return Err(rejected(
                ErrorCode::InvalidMessage,
                "duplicate topology neighbor",
            ));
        }
        let expires_at_ms = now
            .unix_ms
            .checked_add(REPORT_TTL_MS)
            .ok_or(Error::Control)?
            .min(publisher.claims().scope.expires_at_ms)
            .min(lease.expires_at_unix_ms);
        let remaining = expires_at_ms
            .checked_sub(now.unix_ms)
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                rejected(
                    ErrorCode::LeaseExpired,
                    "topology report has no remaining lifetime",
                )
            })?;
        let deadline_ms = now
            .monotonic_ms
            .checked_add(remaining)
            .ok_or(Error::Control)?
            .min(state.gate.deadline_ms());
        let sequence = state.topology.next(context.space_id)?;
        let report = TopologyReport {
            schema_version: SCHEMA_VERSION,
            deployment_id: lease.deployment_id.clone(),
            space_id: context.space_id.into(),
            policy_epoch: context.policy_epoch,
            node_id: lease.node_id.clone(),
            peer: publisher.claims().peer,
            publisher_digest: publisher.digest(),
            incarnation: incarnation.clone(),
            sequence,
            not_before_ms: now.unix_ms,
            expires_at_ms,
            neighbors,
            prefixes: Vec::new(),
        };
        let signed = self.identity.sign_topology_report(&report)?;
        let report =
            verify_topology_report(&signed, &publisher, &current, &incarnation, sequence - 1)?;
        Ok(PreparedReport {
            lease,
            publisher,
            report,
            signed,
            deadline_ms,
        })
    }

    async fn send(
        &self,
        url: &str,
        report: &SignedTopologyReport,
    ) -> Result<SignedTopologyAdvertisement, Error> {
        let response = self
            .client
            .post(url)
            .json(report)
            .send()
            .await
            .map_err(|_| Error::Control)?;
        if !response.status().is_success() {
            return Err(Error::Control);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(rejected(
                ErrorCode::CapacityExceeded,
                "topology response exceeded its budget",
            ));
        }
        let mut chunks = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|_| Error::Control)?;
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > MAX_RESPONSE_BYTES)
            {
                return Err(rejected(
                    ErrorCode::CapacityExceeded,
                    "topology response exceeded its budget",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| rejected(ErrorCode::InvalidMessage, "malformed topology response"))
    }

    fn accept(
        &self,
        control: &NodeControl,
        context: &NetworkVerification<'_>,
        prepared: &PreparedReport,
        signed: &SignedTopologyAdvertisement,
    ) -> Result<VerifiedTopologyAdvertisement, Error> {
        let current = at(context, sample(control.started)?.unix_ms);
        let expected = prepared.report.claims();
        let advertisement = verify_topology_advertisement(
            signed,
            &prepared.publisher,
            &current,
            &incarnation(&prepared.lease),
            expected.sequence - 1,
        )?;
        let claims = advertisement.claims();
        if claims.report.canonical_bytes()? != prepared.signed.claims
            || claims.report_signature != prepared.signed.signature
            || claims.report_digest != prepared.report.digest()
            || claims.report.sequence != expected.sequence
            || claims.report.expires_at_ms != expected.expires_at_ms
        {
            return Err(rejected(
                ErrorCode::IdentityMismatch,
                "topology response acknowledges another report",
            ));
        }
        let mut state = control.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *control.stopped.borrow() {
            return Err(Error::Control);
        }
        let now = sample(control.started)?;
        let lease = state.gate.current(now)?;
        if lease.deployment_id != prepared.lease.deployment_id
            || lease.node_id != prepared.lease.node_id
            || lease.node_key_sha256 != prepared.lease.node_key_sha256
            || lease.runtime_id != prepared.lease.runtime_id
            || lease.runtime_id != control.runtime_id
            || lease.runtime_generation != prepared.lease.runtime_generation
            || lease.security_epoch != prepared.lease.security_epoch
            || lease.policy_revision != prepared.lease.policy_revision
            || lease.lease_sequence < prepared.lease.lease_sequence
        {
            return Err(rejected(
                ErrorCode::IdentityMismatch,
                "node changed while topology report was in flight",
            ));
        }
        // A renewed lease cannot move either original expiration anchor. A
        // shorter new lease also cannot be expanded by an earlier response.
        if now.monotonic_ms >= prepared.deadline_ms
            || now.unix_ms >= expected.expires_at_ms
            || claims.expires_at_ms > lease.expires_at_unix_ms
        {
            return Err(rejected(
                ErrorCode::LeaseExpired,
                "topology response outlived its original lease",
            ));
        }
        advertisement.check_current(&at(context, now.unix_ms))?;
        if !state.topology.is_current(expected) {
            // Concurrent higher-sequence publication supersedes an earlier
            // response, even if that earlier response is correctly signed.
            return Err(rejected(
                ErrorCode::ReplayRejected,
                "topology response was superseded",
            ));
        }
        Ok(advertisement)
    }
}

fn incarnation(lease: &NodeLeaseClaims) -> BootIncarnation {
    BootIncarnation {
        runtime_generation: lease.runtime_generation,
        runtime_id: lease.runtime_id.clone(),
    }
}

fn at<'a>(context: &NetworkVerification<'a>, now_ms: u64) -> NetworkVerification<'a> {
    NetworkVerification {
        authority_key: context.authority_key,
        deployment_id: context.deployment_id,
        space_id: context.space_id,
        policy_epoch: context.policy_epoch,
        // Do not lower a later time already observed by trusted policy merely
        // because this process's wall clock is behind that observation.
        now_ms: now_ms.max(context.now_ms),
        revoked_grant_ids: context.revoked_grant_ids,
    }
}

fn rejected(code: ErrorCode, message: &'static str) -> Error {
    Error::Authorization(ContractError::new(code, message))
}

#[cfg(test)]
mod tests;
