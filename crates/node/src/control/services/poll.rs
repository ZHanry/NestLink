use super::super::{NodeConfig, Runtime};
use super::*;
use futures_util::StreamExt;
use nestlink_identity::{nodes::NodeIdentity, service_plane::verify_service_snapshot};
use nestlink_protocol::{
    NODE_RESOURCE_TTL_MS, NodeResourceQueryClaims, SCHEMA_VERSION,
    service_plane::{publication::SERVICE_POLL_MS, *},
};
use std::sync::{Arc, Mutex};

pub(in crate::control) async fn poll(
    config: NodeConfig,
    identity: Arc<NodeIdentity>,
    state: Arc<Mutex<Runtime>>,
    started: Instant,
) -> Result<(), Error> {
    if !config.roles.contains(&(NodeRole::NodeEdge as i32)) {
        return std::future::pending().await;
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(700))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| Error::Control)?;
    let url = format!(
        "{}/api/v3/nodes/{}/service-resources",
        config.control_origin, config.node_id
    );
    let issuer = config.issuer()?;
    let mut sequence = 0u64;
    let mut accepted = false;
    let mut tick = tokio::time::interval(Duration::from_millis(SERVICE_POLL_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let shutdown_requested = state.lock().map_err(|_| Error::Control)?.service_shutdown;
        if shutdown_requested {
            return std::future::pending().await;
        }
        let (query, requested) = {
            let mut runtime = state.lock().map_err(|_| Error::Control)?;
            if runtime.service_shutdown {
                continue;
            }
            if !runtime.ready {
                continue;
            }
            let requested = Instant::now();
            let now = sample(started)?;
            let lease = runtime.gate.current(now)?.clone();
            if !lease.public_ingress_allowed || !lease.server_forwarding_allowed {
                if accepted {
                    runtime.resources.services.stop();
                    return Err(Error::Control);
                }
                continue;
            }
            sequence = sequence
                .checked_add(1)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(Error::Control)?;
            (NodeResourceQueryClaims {
                schema_version: SCHEMA_VERSION,
                deployment_id: lease.deployment_id,
                security_epoch: lease.security_epoch,
                node_id: lease.node_id,
                runtime_id: lease.runtime_id,
                runtime_generation: lease.runtime_generation,
                policy_revision: lease.policy_revision,
                lease_sequence: lease.lease_sequence,
                request_id: uuid::Uuid::new_v4().to_string(),
                request_sequence: sequence,
                issued_at_unix_ms: now.unix_ms,
                expires_at_unix_ms: now
                    .unix_ms
                    .checked_add(SERVICE_RESOURCE_MS.min(NODE_RESOURCE_TTL_MS))
                    .ok_or(Error::Control)?
                    .min(lease.expires_at_unix_ms),
            }, requested)
        };
        let signed = identity.sign_service_query(&query)?;
        let signed_at = Instant::now();
        let mut received_at = None;
        let mut verified_at = None;
        // Preserve the original pre-sign/query monotonic anchor. Signing and
        // sending cannot shift the original signed query's finite lifetime.
        let response = tokio::time::timeout(Duration::from_millis(700), async {
            let response = client
                .post(&url)
                .json(&signed)
                .send()
                .await
                .map_err(|_| Error::Transport)?;
            if !response.status().is_success() {
                return Err(Error::ServiceResourceStatus(response.status().as_u16()));
            }
            let mut chunks = response.bytes_stream();
            let mut bytes = Vec::new();
            // Vec<u8> signatures/claims expand in the outer JSON wrapper.
            let maximum = SERVICE_SNAPSHOT_BYTES
                .checked_mul(6)
                .ok_or(Error::Control)?;
            while let Some(chunk) = chunks.next().await {
                let chunk = chunk.map_err(|_| Error::Transport)?;
                if bytes
                    .len()
                    .checked_add(chunk.len())
                    .is_none_or(|n| n > maximum)
                {
                    return Err(Error::Control);
                }
                bytes.extend_from_slice(&chunk);
            }
            received_at = Some(Instant::now());
            let envelope: nestlink_protocol::service_plane::publication::ServiceResourceGrant =
                serde_json::from_slice(&bytes)
                    .map_err(|_| phase("service snapshot JSON", Error::Control))?;
            let snapshot = verify_service_snapshot(
                &envelope.snapshot,
                &issuer,
                &signed,
                &identity.public_key(),
            )?;
            verified_at = Some(Instant::now());
            Ok::<_, Error>((snapshot, envelope.issuer))
        })
        .await;
        let waiting_at = Instant::now();
        let mut runtime = state.lock().map_err(|_| Error::Control)?;
        runtime.resources.services.observe_response(requested);
        runtime.resources.services.observe_poll_stages(
            signed_at.saturating_duration_since(requested),
            received_at.unwrap_or(waiting_at).saturating_duration_since(signed_at),
            verified_at.unwrap_or(waiting_at).saturating_duration_since(received_at.unwrap_or(waiting_at)),
            waiting_at.elapsed(),
        );
        if runtime.service_shutdown {
            continue;
        }
        if runtime.service_resource_owner != Some(runtime.resources.services.owner_token()) {
            runtime.resources.services.stop();
            return Err(Error::Control);
        }
        match response {
            Ok(Err(Error::Transport | Error::ServiceResourceStatus(429 | 500..=599))) | Err(_) => {
                // An unavailable transport supplies no new authority. Keep the
                // last signed snapshot's original query/signed monotonic cap;
                // publication admission independently enforces that deadline.
                // Expired IDs are retired before a later snapshot can arrive,
                // so a transient retry cannot revive an expired publication.
                runtime.resources.services.observe_unavailable(Instant::now());
                continue;
            }
            Ok(Ok((snapshot, issuer_delegation))) => {
                let node_deadline = match inspect_snapshot(&mut runtime.gate, &snapshot, started) {
                    Ok(end) => end,
                    Err(error) => {
                        // A concurrent node renewal can supersede the exact query;
                        // discard it without installing its authority. Existing
                        // owners retain only their original query/signed cap.
                        let current = runtime.gate.current(sample(started)?)?;
                        if snapshot.claims().query.lease_sequence < current.lease_sequence {
                            runtime.resources.services.observe_superseded();
                            continue;
                        }
                        if accepted {
                            runtime.resources.services.stop();
                            return Err(error);
                        }
                        continue;
                    }
                };
                let installation_started = Instant::now();
                let installation =
                    runtime
                        .resources
                        .services
                        .accept_checked(snapshot, node_deadline, requested);
                runtime.resources.services.observe_installation(installation_started);
                if let Err(error) = installation {
                    runtime.resources.services.stop();
                    return Err(phase("service snapshot installation", service_error(error)));
                }
                if let Err(error) = runtime
                    .resources
                    .services
                    .set_issuer_delegation(issuer_delegation)
                {
                    runtime.resources.services.stop();
                    return Err(phase(
                        "service issuer delegation installation",
                        service_error(error),
                    ));
                }
                accepted = true;
            }
            failure => {
                // Before the first snapshot there is no service authority to
                // revoke (including a server's initial restart fence).
                if accepted {
                    runtime.resources.services.stop();
                    return Err(match failure {
                        Ok(Err(error)) => phase("service snapshot response", error),
                        Err(_) => phase("service snapshot deadline", Error::Control),
                        Ok(Ok(_)) => unreachable!(),
                    });
                }
            }
        }
    }
}
fn phase(stage: &'static str, cause: Error) -> Error {
    Error::Phase {
        stage,
        cause: Box::new(cause),
    }
}
fn service_error(error: crate::service_plane::Error) -> Error {
    match error {
        crate::service_plane::Error::Authorization(error) => Error::Authorization(error),
        crate::service_plane::Error::Node(error) => error,
        _ => Error::Control,
    }
}
