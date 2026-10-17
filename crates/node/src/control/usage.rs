use super::{Error, NodeConfig};
use crate::service_usage::{GrantSnapshot, ServiceUsageStore};
use futures_util::StreamExt;
use nestlink_identity::{
    digest,
    nodes::{NodeIdentity, verify_service_usage_ack},
};
use nestlink_protocol::{
    SCHEMA_VERSION,
    service_plane::{
        SERVICE_USAGE_BYTES, ServiceUsageReportAckClaims, ServiceUsageReportClaims,
        SignedServiceUsageReport, SignedServiceUsageReportAck,
    },
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::watch, time::MissedTickBehavior};

const REPORT_PERIOD: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_millis(900);
const STOP_REPORT_BUDGET: Duration = Duration::from_secs(5);

/// Persist each exact signed report before sending it, then retry that frozen
/// object until the trusted policy issuer acknowledges the same digest.
pub(super) async fn reporter(
    config: NodeConfig,
    identity: Arc<NodeIdentity>,
    runtime_id: String,
    store: Arc<ServiceUsageStore>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Error> {
    if !config
        .roles
        .contains(&(nestlink_protocol::NodeRole::NodeEdge as i32))
    {
        return Ok(());
    }
    let work = report_loop(config, identity, runtime_id, store, shutdown.clone());
    tokio::pin!(work);
    let stopping = async {
        loop {
            if *shutdown.borrow() || shutdown.changed().await.is_err() {
                return;
            }
        }
    };
    tokio::pin!(stopping);
    tokio::select! {
        result = &mut work => result,
        _ = &mut stopping => {
            // Dropping the timed-out worker retains its exact pending report
            // and seal in SQLite; it never releases an unknown commitment.
            match tokio::time::timeout(STOP_REPORT_BUDGET, &mut work).await {
                Ok(result) => result,
                Err(_) => Ok(()),
            }
        }
    }
}

async fn report_loop(
    config: NodeConfig,
    identity: Arc<NodeIdentity>,
    runtime_id: String,
    store: Arc<ServiceUsageStore>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), Error> {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| Error::Control)?;
    let url = format!(
        "{}/api/v3/nodes/{}/service-usage",
        config.control_origin, config.node_id
    );
    let issuer = config.issuer()?;
    let mut tick = tokio::time::interval(REPORT_PERIOD);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let snapshots = store.snapshots(&runtime_id)?;
        let shutdown_requested = *shutdown.borrow();
        let finished_unsealed_reports = shutdown_requested
            && snapshots.iter().all(|snapshot| {
                !snapshot.drain_confirmed
                    && !snapshot.needs_report
                    && snapshot.pending_report.is_none()
                    && snapshot.pending_stop.is_none()
            });
        for snapshot in snapshots {
            if snapshot.pending_report.is_some() || snapshot.needs_report {
                let report = if let Some(pending) = snapshot.pending_report.clone() {
                    pending
                } else {
                    let signed = build_report(&identity, &config, &snapshot)?;
                    // This transaction fixes the bytes and sequence across restarts.
                    store.queue_report(&signed)?;
                    signed
                };
                // Transient failures retry the same persisted signed report.
                if let Some((ack, ack_json)) =
                    post_report(&client, &url, &issuer, &report, &snapshot).await?
                {
                    store.acknowledge_report(&ack, &ack_json)?;
                }
                // Re-read persisted highwaters next tick. A stop statement must
                // name the final acknowledged report digest, including a report
                // created above for the final flow counters.
                continue;
            }
            if let Some(pending) = snapshot.pending_stop.clone() {
                if post_stop(&client, &url, &pending).await? {
                    store.complete_stop(&snapshot.claims.grant_id, &digest(&pending.claims))?;
                }
            } else if snapshot.drain_confirmed {
                let signed = build_stop(&identity, &config, &snapshot)?;
                store.queue_stop(&signed)?;
                if post_stop(&client, &url, &signed).await? {
                    store.complete_stop(&snapshot.claims.grant_id, &digest(&signed.claims))?;
                }
            }
        }
        if finished_unsealed_reports {
            return Ok(());
        }
    }
}

fn build_stop(
    identity: &NodeIdentity,
    config: &NodeConfig,
    snapshot: &GrantSnapshot,
) -> Result<nestlink_protocol::service_plane::SignedServiceUsageRuntimeStop, Error> {
    let grant = &snapshot.claims;
    let stopped_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Control)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Control)?;
    let mut stop_nonce = [0; 32];
    stop_nonce[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    stop_nonce[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    let claims = nestlink_protocol::service_plane::ServiceUsageRuntimeStopClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: grant.deployment_id.clone(),
        security_epoch: grant.security_epoch,
        policy_revision: grant.policy_revision,
        node_id: config.node_id.clone(),
        node_runtime_id: grant.edge_runtime_id.clone(),
        node_runtime_generation: grant.edge_runtime_generation,
        grant_id: grant.grant_id.clone(),
        grant_sha256: snapshot.grant_sha256,
        publication_id: grant.publication_id.clone(),
        publication_generation: grant.publication_generation,
        final_report_sequence: snapshot.report_sequence,
        final_report_sha256: snapshot.report_sha256,
        admitted_bytes: snapshot.highwater.admitted_bytes,
        opened_connections: snapshot.highwater.opened_connections,
        closed_connections: snapshot.highwater.closed_connections,
        stop_nonce,
        stopped_at_unix_ms,
    };
    Ok(identity.sign_service_usage_stop(&claims)?)
}

fn build_report(
    identity: &NodeIdentity,
    config: &NodeConfig,
    snapshot: &GrantSnapshot,
) -> Result<SignedServiceUsageReport, Error> {
    let grant = &snapshot.claims;
    let report_sequence = snapshot
        .report_sequence
        .checked_add(1)
        .filter(|sequence| *sequence <= i64::MAX as u64)
        .ok_or(Error::Control)?;
    let sampled_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Control)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Control)?;
    let claims = ServiceUsageReportClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: grant.deployment_id.clone(),
        security_epoch: grant.security_epoch,
        policy_revision: grant.policy_revision,
        node_id: config.node_id.clone(),
        node_runtime_id: grant.edge_runtime_id.clone(),
        node_runtime_generation: grant.edge_runtime_generation,
        grant_id: grant.grant_id.clone(),
        grant_sha256: snapshot.grant_sha256,
        publication_id: grant.publication_id.clone(),
        publication_generation: grant.publication_generation,
        account_id: grant.account_id.clone(),
        host_device_id: grant.host_device_id.clone(),
        service_id: grant.service_id.clone(),
        report_sequence,
        admitted_bytes: snapshot.highwater.admitted_bytes,
        opened_connections: snapshot.highwater.opened_connections,
        closed_connections: snapshot.highwater.closed_connections,
        sampled_at_unix_ms,
    };
    Ok(identity.sign_service_usage(&claims)?)
}

async fn post_report(
    client: &reqwest::Client,
    url: &str,
    issuer: &[u8; 32],
    report: &SignedServiceUsageReport,
    snapshot: &GrantSnapshot,
) -> Result<Option<(ServiceUsageReportAckClaims, String)>, Error> {
    let response =
        match tokio::time::timeout(REQUEST_TIMEOUT, client.post(url).json(report).send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => return Ok(None),
        };
    let status = response.status();
    if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(Error::Control);
    }

    let mut chunks = response.bytes_stream();
    let maximum = SERVICE_USAGE_BYTES.checked_mul(6).ok_or(Error::Control)?;
    let mut body = Vec::new();
    while let Some(chunk) = chunks.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) => return Ok(None),
        };
        if body
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > maximum)
        {
            return Err(Error::Control);
        }
        body.extend_from_slice(&chunk);
    }
    let signed_ack: SignedServiceUsageReportAck =
        serde_json::from_slice(&body).map_err(|_| Error::Control)?;
    let ack = verify_service_usage_ack(&signed_ack, issuer)?;
    let report_hash = digest(&report.claims);
    if ack.deployment_id != snapshot.claims.deployment_id
        || ack.security_epoch != snapshot.claims.security_epoch
        || ack.node_id != snapshot.claims.edge_node_id
        || ack.node_runtime_id != snapshot.claims.edge_runtime_id
        || ack.node_runtime_generation != snapshot.claims.edge_runtime_generation
        || ack.grant_id != snapshot.claims.grant_id
        || ack.report_sequence
            != snapshot
                .report_sequence
                .checked_add(1)
                .ok_or(Error::Control)?
        || ack.report_sha256 != report_hash
    {
        return Err(Error::Control);
    }
    let ack_json = serde_json::to_string(&signed_ack).map_err(|_| Error::Control)?;
    Ok(Some((ack, ack_json)))
}

async fn post_stop(
    client: &reqwest::Client,
    report_url: &str,
    stop: &nestlink_protocol::service_plane::SignedServiceUsageRuntimeStop,
) -> Result<bool, Error> {
    let url = report_url.trim_end_matches("service-usage").to_owned() + "service-usage-stop";
    let response =
        match tokio::time::timeout(REQUEST_TIMEOUT, client.post(url).json(stop).send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => return Ok(false),
        };
    let status = response.status();
    if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Ok(false);
    }
    if status == reqwest::StatusCode::NO_CONTENT {
        Ok(true)
    } else {
        Err(Error::Control)
    }
}

#[cfg(test)]
mod tests;
