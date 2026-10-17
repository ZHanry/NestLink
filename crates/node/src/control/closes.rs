//! Bounded terminal-fact retries continue briefly after forwarding authority stops.
use super::*;
use nestlink_identity::node_closes::verify_relay_close_ack;
use nestlink_protocol::{
    NODE_RELAY_CLOSE_DRAIN_MS, RELAY_CLOSE_MESSAGE_BYTES, RelayCloseClaims, SignedRelayClose,
    SignedRelayCloseAck,
};

pub(super) struct PendingClose {
    pub claims: RelayCloseClaims,
    pub signed: Option<SignedRelayClose>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseReportStatus {
    pub active_allocations: usize,
    pub pending_receipts: usize,
    pub acknowledged_receipts: u64,
}
impl NodeControl {
    /// Local queue facts only; acknowledgement means control recorded a signed
    /// retirement, not that application data arrived at the other endpoint.
    pub fn close_report_status(&self) -> Result<CloseReportStatus, Error> {
        let state = self.state.lock().map_err(|_| Error::Control)?;
        Ok(CloseReportStatus {
            active_allocations: state.resources.active_pairs(),
            pending_receipts: state.resources.pending_closes.len(),
            acknowledged_receipts: state.resources.acknowledged_closes,
        })
    }
}

pub(super) async fn reporter(
    config: NodeConfig,
    identity: Arc<NodeIdentity>,
    state: Arc<Mutex<Runtime>>,
    started: Instant,
    mut stopped: watch::Receiver<bool>,
) -> Result<(), Error> {
    let issuer = config.issuer()?;
    let url = format!(
        "{}/api/v3/nodes/{}/close",
        config.control_origin, config.node_id
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(700))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| Error::Control)?;
    let mut drain_deadline = None;
    loop {
        if (*stopped.borrow() || stopped.has_changed().is_err()) && drain_deadline.is_none() {
            drain_deadline =
                Some(Instant::now() + Duration::from_millis(NODE_RELAY_CLOSE_DRAIN_MS));
        }
        if drain_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Ok(()); // Unacknowledged promises retain their original expiry.
        }
        let signed = {
            let mut runtime = state.lock().map_err(|_| Error::Control)?;
            let resources = &mut runtime.resources;
            if drain_deadline.is_some()
                && resources.active_pairs() == 0
                && resources.pending_closes.is_empty()
            {
                return Ok(());
            }
            if let Some(pending) = resources.pending_closes.front_mut() {
                if pending.signed.is_none() {
                    pending.signed = Some(identity.sign_relay_close(&pending.claims)?);
                }
                pending.signed.clone()
            } else {
                None
            }
        };
        if let Some(signed) = signed {
            let timeout = drain_deadline
                .map(|deadline| deadline.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_millis(700))
                .min(Duration::from_millis(700));
            let accepted =
                tokio::time::timeout(timeout, send(&client, &url, &issuer, &signed, started))
                    .await
                    .is_ok_and(|result| result.is_ok());
            {
                let mut runtime = state.lock().map_err(|_| Error::Control)?;
                let resources = &mut runtime.resources;
                if resources
                    .pending_closes
                    .front()
                    .is_some_and(|pending| pending.signed.as_ref() == Some(&signed))
                {
                    let pending = resources.pending_closes.pop_front().ok_or(Error::Control)?;
                    if accepted {
                        resources.acknowledged_closes = resources
                            .acknowledged_closes
                            .checked_add(1)
                            .ok_or(Error::Control)?;
                    } else {
                        resources.pending_closes.push_back(pending);
                    }
                } else {
                    return Err(Error::Control);
                }
            }
            if accepted {
                tokio::task::yield_now().await;
                continue;
            }
        }
        // No mutex/watch borrow crosses an await. Rotate failed exact payloads
        // so one lost ACK cannot starve other completed allocations.
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {},
            _ = stopped.changed(), if drain_deadline.is_none() => {},
        }
    }
}

async fn send(
    client: &reqwest::Client,
    url: &str,
    issuer: &[u8; 32],
    signed: &SignedRelayClose,
    started: Instant,
) -> Result<(), Error> {
    let response = client
        .post(url)
        .json(signed)
        .send()
        .await
        .map_err(|_| Error::Control)?;
    if !response.status().is_success() {
        return Err(Error::Control);
    }
    let mut chunks = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|_| Error::Control)?;
        if bytes.len() + chunk.len() > (RELAY_CLOSE_MESSAGE_BYTES * 4 + 512) as usize {
            return Err(Error::Control);
        }
        bytes.extend_from_slice(&chunk);
    }
    let response: SignedRelayCloseAck =
        serde_json::from_slice(&bytes).map_err(|_| Error::Control)?;
    let ack = verify_relay_close_ack(&response, issuer, signed)?;
    if ack.accepted_at_unix_ms > sample(started)?.unix_ms.saturating_add(1000) {
        return Err(Error::Control);
    }
    Ok(())
}
