use super::*;
use nestlink_identity::{signal_transcript, verify_device_action};

/// One cursor per peer/session. Old candidates cannot replace newer network state.
pub struct SignalCursor {
    session: String,
    peer: String,
    connection: u64,
    network: u64,
    sequence: u64,
    lease: u64,
    last_digest: Option<[u8; 32]>,
}
impl SignalCursor {
    pub fn new(permit: &VerifiedPermit, installation: &DeviceIdentity) -> Result<Self, SdkError> {
        let peer = other_endpoint(permit, installation)?;
        Ok(Self {
            session: permit.claims().session_id.clone(),
            peer: peer.into(),
            connection: permit.claims().connection_generation,
            network: 0,
            sequence: 0,
            lease: 0,
            last_digest: None,
        })
    }
}
pub(super) fn other_endpoint<'a>(
    permit: &'a VerifiedPermit,
    installation: &DeviceIdentity,
) -> Result<&'a str, SdkError> {
    let claims = permit.claims();
    if installation.device_id == claims.controller_device_id
        && installation.identity.fingerprint() == claims.controller_key_sha256.as_slice()
    {
        Ok(&claims.host_device_id)
    } else if installation.device_id == claims.host_device_id
        && installation.identity.fingerprint() == claims.host_key_sha256.as_slice()
    {
        Ok(&claims.controller_device_id)
    } else {
        Err(SdkError::Trust)
    }
}
pub fn verify_peer_signal(
    permit: &VerifiedPermit,
    installation: &DeviceIdentity,
    view: SignalView,
    cursor: &mut SignalCursor,
) -> Result<Option<SignalPayload>, SdkError> {
    let peer = other_endpoint(permit, installation)?;
    let claims = permit.claims();
    if cursor.session != claims.session_id
        || cursor.peer != peer
        || cursor.connection != claims.connection_generation
        || view.submission.device_id != peer
    {
        return Err(SdkError::Trust);
    }
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(view.public_key)
        .map_err(|_| SdkError::Invalid)?
        .try_into()
        .map_err(|_| SdkError::Invalid)?;
    let expected = if peer == claims.controller_device_id {
        &claims.controller_key_sha256
    } else {
        &claims.host_key_sha256
    };
    if expected != &digest(&key) {
        return Err(SdkError::Trust);
    }
    let payload = view.submission.payload;
    let proof = signal_transcript(claims, &view.account_id, peer, &payload)?;
    let signature = URL_SAFE_NO_PAD
        .decode(view.submission.signature)
        .map_err(|_| SdkError::Invalid)?;
    verify_device_action(&proof, &key, &signature)?;
    let hash = digest(&serde_json::to_vec(&payload)?);
    if payload.network_generation < cursor.network
        || payload.sequence < cursor.sequence
        || payload.lease_sequence < cursor.lease
    {
        return Err(SdkError::Trust);
    }
    if payload.sequence == cursor.sequence {
        if cursor.last_digest != Some(hash) {
            return Err(SdkError::Trust);
        }
        return Ok(None);
    }
    cursor.network = payload.network_generation;
    cursor.sequence = payload.sequence;
    cursor.lease = payload.lease_sequence;
    cursor.last_digest = Some(hash);
    Ok(Some(payload))
}
impl Sdk {
    pub async fn publish_signal(
        &self,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        payload: SignalPayload,
    ) -> Result<(), SdkError> {
        other_endpoint(permit, installation)?;
        if permit.claims().deployment_id != self.trust.deployment_id
            || permit.claims().security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        let proof = signal_transcript(
            permit.claims(),
            &self.principal().ok_or(SdkError::SignIn)?.account_id,
            &installation.device_id,
            &payload,
        )?;
        let body = SignalSubmission {
            device_id: installation.device_id.clone(),
            payload,
            signature: URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&proof)?),
        };
        self.call::<_, serde_json::Value>(
            Method::POST,
            &format!(
                "{}/signals",
                resource("remote", &permit.claims().session_id)?
            ),
            Some(&body),
            true,
        )
        .await
        .map(|_| ())
    }
    pub async fn peer_signals(
        &self,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        cursor: &mut SignalCursor,
    ) -> Result<Vec<SignalPayload>, SdkError> {
        let peer = other_endpoint(permit, installation)?;
        if permit.claims().deployment_id != self.trust.deployment_id
            || permit.claims().security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        let response: SignalsResponse = self
            .required(
                Method::GET,
                &format!(
                    "{}/signals",
                    resource("remote", &permit.claims().session_id)?
                ),
                None::<&()>,
            )
            .await?;
        if response.signals.len() > 2 {
            return Err(SdkError::Invalid);
        }
        let mut result = Vec::new();
        for signal in response.signals {
            if signal.submission.device_id == peer {
                if let Some(payload) = verify_peer_signal(permit, installation, signal, cursor)? {
                    result.push(payload);
                }
            } else if signal.submission.device_id != installation.device_id {
                return Err(SdkError::Trust);
            }
        }
        Ok(result)
    }
}
