//! Reconnect proofs travel over the independent management plane, with one original deadline.
use super::*;
use nestlink_identity::{reconnection, verify_device_action};
use nestlink_protocol::RECONNECTION_BYTES;
use std::future::Future;
#[cfg(not(target_arch = "wasm32"))]
type Started = std::time::Instant;
#[cfg(target_arch = "wasm32")]
type Started = f64;
#[cfg(not(target_arch = "wasm32"))]
fn time() -> Result<(Started, u64), SdkError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SdkError::Trust)?
        .as_millis();
    Ok((Started::now(), now.try_into().map_err(|_| SdkError::Trust)?))
}
#[cfg(target_arch = "wasm32")]
fn time() -> Result<(Started, u64), SdkError> {
    let monotonic = web_sys::window()
        .and_then(|w| w.performance())
        .ok_or(SdkError::BrowserTransport)?
        .now();
    let unix = js_sys::Date::now();
    if !monotonic.is_finite() || !unix.is_finite() || unix < 0.0 {
        return Err(SdkError::Trust);
    }
    Ok((monotonic, unix as u64))
}
pub struct ReconnectionAttempt {
    previous: VerifiedPermit,
    offer: ReconnectionOffer,
    issuer: [u8; 32],
    login_session: String,
    started: Started,
    budget_ms: u64,
    unix_at_start: u64,
}
/// The successor and its original request budget travel together through native rebuilding.
pub struct ReconnectedPermit {
    permit: VerifiedPermit,
    context: ReconnectionAttempt,
}
impl ReconnectedPermit {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn bounded<T>(
        &self,
        future: impl Future<Output = Result<T, SdkError>>,
    ) -> impl Future<Output = Result<T, SdkError>> {
        self.context.bounded(future)
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn allocation_id(&self, node: &str) -> Result<String, SdkError> {
        if !valid_id(node) {
            return Err(SdkError::Invalid);
        }
        let mut bytes = b"NestLink/v15/reconnection-allocation/v1\0".to_vec();
        bytes.extend_from_slice(&self.context.previous.digest());
        bytes.extend_from_slice(
            &URL_SAFE_NO_PAD
                .decode(&self.context.offer.choice.nonce)
                .map_err(|_| SdkError::Invalid)?,
        );
        bytes.extend_from_slice(node.as_bytes());
        let hash = digest(&bytes);
        let mut id: [u8; 16] = hash[..16].try_into().map_err(|_| SdkError::Invalid)?;
        id[6] = (id[6] & 0x0f) | 0x80;
        id[8] = (id[8] & 0x3f) | 0x80;
        Ok(uuid::Uuid::from_bytes(id).hyphenated().to_string())
    }
    pub fn permit(&self) -> &VerifiedPermit {
        &self.permit
    }
    pub fn choice(&self) -> &ReconnectionChoice {
        self.context.choice()
    }
    /// Native and browser consumers use the same original monotonic request budget.
    pub fn remaining_ms(&self) -> Result<u64, SdkError> {
        self.context.remaining()
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub fn runtime_clock(&self) -> Result<nestlink_remote::RuntimeClock, SdkError> {
        self.remaining_ms()?;
        nestlink_remote::RuntimeClock::from_request_start(self.context.started)
            .map_err(|_| SdkError::Trust)
    }
}
#[cfg(not(target_arch = "wasm32"))]
pub struct NativeReconnectionConfig<'a> {
    pub bound: std::net::SocketAddr,
    pub stun_servers: Vec<std::net::SocketAddr>,
    pub address_policy: crate::native::AddressPolicy,
    pub monitor: Option<&'a nestlink_platform_network::NetworkMonitor>,
}
impl ReconnectionAttempt {
    #[cfg(not(target_arch = "wasm32"))]
    fn cap_deadline(&mut self, deadline: Started) -> Result<(), SdkError> {
        let budget: u64 = deadline
            .checked_duration_since(self.started)
            .ok_or(SdkError::Timeout)?
            .as_millis()
            .try_into()
            .map_err(|_| SdkError::Timeout)?;
        self.budget_ms = self.budget_ms.min(budget);
        self.remaining()?;
        Ok(())
    }
    pub fn choice(&self) -> &ReconnectionChoice {
        &self.offer.choice
    }
    fn remaining(&self) -> Result<u64, SdkError> {
        let unix = time()?.1;
        if unix < self.unix_at_start {
            return Err(SdkError::Trust);
        }
        if unix >= self.previous.claims().expires_at_unix_ms
            || self
                .offer
                .choice
                .network_recovery
                .as_ref()
                .is_some_and(|recovery| unix >= recovery.expires_at_unix_ms)
        {
            return Err(SdkError::Timeout);
        }
        #[cfg(not(target_arch = "wasm32"))]
        let elapsed = self.started.elapsed().as_millis();
        #[cfg(target_arch = "wasm32")]
        let elapsed = {
            let now = time()?.0;
            if now < self.started {
                return Err(SdkError::Trust);
            }
            (now - self.started).ceil() as u128
        };
        let elapsed: u64 = elapsed.try_into().map_err(|_| SdkError::Timeout)?;
        self.budget_ms
            .checked_sub(elapsed)
            .filter(|v| *v > 0)
            .ok_or(SdkError::Timeout)
    }
    fn check(&self, sdk: &Sdk) -> Result<(), SdkError> {
        let p = sdk.principal().ok_or(SdkError::SignIn)?;
        if p.session_id != self.login_session
            || sdk.trust.permit_issuer != self.issuer
            || self.previous.issuer() != self.issuer
            || self.previous.claims().deployment_id != sdk.trust.deployment_id
            || self.previous.claims().security_epoch != sdk.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        self.remaining()?;
        Ok(())
    }
    fn bounded<T>(
        &self,
        future: impl Future<Output = Result<T, SdkError>>,
    ) -> impl Future<Output = Result<T, SdkError>> {
        let future = Box::pin(future);
        async move {
            let remaining = self.remaining()?;
            #[cfg(not(target_arch = "wasm32"))]
            {
                tokio::time::timeout(Duration::from_millis(remaining), future)
                    .await
                    .map_err(|_| SdkError::Timeout)?
            }
            #[cfg(target_arch = "wasm32")]
            {
                use futures_util::future::{Either, select};
                match select(
                    Box::pin(future),
                    Box::pin(gloo_timers::future::TimeoutFuture::new(
                        remaining.min(u32::MAX as u64) as u32,
                    )),
                )
                .await
                {
                    Either::Left((result, _)) => result,
                    Either::Right(_) => Err(SdkError::Timeout),
                }
            }
        }
    }
    async fn pause(&self) -> Result<(), SdkError> {
        let delay = self.remaining()?.min(100);
        #[cfg(not(target_arch = "wasm32"))]
        tokio::time::sleep(Duration::from_millis(delay)).await;
        #[cfg(target_arch = "wasm32")]
        gloo_timers::future::TimeoutFuture::new(delay as u32).await;
        self.remaining()?;
        Ok(())
    }
    fn submission(&self, host_signature: String) -> ReconnectionSubmission {
        ReconnectionSubmission {
            choice: self.offer.choice.clone(),
            controller_signature: self.offer.controller_signature.clone(),
            host_signature,
        }
    }
}
fn peer_proof(
    permit: &VerifiedPermit,
    key: &[u8; 32],
    host: bool,
    choice: &ReconnectionChoice,
    signature: &str,
) -> Result<(), SdkError> {
    let c = permit.claims();
    let (id, expected) = if host {
        (&c.host_device_id, &c.host_key_sha256)
    } else {
        (&c.controller_device_id, &c.controller_key_sha256)
    };
    if digest(key).as_slice() != expected {
        return Err(SdkError::Trust);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| SdkError::Invalid)?;
    verify_device_action(&reconnection::transcript(c, id, choice)?, key, &signature)?;
    Ok(())
}
fn retryable(error: &SdkError) -> bool {
    matches!(
        error,
        SdkError::Transport(_) | SdkError::BrowserTransport | SdkError::Timeout
    )
}
impl Sdk {
    fn reconnection_identity(
        &self,
        local: &DeviceIdentity,
        previous: &VerifiedPermit,
        host: bool,
    ) -> Result<(), SdkError> {
        let c = previous.claims();
        let p = self.principal().ok_or(SdkError::SignIn)?;
        let unix = time()?.1;
        if unix < c.issued_at_unix_ms || unix >= c.expires_at_unix_ms {
            return Err(SdkError::Trust);
        }
        let (id, key) = if host {
            (&c.host_device_id, &c.host_key_sha256)
        } else {
            (&c.controller_device_id, &c.controller_key_sha256)
        };
        if previous.issuer() != self.trust.permit_issuer
            || c.deployment_id != self.trust.deployment_id
            || c.security_epoch != self.health.security_epoch
            || id != &local.device_id
            || key.as_slice() != local.identity.fingerprint()
            || (!host && c.account_id != p.account_id)
        {
            return Err(SdkError::Trust);
        }
        Ok(())
    }
    pub fn prepare_reconnection(
        &self,
        local: &DeviceIdentity,
        previous: &VerifiedPermit,
    ) -> Result<ReconnectionAttempt, SdkError> {
        self.reconnection_identity(local, previous, false)?;
        let (started, now) = time()?;
        let c = previous.claims();
        if now < c.issued_at_unix_ms {
            return Err(SdkError::Trust);
        }
        let budget_ms = c
            .expires_at_unix_ms
            .checked_sub(now)
            .filter(|v| *v > 0)
            .ok_or(SdkError::Timeout)?;
        let choice = ReconnectionChoice {
            previous_permit_sha256: URL_SAFE_NO_PAD.encode(previous.digest()),
            connection_generation: c
                .connection_generation
                .checked_add(1)
                .ok_or(SdkError::Invalid)?,
            lease_sequence: c.lease_sequence.checked_add(1).ok_or(SdkError::Invalid)?,
            nonce: URL_SAFE_NO_PAD.encode(nestlink_auth::random_bytes::<32>()),
            network_recovery: None,
        };
        let signature = URL_SAFE_NO_PAD.encode(
            local
                .identity
                .sign_action(&reconnection::transcript(c, &local.device_id, &choice)?)?,
        );
        Ok(ReconnectionAttempt {
            previous: previous.clone(),
            offer: ReconnectionOffer {
                choice,
                controller_signature: signature,
            },
            issuer: self.trust.permit_issuer,
            login_session: self.principal().ok_or(SdkError::SignIn)?.session_id.clone(),
            started,
            budget_ms,
            unix_at_start: now,
        })
    }
    pub async fn offer_reconnection(&self, attempt: &ReconnectionAttempt) -> Result<(), SdkError> {
        attempt.check(self)?;
        attempt
            .bounded(self.call::<_, serde_json::Value>(
                Method::POST,
                &format!(
                    "{}/reconnect/offer",
                    resource("remote", &attempt.previous.claims().session_id)?
                ),
                Some(&attempt.offer),
                true,
            ))
            .await?;
        attempt.check(self)
    }
    pub async fn reconnection_state(&self, id: &str) -> Result<ReconnectionState, SdkError> {
        self.required(
            Method::GET,
            &format!("{}/reconnect", resource("remote", id)?),
            None::<&()>,
        )
        .await
    }
    pub fn reconnection_host_signature(
        &self,
        local: &DeviceIdentity,
        previous: &VerifiedPermit,
        controller_key: &[u8; 32],
        offer: &ReconnectionOffer,
    ) -> Result<String, SdkError> {
        if offer.choice.network_recovery.is_some() {
            return Err(SdkError::Trust);
        }
        self.reconnection_host_signature_inner(local, previous, controller_key, offer)
    }
    fn reconnection_host_signature_inner(
        &self,
        local: &DeviceIdentity,
        previous: &VerifiedPermit,
        controller_key: &[u8; 32],
        offer: &ReconnectionOffer,
    ) -> Result<String, SdkError> {
        self.reconnection_identity(local, previous, true)?;
        peer_proof(
            previous,
            controller_key,
            false,
            &offer.choice,
            &offer.controller_signature,
        )?;
        Ok(
            URL_SAFE_NO_PAD.encode(local.identity.sign_action(&reconnection::transcript(
                previous.claims(),
                &local.device_id,
                &offer.choice,
            )?)?),
        )
    }
    fn accept_reconnection(
        &self,
        attempt: &ReconnectionAttempt,
        submission: &ReconnectionSubmission,
        grant: &str,
    ) -> Result<ReconnectedPermit, SdkError> {
        attempt.check(self)?;
        if grant.len() as u64 > (RECONNECTION_BYTES + 128).div_ceil(3) * 4 {
            return Err(SdkError::Invalid);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(grant)
            .map_err(|_| SdkError::Invalid)?;
        let next = reconnection::verify_reconnection(
            &bytes,
            &self.trust.permit_issuer,
            attempt.previous.claims(),
            submission,
        )?.retain_remote_budget(&attempt.previous)?;
        attempt.check(self)?;
        Ok(ReconnectedPermit {
            permit: next,
            context: ReconnectionAttempt {
                previous: attempt.previous.clone(),
                offer: attempt.offer.clone(),
                issuer: attempt.issuer,
                login_session: attempt.login_session.clone(),
                started: attempt.started,
                budget_ms: attempt.budget_ms,
                unix_at_start: attempt.unix_at_start,
            },
        })
    }
    pub async fn commit_reconnection(
        &self,
        attempt: &ReconnectionAttempt,
        host_key: &[u8; 32],
        host_signature: String,
    ) -> Result<ReconnectedPermit, SdkError> {
        attempt.check(self)?;
        peer_proof(
            &attempt.previous,
            host_key,
            true,
            &attempt.offer.choice,
            &host_signature,
        )?;
        let submission = attempt.submission(host_signature);
        let response: ReconnectionResponse = attempt
            .bounded(self.required(
                Method::POST,
                &format!(
                    "{}/reconnect",
                    resource("remote", &attempt.previous.claims().session_id)?
                ),
                Some(&submission),
            ))
            .await?;
        self.accept_reconnection(attempt, &submission, &response.grant)
    }
    /// Called after a failed committed carrier. Both endpoints retain their original lease budget.
    pub async fn coordinate_reconnection_controller(
        &self,
        attempt: &ReconnectionAttempt,
        host_key: &[u8; 32],
        cancelled: impl Fn() -> bool,
    ) -> Result<ReconnectedPermit, SdkError> {
        loop {
            attempt.check(self)?;
            if cancelled() {
                return Err(SdkError::Timeout);
            }
            match self.offer_reconnection(attempt).await {
                Ok(()) => break,
                Err(e) if retryable(&e) => attempt.pause().await?,
                Err(e) => return Err(e),
            }
        }
        loop {
            attempt.check(self)?;
            if cancelled() {
                return Err(SdkError::Timeout);
            }
            let state = match attempt
                .bounded(self.reconnection_state(&attempt.previous.claims().session_id))
                .await
            {
                Ok(s) => s,
                Err(e) if retryable(&e) => {
                    attempt.pause().await?;
                    continue;
                }
                Err(e) => return Err(e),
            };
            if let Some(offer) = state.offer {
                if offer != attempt.offer {
                    return Err(SdkError::Trust);
                }
                if let Some(signature) = state.host_signature {
                    if cancelled() {
                        return Err(SdkError::Timeout);
                    }
                    match self.commit_reconnection(attempt, host_key, signature).await {
                        Ok(next) => {
                            if cancelled() {
                                return Err(SdkError::Timeout);
                            }
                            return Ok(next);
                        }
                        Err(e) if retryable(&e) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
            attempt.pause().await?;
        }
    }
    pub async fn coordinate_reconnection_host(
        &self,
        local: &DeviceIdentity,
        previous: &VerifiedPermit,
        controller_key: &[u8; 32],
        cancelled: impl Fn() -> bool,
    ) -> Result<ReconnectedPermit, SdkError> {
        self.coordinate_reconnection_host_bounded(local, previous, controller_key, cancelled, None)
            .await
    }
    pub(crate) async fn coordinate_reconnection_host_bounded(
        &self,
        local: &DeviceIdentity,
        previous: &VerifiedPermit,
        controller_key: &[u8; 32],
        cancelled: impl Fn() -> bool,
        deadline: Option<Started>,
    ) -> Result<ReconnectedPermit, SdkError> {
        self.coordinate_reconnection_host_checked(
            local,
            previous,
            controller_key,
            cancelled,
            deadline,
            |choice| {
                if choice.network_recovery.is_none() {
                    Ok(())
                } else {
                    Err(SdkError::Trust)
                }
            },
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn coordinate_reconnection_host_checked(
        &self,
        local: &DeviceIdentity,
        previous: &VerifiedPermit,
        controller_key: &[u8; 32],
        cancelled: impl Fn() -> bool,
        deadline: Option<Started>,
        validate: impl Fn(&ReconnectionChoice) -> Result<(), SdkError>,
    ) -> Result<ReconnectedPermit, SdkError> {
        self.reconnection_identity(local, previous, true)?;
        let (started, now) = time()?;
        let c = previous.claims();
        if now < c.issued_at_unix_ms {
            return Err(SdkError::Trust);
        }
        let budget_ms = c
            .expires_at_unix_ms
            .checked_sub(now)
            .filter(|v| *v > 0)
            .ok_or(SdkError::Timeout)?;
        let mut attempt = ReconnectionAttempt {
            previous: previous.clone(),
            offer: ReconnectionOffer {
                choice: ReconnectionChoice {
                    previous_permit_sha256: String::new(),
                    connection_generation: 0,
                    lease_sequence: 0,
                    nonce: String::new(),
                    network_recovery: None,
                },
                controller_signature: String::new(),
            },
            issuer: self.trust.permit_issuer,
            login_session: self.principal().ok_or(SdkError::SignIn)?.session_id.clone(),
            started,
            budget_ms,
            unix_at_start: now,
        };
        let mut chosen = false;
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(deadline) = deadline {
            attempt.cap_deadline(deadline)?;
        }
        #[cfg(target_arch = "wasm32")]
        let _ = deadline;
        loop {
            attempt.check(self)?;
            if cancelled() {
                return Err(SdkError::Timeout);
            }
            let state = match attempt
                .bounded(self.reconnection_state(&c.session_id))
                .await
            {
                Ok(s) => s,
                Err(e) if retryable(&e) => {
                    attempt.pause().await?;
                    continue;
                }
                Err(e) => return Err(e),
            };
            if cancelled() {
                return Err(SdkError::Timeout);
            }
            if let Some(offer) = state.offer {
                if offer.choice.previous_permit_sha256 != URL_SAFE_NO_PAD.encode(previous.digest())
                    && !chosen
                {
                    // A completed prior exchange can remain visible until the next offer arrives.
                    attempt.pause().await?;
                    continue;
                }
                validate(&offer.choice)?;
                let signature = self.reconnection_host_signature_inner(
                    local,
                    previous,
                    controller_key,
                    &offer,
                )?;
                if chosen && attempt.offer != offer {
                    return Err(SdkError::Trust);
                }
                attempt.offer = offer;
                chosen = true;
                if let Some(grant) = state.grant {
                    if state.host_signature.as_deref() != Some(&signature) {
                        return Err(SdkError::Trust);
                    }
                    return self.accept_reconnection(
                        &attempt,
                        &attempt.submission(signature),
                        &grant,
                    );
                }
                let body = ReconnectionApproval {
                    choice: attempt.offer.choice.clone(),
                    host_signature: signature,
                };
                if cancelled() {
                    return Err(SdkError::Timeout);
                }
                match attempt
                    .bounded(self.call::<_, serde_json::Value>(
                        Method::POST,
                        &format!("{}/reconnect/approve", resource("remote", &c.session_id)?),
                        Some(&body),
                        true,
                    ))
                    .await
                {
                    Ok(_) => {}
                    Err(e) if retryable(&e) => {}
                    // Commit can win the race with a duplicate approval. Read its receipt next.
                    Err(SdkError::Api(StatusCode::CONFLICT, _)) => {}
                    Err(e) => return Err(e),
                }
            }
            attempt.pause().await?;
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub fn reconnection_endpoint(
        &self,
        receipt: &ReconnectedPermit,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        config: NativeReconnectionConfig<'_>,
    ) -> Result<crate::native::NativeEndpoint, SdkError> {
        receipt.context.check(self)?;
        let automatic = config.bound == std::net::SocketAddr::from(([0, 0, 0, 0], 0));
        let mut endpoint = if automatic && let Some(monitor) = config.monitor {
            crate::native::NativeEndpoint::new_dual_stack_monitored(
                local,
                peer_key,
                receipt.permit.clone(),
                config.stun_servers,
                config.address_policy,
                monitor,
            )?
        } else if automatic {
            crate::native::NativeEndpoint::new_dual_stack(
                local,
                peer_key,
                receipt.permit.clone(),
                config.stun_servers,
                config.address_policy,
            )?
        } else if let Some(monitor) = config.monitor {
            crate::native::NativeEndpoint::new_monitored(
                config.bound,
                local,
                peer_key,
                receipt.permit.clone(),
                config.stun_servers,
                config.address_policy,
                monitor,
            )?
        } else {
            crate::native::NativeEndpoint::new(
                config.bound,
                local,
                peer_key,
                receipt.permit.clone(),
                config.stun_servers,
                config.address_policy,
            )?
        };
        endpoint.cap_authorization_deadline(
            receipt.context.started + Duration::from_millis(receipt.context.budget_ms),
        )?;
        receipt.context.check(self)?;
        Ok(endpoint)
    }
    /// Consume and stop the committed session before initiating a replacement.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn reconnect_native_controller(
        &self,
        local: &DeviceIdentity,
        previous: &VerifiedPermit,
        host_key: &[u8; 32],
        mut failed: crate::native::NativeSession,
        cancelled: impl Fn() -> bool,
    ) -> Result<ReconnectedPermit, SdkError> {
        let mut attempt = self.prepare_reconnection(local, previous)?;
        failed
            .channels
            .shutdown(nestlink_session::StopReason::NetworkChanged)
            .await?;
        let budget = failed.channels.lease_control().reconnection_budget()?;
        if budget.permit().claims() != previous.claims() {
            return Err(SdkError::Trust);
        }
        attempt.cap_deadline(budget.deadline())?;
        drop(failed);
        self.coordinate_reconnection_controller(&attempt, host_key, cancelled)
            .await
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn reconnect_native_host(
        &self,
        local: &DeviceIdentity,
        previous: &VerifiedPermit,
        controller_key: &[u8; 32],
        mut failed: crate::native::NativeSession,
        cancelled: impl Fn() -> bool,
    ) -> Result<ReconnectedPermit, SdkError> {
        self.reconnection_identity(local, previous, true)?;
        failed
            .channels
            .shutdown(nestlink_session::StopReason::NetworkChanged)
            .await?;
        let budget = failed.channels.lease_control().reconnection_budget()?;
        if budget.permit().claims() != previous.claims() {
            return Err(SdkError::Trust);
        }
        drop(failed);
        self.coordinate_reconnection_host_bounded(
            local,
            previous,
            controller_key,
            cancelled,
            Some(budget.deadline()),
        )
        .await
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn prepare_bounded_reconnection(
        &self,
        local: &DeviceIdentity,
        budget: &nestlink_remote::ReconnectionBudget,
    ) -> Result<ReconnectionAttempt, SdkError> {
        let mut attempt = self.prepare_reconnection(local, budget.permit())?;
        attempt.cap_deadline(budget.deadline())?;
        Ok(attempt)
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn prepare_network_reconnection(
        &self,
        local: &DeviceIdentity,
        budget: &nestlink_remote::ReconnectionBudget,
        recovery: nestlink_protocol::api::NetworkRouteRecoveryChoice,
    ) -> Result<ReconnectionAttempt, SdkError> {
        let mut attempt = self.prepare_bounded_reconnection(local, budget)?;
        attempt.offer.choice.network_recovery = Some(recovery);
        attempt.offer.controller_signature =
            URL_SAFE_NO_PAD.encode(local.identity.sign_action(&reconnection::transcript(
                budget.permit().claims(),
                &local.device_id,
                &attempt.offer.choice,
            )?)?);
        attempt.check(self)?;
        Ok(attempt)
    }
}
