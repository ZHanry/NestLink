//! The actor retains this job and its Client while the SDK performs a round.
//! No second management client or detached signing/renewal worker is created.
use super::*;
use nestlink_protocol::media_authority::MediaDirection;
struct ExecutionFence {
    dispatch: sdk_call::DispatchFence,
    execution: Arc<dyn nestlink_remote::native_renewal::NativeExecutionFence>,
}
impl nestlink_remote::native_renewal::NativeExecutionFence for ExecutionFence {
    fn with_current(&self, operation: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.dispatch
            .check()
            .map_err(|_| io::Error::other("renewal dispatch retired"))?;
        self.execution.with_current(&mut || {
            self.dispatch
                .check()
                .map_err(|_| io::Error::other("renewal dispatch retired"))?;
            operation()
        })
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn poll(
    client: &Client,
    identity: &DeviceIdentity,
    key: &NativeSessionKey,
    dispatch: &sdk_call::DispatchFence,
    control: Option<&NativeSessionControl>,
    config: Option<&NativeSessionConfig>,
    shared: &Arc<Shared>,
) -> NativePermitState {
    let Some(control) = control.filter(|control| control.has_native_renewal()) else {
        return poll_native_permit(client, identity, key, dispatch).await;
    };
    let result = advance(client, identity, key, dispatch, control, config, shared).await;
    match result {
        Ok(sequence) if sequence == key.lease_sequence => NativePermitState::Current,
        Ok(sequence) if key.lease_sequence.checked_add(1) == Some(sequence) => {
            NativePermitState::Renewed(sequence)
        }
        _ => {
            let _ = control.stop(StopReason::Revoked);
            NativePermitState::Revoked
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn advance(
    client: &Client,
    identity: &DeviceIdentity,
    key: &NativeSessionKey,
    dispatch: &sdk_call::DispatchFence,
    control: &NativeSessionControl,
    config: Option<&NativeSessionConfig>,
    shared: &Arc<Shared>,
) -> Result<u64, Failure> {
    dispatch.check()?;
    let config = config.ok_or_else(|| Failure::local(FailureKind::NativeSessionUnavailable))?;
    let source = Source {
        config,
        shared,
        dispatch: dispatch.clone(),
        binding: NativeSessionBinding {
            request_id: key.request_id.clone(),
            connection_generation: key.connection_generation,
        },
    };
    let deadline = tokio::time::Instant::now()
        + control
            .lease_remaining()
            .map_err(|_| Failure::local(FailureKind::PermitExpired))?;
    let permit = control
        .native_renewal_step(&client.sdk, identity, &source)
        .await
        .map_err(Failure::from)?;
    dispatch.check()?;
    // GET the existing signed current lease; POST /permit is initial-only.
    let current = tokio::time::timeout_at(
        deadline,
        client.sdk.current_native_permit(identity, &key.request_id),
    )
    .await
    .map_err(|_| Failure::local(FailureKind::Timeout))?
    .map_err(Failure::from)?;
    dispatch.check()?;
    let view = tokio::time::timeout_at(deadline, client.sdk.remote(&key.request_id))
        .await
        .map_err(|_| Failure::local(FailureKind::Timeout))?
        .map_err(Failure::from)?;
    dispatch.check()?;
    let c = permit.claims();
    if current.claims() != c
        || current.issuer() != permit.issuer()
        || view.status != "approved"
        || c.session_id != key.request_id
        || c.connection_generation != key.connection_generation
        || view.connection_generation != c.connection_generation
        || view.lease_sequence != c.lease_sequence
        || view.permissions != c.permissions
        || view.paths != c.paths
        || c.expires_at_unix_ms <= unix_millis().unwrap_or(u64::MAX)
    {
        return Err(Failure::local(FailureKind::Trust));
    }
    Ok(c.lease_sequence)
}

struct Source<'a> {
    config: &'a NativeSessionConfig,
    shared: &'a Arc<Shared>,
    dispatch: sdk_call::DispatchFence,
    binding: NativeSessionBinding,
}
impl nestlink_sdk::native_renewal::NativeRenewalSource for Source<'_> {
    fn prepare<'a>(
        &'a self,
        sdk: &'a Sdk,
        identity: &'a DeviceIdentity,
        current: &'a nestlink_identity::VerifiedPermit,
        role: nestlink_session::EndpointRole,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        nestlink_sdk::native_renewal::PreparedNativeRenewal,
                        nestlink_sdk::SdkError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.dispatch
                .check()
                .map_err(|_| nestlink_sdk::SdkError::Trust)?;
            if current.claims().session_id != self.binding.request_id
                || current.claims().connection_generation != self.binding.connection_generation
            {
                return Err(nestlink_sdk::SdkError::Trust);
            }
            let provider = self
                .config
                .media_provider
                .as_ref()
                .ok_or(nestlink_sdk::SdkError::Trust)?;
            let direction = if role == nestlink_session::EndpointRole::Host {
                MediaDirection::Encode
            } else {
                MediaDirection::Decode
            };
            let execution = self
                .shared
                .native_media_execution_fence(&self.binding, direction)?;
            let local = provider
                .publish_for_renewal(sdk, identity, direction, &self.dispatch)
                .await?;
            self.dispatch
                .check()
                .map_err(|_| nestlink_sdk::SdkError::Trust)?;
            let frozen = sdk
                .remote_media_scope(&self.binding.request_id)
                .await?
                .ok_or(nestlink_sdk::SdkError::Trust)?;
            self.dispatch
                .check()
                .map_err(|_| nestlink_sdk::SdkError::Trust)?;
            Ok(nestlink_sdk::native_renewal::PreparedNativeRenewal {
                evidence: nestlink_sdk::native::NativeMediaEvidence { frozen, local },
                execution: Arc::new(ExecutionFence {
                    dispatch: self.dispatch.clone(),
                    execution,
                }),
            })
        })
    }
}
