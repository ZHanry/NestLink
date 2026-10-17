use crate::{
    Action, Failure, FailureKind, HostRemotePassword, Page, PublicOutput, RemoteAccess,
    RemoteEffect, RemotePasswordOffer, Snapshot, TrustedDevices,
};
use nestlink_auth::random_id;
use nestlink_protocol::api::*;
use nestlink_sdk::{DeviceIdentity, Sdk, SdkError};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

#[derive(Clone)]
pub(crate) struct DispatchFence {
    pub generation: Arc<AtomicU64>,
    pub expected: u64,
    pub closing: Arc<AtomicBool>,
    pub cancelled: Arc<AtomicBool>,
}
impl DispatchFence {
    pub(crate) fn check(&self) -> Result<(), Failure> {
        if self.generation.load(Ordering::Acquire) != self.expected
            || self.closing.load(Ordering::Acquire)
            || self.cancelled.load(Ordering::Acquire)
        {
            Err(Failure::local(FailureKind::Superseded))
        } else {
            Ok(())
        }
    }
}
async fn read<T>(
    future: impl Future<Output = Result<T, SdkError>>,
    fence: &DispatchFence,
) -> Result<T, Failure> {
    fence.check()?;
    future.await.map_err(Failure::from)
}

pub(crate) enum Patch {
    Security(MeResponse),
    Devices(Vec<DeviceView>),
    Services(ServicePage),
    SelectedService(ServiceView),
    Requests(Vec<RemoteView>),
    SelectedRequest(RemoteView),
    Accounts(Vec<AccountView>),
    Policy(PolicyResponse),
    PathLimits(Vec<PathLimit>),
    RelayQuota(RelayQuota),
    RelayUsage(RelayUsage),
    Nodes(Vec<NodeView>),
    NodeUsage(NodeUsagePage),
    Audit(AuditPage),
    AuditRetention(AuditRetention),
    TrustedDevices(TrustedDevices),
    RemotePassword(HostRemotePassword),
    RemotePasswordOffer(RemotePasswordOffer),
}
impl Patch {
    pub(crate) fn apply(self, view: &mut Snapshot) {
        match self {
            Self::Security(value) => {
                view.principal = Some(value.principal.clone());
                view.security.replace(value);
            }
            Self::Devices(value) => view.devices.replace(value),
            Self::Services(value) => view.services.replace(value),
            Self::SelectedService(value) => view.selected_service.replace(value),
            Self::Requests(value) => view.requests.replace(value),
            Self::SelectedRequest(value) => view.selected_request.replace(value),
            Self::Accounts(value) => view.accounts.replace(value),
            Self::Policy(value) => view.policy.replace(value),
            Self::PathLimits(value) => view.path_limits.replace(value),
            Self::RelayQuota(value) => view.relay_quota.replace(value),
            Self::RelayUsage(value) => view.relay_usage.replace(value),
            Self::Nodes(value) => view.nodes.replace(value),
            Self::NodeUsage(value) => view.node_usage.replace(value),
            Self::Audit(value) => view.audit.replace(value),
            Self::AuditRetention(value) => view.audit_retention.replace(value),
            Self::TrustedDevices(value) => view.trusted_devices.replace(value),
            Self::RemotePassword(value) => view.remote_password.replace(value),
            Self::RemotePasswordOffer(value) => view.remote_password_offer.replace(value),
        }
    }
}

pub(crate) struct Response {
    pub sdk: Sdk,
    pub failure: Option<Failure>,
    pub effect: RemoteEffect,
    pub output: PublicOutput,
    pub sensitive: Option<crate::SensitiveMaterial>,
    pub patches: Vec<Patch>,
    pub session_lost: bool,
}

impl From<SdkError> for Failure {
    fn from(error: SdkError) -> Self {
        match error {
            SdkError::Api(status, code) => Self {
                kind: FailureKind::Rejected,
                status: Some(status.as_u16()),
                code: Some(code),
            },
            SdkError::SignIn => Self::local(FailureKind::SignInRequired),
            SdkError::Trust | SdkError::Proof(_) => Self::local(FailureKind::Trust),
            SdkError::Invalid | SdkError::Json(_) => Self::local(FailureKind::Invalid),
            SdkError::Timeout => Self::local(FailureKind::Timeout),
            SdkError::Transport(error) if error.is_timeout() => Self::local(FailureKind::Timeout),
            _ => Self::local(FailureKind::Transport),
        }
    }
}

async fn write<T>(
    future: impl Future<Output = Result<T, SdkError>>,
    effect: &mut RemoteEffect,
    fence: &DispatchFence,
) -> Result<T, Failure> {
    fence.check()?;
    *effect = RemoteEffect::Unknown;
    match future.await {
        Ok(value) => {
            *effect = RemoteEffect::Committed;
            Ok(value)
        }
        Err(error) => {
            let failure = Failure::from(error);
            // An explicit client rejection is known. A lost response or a 5xx
            // cannot establish whether a transaction committed.
            if failure
                .status
                .is_some_and(|status| (400..500).contains(&status))
            {
                *effect = RemoteEffect::None;
            }
            Err(failure)
        }
    }
}

async fn security(sdk: &Sdk, fence: &DispatchFence) -> Result<MeResponse, Failure> {
    let me = read(sdk.me(), fence).await?;
    let principal = sdk
        .principal()
        .ok_or_else(|| Failure::local(FailureKind::SignInRequired))?;
    if me.principal.account_id != principal.account_id
        || me.principal.session_id != principal.session_id
        || me.principal.access_expires == 0
        || me.principal.access_expires > i64::MAX as u64
    {
        return Err(Failure::local(FailureKind::Trust));
    }
    Ok(me)
}

pub(crate) async fn run(
    sdk: Sdk,
    identity: Option<Arc<DeviceIdentity>>,
    action: Action,
    fence: DispatchFence,
) -> Response {
    let reauthentication = action.reauthentication();
    let sign_in = matches!(action, Action::SignIn { .. });
    let mut response = Response {
        sdk,
        failure: None,
        effect: RemoteEffect::None,
        output: PublicOutput::None,
        sensitive: None,
        patches: Vec::new(),
        session_lost: false,
    };
    let result = execute(&mut response, identity.as_deref(), action, &fence).await;
    if let Err(failure) = result {
        if !sign_in && failure.authentication_rejected() {
            // A bad reauthentication factor is not evidence that a management
            // session expired. Confirm the actual session using its access token.
            response.session_lost = if reauthentication && response.sdk.principal().is_some() {
                match security(&response.sdk, &fence).await {
                    Ok(me) => {
                        response.patches.push(Patch::Security(me));
                        false
                    }
                    Err(_) => true,
                }
            } else {
                true
            };
        }
        response.failure = Some(failure);
    }
    if !sign_in && response.sdk.principal().is_none() {
        response.session_lost = true;
    }
    // Keep ownership explicit in the return value, including failed requests.
    response
}

async fn execute(
    response: &mut Response,
    identity: Option<&DeviceIdentity>,
    action: Action,
    fence: &DispatchFence,
) -> Result<(), Failure> {
    fence.check()?;
    let sdk = &mut response.sdk;
    let effect = &mut response.effect;
    let patches = &mut response.patches;
    let local = || identity.ok_or_else(|| Failure::local(FailureKind::LocalIdentityRequired));
    match action {
        Action::SignIn {
            username,
            password,
            factor,
        } => {
            write(sdk.login(username, password, factor), effect, fence).await?;
            patches.push(Patch::Security(security(sdk, fence).await?));
        }
        Action::RefreshSession => {
            write(sdk.refresh(), effect, fence).await?;
            patches.push(Patch::Security(security(sdk, fence).await?));
        }
        Action::Load { page } => patches.push(match page {
            Page::AccountSecurity => Patch::Security(security(sdk, fence).await?),
            Page::Devices => Patch::Devices(read(sdk.devices(), fence).await?),
            Page::Services => Patch::Services(read(sdk.services(None, 50), fence).await?),
            Page::Requests => Patch::Requests(read(sdk.pending_remote(), fence).await?),
            Page::Accounts => Patch::Accounts(read(sdk.accounts(), fence).await?),
            Page::Policy => Patch::Policy(read(sdk.policy(), fence).await?),
            Page::PathLimits => Patch::PathLimits(read(sdk.path_limits(), fence).await?),
            Page::RelayQuota => Patch::RelayQuota(read(sdk.relay_quota(), fence).await?),
            Page::RelayUsage => Patch::RelayUsage(read(sdk.relay_usage(), fence).await?),
            Page::Nodes => Patch::Nodes(read(sdk.nodes(), fence).await?),
            Page::AuditRetention => {
                Patch::AuditRetention(read(sdk.audit_retention(), fence).await?)
            }
        }),
        Action::LoadServicesPage { after_id, limit } => {
            patches.push(Patch::Services(
                read(sdk.services(after_id.as_deref(), limit), fence).await?,
            ));
        }
        Action::InspectService { service_id } => {
            patches.push(Patch::SelectedService(
                read(sdk.service(&service_id), fence).await?,
            ));
        }
        Action::CreateService { create } => {
            let value = write(sdk.create_service(&create), effect, fence).await?;
            response.output = PublicOutput::Created {
                id: value.id.clone(),
            };
            patches.push(Patch::SelectedService(value));
            patches.push(Patch::Services(read(sdk.services(None, 50), fence).await?));
        }
        Action::UpdateService { service_id, update } => {
            let value = write(sdk.update_service(&service_id, &update), effect, fence).await?;
            response.output = PublicOutput::Revision {
                revision: value.revision,
            };
            patches.push(Patch::SelectedService(value));
            patches.push(Patch::Services(read(sdk.services(None, 50), fence).await?));
        }
        Action::RevokeService {
            service_id,
            expected_revision,
        } => {
            let value = write(
                sdk.revoke_service(&service_id, expected_revision),
                effect,
                fence,
            )
            .await?;
            response.output = PublicOutput::Revision {
                revision: value.revision,
            };
            patches.push(Patch::SelectedService(value));
            patches.push(Patch::Services(read(sdk.services(None, 50), fence).await?));
        }
        Action::LoadAudit {
            after_sequence,
            limit,
        } => patches.push(Patch::Audit(
            read(sdk.audit_page(after_sequence, limit), fence).await?,
        )),
        Action::LoadNodeUsage {
            node_id,
            after_generation,
            limit,
        } => patches.push(Patch::NodeUsage(
            read(sdk.node_usage(&node_id, after_generation, limit), fence).await?,
        )),
        Action::InspectRemote { request_id } => patches.push(Patch::SelectedRequest(
            read(sdk.remote(&request_id), fence).await?,
        )),
        Action::IssueRemotePermit { request_id } => {
            let permit = write(sdk.permit(&request_id), effect, fence).await?;
            response.output = PublicOutput::Revision {
                revision: permit.claims().lease_sequence,
            };
            patches.push(Patch::SelectedRequest(
                read(sdk.remote(&request_id), fence).await?,
            ));
        }
        Action::EnrollLocalDevice {
            name,
            platform,
            capabilities,
            path_mode,
        } => {
            write(
                sdk.enroll(local()?, name, platform, capabilities, path_mode),
                effect,
                fence,
            )
            .await?;
            patches.push(Patch::Devices(read(sdk.devices(), fence).await?));
        }
        Action::RevokeDevice { device_id } => {
            write(sdk.revoke_device(&device_id), effect, fence).await?;
            patches.push(Patch::Devices(read(sdk.devices(), fence).await?));
        }
        Action::RequestRemote {
            host_device_id,
            permissions,
            path_mode,
            access,
        } => {
            let request = RemoteRequest {
                id: random_id(),
                controller_device_id: local()?.device_id.clone(),
                host_device_id,
                permissions,
                path_mode,
            };
            let value = match access {
                RemoteAccess::LocalApproval => {
                    write(sdk.create_remote(request), effect, fence).await?
                }
                RemoteAccess::TrustedDevice => {
                    write(sdk.create_trusted_remote(request), effect, fence).await?
                }
            };
            response.output = PublicOutput::Created {
                id: value.id.clone(),
            };
            patches.push(Patch::SelectedRequest(value));
        }
        Action::ApproveRemote {
            request_id,
            expected_nonce,
            expected_policy_revision,
            choice,
        } => {
            let view = read(sdk.remote(&request_id), fence).await?;
            if view.nonce != expected_nonce
                || view.policy_revision != expected_policy_revision
                || view.status != "pending"
            {
                return Err(Failure::local(FailureKind::Trust));
            }
            write(sdk.approve(local()?, &view, choice), effect, fence).await?;
            patches.push(Patch::Requests(read(sdk.pending_remote(), fence).await?));
            patches.push(Patch::SelectedRequest(
                read(sdk.remote(&request_id), fence).await?,
            ));
        }
        Action::RevokeRemote { request_id } => {
            write(sdk.revoke_remote(&request_id), effect, fence).await?;
            patches.push(Patch::Requests(read(sdk.pending_remote(), fence).await?));
            patches.push(Patch::SelectedRequest(
                read(sdk.remote(&request_id), fence).await?,
            ));
        }
        Action::BeginTotp { password, factor } => {
            response.sensitive = Some(crate::SensitiveMaterial::TotpSeed(
                write(sdk.begin_totp(password, factor), effect, fence).await?,
            ));
        }
        Action::ConfirmTotp { code } => {
            response.sensitive = Some(crate::SensitiveMaterial::RecoveryCodes(
                write(sdk.confirm_totp(code), effect, fence).await?,
            ));
            patches.push(Patch::Security(security(sdk, fence).await?));
        }
        Action::ResetRecovery { password, factor } => {
            response.sensitive = Some(crate::SensitiveMaterial::RecoveryCodes(
                write(sdk.reset_recovery(password, factor), effect, fence).await?,
            ));
            patches.push(Patch::Security(security(sdk, fence).await?));
        }
        Action::ChangePassword {
            current_password,
            new_password,
            factor,
        } => {
            write(
                sdk.change_password(current_password, new_password, factor),
                effect,
                fence,
            )
            .await?;
        }
        Action::CreateAccount { username, password } => {
            response.output = PublicOutput::Created {
                id: write(sdk.create_account(username, password), effect, fence).await?,
            };
            patches.push(Patch::Accounts(read(sdk.accounts(), fence).await?));
        }
        Action::DisableAccount { account_id } => {
            write(sdk.disable_account(&account_id), effect, fence).await?;
            patches.push(Patch::Accounts(read(sdk.accounts(), fence).await?));
        }
        Action::SetPolicy { update } => {
            response.output = PublicOutput::Revision {
                revision: write(sdk.set_policy(update), effect, fence).await?,
            };
            patches.push(Patch::Policy(read(sdk.policy(), fence).await?));
        }
        Action::SetPathLimit {
            scope,
            resource_id,
            update,
        } => {
            response.output = PublicOutput::Revision {
                revision: write(
                    sdk.set_path_limit(&scope, &resource_id, update),
                    effect,
                    fence,
                )
                .await?,
            };
            patches.push(Patch::PathLimits(read(sdk.path_limits(), fence).await?));
        }
        Action::SetRelayQuota { update } => patches.push(Patch::RelayQuota(
            write(sdk.set_relay_quota(update), effect, fence).await?,
        )),
        Action::RegisterNode { node } => {
            write(sdk.register_node(node), effect, fence).await?;
            patches.push(Patch::Nodes(read(sdk.nodes(), fence).await?));
        }
        Action::RevokeNode { node_id } => {
            write(sdk.revoke_node(&node_id), effect, fence).await?;
            patches.push(Patch::Nodes(read(sdk.nodes(), fence).await?));
        }
        Action::SetAuditRetention { update } => patches.push(Patch::AuditRetention(
            write(sdk.set_audit_retention(update), effect, fence).await?,
        )),
        Action::LoadTrustedDevices { host_device_id } => {
            let devices = read(sdk.trusted_devices(&host_device_id), fence).await?;
            patches.push(Patch::TrustedDevices(TrustedDevices {
                host_device_id,
                devices,
            }));
        }
        Action::TrustRemote { request_id, choice } => {
            let host = local()?;
            let permit = read(sdk.host_permit(host, &request_id), fence).await?;
            response.output = PublicOutput::Revision {
                revision: write(sdk.trust_remote(host, &permit, choice), effect, fence).await?,
            };
            patches.push(Patch::TrustedDevices(TrustedDevices {
                host_device_id: host.device_id.clone(),
                devices: read(sdk.trusted_devices(&host.device_id), fence).await?,
            }));
        }
        Action::RevokeDeviceTrust {
            host_device_id,
            controller_device_id,
            expected_revision,
        } => {
            write(
                sdk.revoke_device_trust(&host_device_id, &controller_device_id, expected_revision),
                effect,
                fence,
            )
            .await?;
            patches.push(Patch::TrustedDevices(TrustedDevices {
                devices: read(sdk.trusted_devices(&host_device_id), fence).await?,
                host_device_id,
            }));
        }
        Action::LoadRemotePassword { host_device_id } => {
            patches.push(Patch::RemotePassword(HostRemotePassword {
                settings: read(sdk.remote_password(&host_device_id), fence).await?,
                host_device_id,
            }))
        }
        Action::LoadRemotePasswordOffer { request_id } => {
            patches.push(Patch::RemotePasswordOffer(RemotePasswordOffer {
                settings: read(sdk.remote_password_offer(&request_id), fence).await?,
                request_id,
            }))
        }
        Action::ConfigureRemotePassword { settings, password } => {
            let host = local()?;
            response.output = PublicOutput::Revision {
                revision: write(
                    sdk.configure_remote_password(host, settings, password),
                    effect,
                    fence,
                )
                .await?,
            };
            patches.push(Patch::RemotePassword(HostRemotePassword {
                host_device_id: host.device_id.clone(),
                settings: read(sdk.remote_password(&host.device_id), fence).await?,
            }));
        }
        Action::RevokeRemotePassword { expected_revision } => {
            let host = local()?;
            write(
                sdk.revoke_remote_password(&host.device_id, expected_revision),
                effect,
                fence,
            )
            .await?;
            patches.push(Patch::RemotePassword(HostRemotePassword {
                host_device_id: host.device_id.clone(),
                settings: read(sdk.remote_password(&host.device_id), fence).await?,
            }));
        }
        Action::AuthorizeRemotePassword {
            request_id,
            expected_revision,
            password,
        } => {
            let view = read(sdk.remote(&request_id), fence).await?;
            patches.push(Patch::SelectedRequest(
                write(
                    sdk.authorize_remote_password(local()?, &view, expected_revision, password),
                    effect,
                    fence,
                )
                .await?,
            ));
        }
        // Native sessions are owned by the app-core actor and never dispatched
        // through the ordinary management-operation executor.
        Action::StartNativeSession { .. }
        | Action::StopNativeSession { .. }
        | Action::StartBrowserHost { .. }
        | Action::StopBrowserHost { .. } => {
            return Err(Failure::local(FailureKind::Invalid));
        }
    }
    Ok(())
}
