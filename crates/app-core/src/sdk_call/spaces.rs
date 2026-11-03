use super::*;
use crate::{SPACE_PAGE_SIZE, SpaceAction, SpaceDetailsPage, SpacePageCursor, SpaceServicePage};
use nestlink_protocol::spaces::{service_publication::*, *};

pub(super) fn bounded<T: serde::Serialize>(value: T) -> Result<T, Failure> {
    // Space views share the original 1 MiB IPC snapshot with other sections.
    // Keep each public section small; do not increase the transport limit.
    if serde_json::to_vec(&value).map_err(|_| Failure::local(FailureKind::Invalid))?.len() > 192 * 1024 {
        return Err(Failure::local(FailureKind::Capacity));
    }
    Ok(value)
}

fn page<T>(mut rows: Vec<T>, after: Option<&str>, id: impl Fn(&T) -> &str) -> (Vec<T>, Option<String>) {
    rows.sort_by(|a, b| id(a).cmp(id(b)));
    rows.retain(|row| after.is_none_or(|after| id(row) > after));
    let next = (rows.len() > SPACE_PAGE_SIZE).then(|| id(&rows[SPACE_PAGE_SIZE - 1]).to_owned());
    rows.truncate(SPACE_PAGE_SIZE);
    (rows, next)
}

fn detail_page(details: SpaceDetails, cursor: SpacePageCursor) -> Result<SpaceDetailsPage, Failure> {
    let (members, next_member) = page(details.members, cursor.after_member.as_deref(), |row| &row.account_id);
    let (devices, next_device) = page(details.devices, cursor.after_device.as_deref(), |row| &row.installation_id);
    let (invitations, next_invitation) = page(details.invitations, cursor.after_invitation.as_deref(), |row| &row.invitation_id);
    bounded(SpaceDetailsPage { space: details.space, members, devices, invitations, next_member, next_device, next_invitation })
}

fn service_page(policy: SpaceServicePolicyView, after: Option<&str>, selected: Option<&str>, after_rule: Option<&str>) -> Result<SpaceServicePage, Failure> {
    let mut binding = selected.and_then(|id| policy.bindings.iter().find(|row| row.service_id == id)).cloned();
    let mut next_rule = None;
    if let Some(binding) = &mut binding {
        let (rules, next) = page(std::mem::take(&mut binding.rules), after_rule, |row| &row.rule_id);
        binding.rules = rules;
        next_rule = next;
    }
    let listing = policy.bindings.into_iter().map(|mut binding| { binding.rules.clear(); binding }).collect();
    let (bindings, next_service) = page(listing, after, |row| &row.service_id);
    bounded(SpaceServicePage { space: policy.space, bindings, selected: binding, next_service, next_rule })
}

pub(super) async fn execute(response: &mut Response, context: String, action: SpaceAction, fence: &DispatchFence) -> Result<(), Failure> {
    let sdk = &response.sdk;
    let effect = &mut response.effect;
    let mut service_selection = None;
    let selected = match action {
        SpaceAction::List => None,
        SpaceAction::Read { space_id, cursor } => {
            let details = read(sdk.space_details(&space_id), fence).await?;
            response.patches.push(Patch::SpaceDetails { context, value: detail_page(details, cursor)? });
            return Ok(());
        }
        SpaceAction::Create { name } => {
            let space = write(sdk.create_space(SpaceCreateRequest { name }), effect, fence).await?;
            response.output = PublicOutput::Created { id: space.space_id.clone() };
            Some(space.space_id)
        }
        SpaceAction::Archive { space_id, request } => {
            write(sdk.archive_space(&space_id, request), effect, fence).await?;
            Some(space_id)
        }
        SpaceAction::UpdateMember { space_id, account_id, request } => {
            write(sdk.update_space_member(&space_id, &account_id, request), effect, fence).await?;
            Some(space_id)
        }
        SpaceAction::RemoveMember { space_id, account_id, request } => {
            write(sdk.remove_space_member(&space_id, &account_id, request), effect, fence).await?;
            Some(space_id)
        }
        SpaceAction::JoinDevice { space_id, request } => {
            write(sdk.join_space_device(&space_id, request), effect, fence).await?;
            Some(space_id)
        }
        SpaceAction::RemoveDevice { space_id, installation_id, request } => {
            write(sdk.remove_space_device(&space_id, &installation_id, request), effect, fence).await?;
            Some(space_id)
        }
        SpaceAction::Invite { space_id, request } => {
            let issued = write(sdk.invite_to_space(&space_id, request), effect, fence).await?;
            let token = nestlink_auth::Secret::from_text(issued.token);
            if issued.space.space_id != space_id || !nestlink_protocol::valid_id(&issued.invitation.invitation_id)
                || token.expose().len() != 43 || !token.expose().bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')) {
                return Err(Failure::local(FailureKind::Trust));
            }
            response.sensitive = Some(crate::SensitiveMaterial::SpaceInvitation {
                space_id: space_id.clone(), invitation_id: issued.invitation.invitation_id, token,
            });
            Some(space_id)
        }
        SpaceAction::RevokeInvitation { space_id, invitation_id, request } => {
            write(sdk.revoke_space_invitation(&space_id, &invitation_id, request), effect, fence).await?;
            Some(space_id)
        }
        SpaceAction::Accept { space_id, invitation_id, token } => {
            write(sdk.accept_space_invitation(&space_id, &invitation_id, SpaceInvitationAcceptance { token: token.expose().to_owned() }), effect, fence).await?;
            Some(space_id)
        }
        SpaceAction::Audit { space_id } => {
            let value = bounded(read(sdk.space_audit(&space_id), fence).await?)?;
            response.patches.push(Patch::SpaceAudit { context, value });
            return Ok(());
        }
        SpaceAction::Services { space_id, after_service, selected_service, after_rule } => {
            let policy = read(sdk.space_service_policy(&space_id), fence).await?;
            let value = service_page(policy, after_service.as_deref(), selected_service.as_deref(), after_rule.as_deref())?;
            response.patches.push(Patch::SpaceServices { context, value });
            return Ok(());
        }
        SpaceAction::BindService { space_id, service_id, request } => {
            write(sdk.bind_space_service(&space_id, &service_id, request), effect, fence).await?;
            service_selection = Some(service_id);
            Some(space_id)
        }
        SpaceAction::RevokeService { space_id, service_id, request } => {
            write(sdk.revoke_space_service(&space_id, &service_id, request), effect, fence).await?;
            service_selection = Some(service_id);
            Some(space_id)
        }
        SpaceAction::GrantServiceRule { space_id, service_id, request } => {
            write(sdk.grant_space_service_rule(&space_id, &service_id, request), effect, fence).await?;
            service_selection = Some(service_id);
            Some(space_id)
        }
        SpaceAction::RevokeServiceRule { space_id, service_id, rule_id, request } => {
            write(sdk.revoke_space_service_rule(&space_id, &service_id, &rule_id, request), effect, fence).await?;
            service_selection = Some(service_id);
            Some(space_id)
        }
    };
    let listing = bounded(read(sdk.spaces(), fence).await?)?;
    response.patches.push(Patch::Spaces(listing));
    if let Some(space_id) = selected {
        let details = read(sdk.space_details(&space_id), fence).await?;
        response.patches.push(Patch::SpaceDetails { context: context.clone(), value: detail_page(details, SpacePageCursor::default())? });
        if let Some(service) = service_selection {
            let policy = read(sdk.space_service_policy(&space_id), fence).await?;
            let value = service_page(policy, None, Some(&service), None)?;
            response.patches.push(Patch::SpaceServices { context, value });
        }
    }
    Ok(())
}
