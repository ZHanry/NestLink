//! Product-space commands reuse the account actor and the existing scoped SDK.
use nestlink_auth::Secret;
use nestlink_protocol::spaces::{service_publication::*, *};
use serde::{Deserialize, Serialize};

pub const SPACE_PAGE_SIZE: usize = 32;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpacePageCursor {
    pub after_member: Option<String>,
    pub after_device: Option<String>,
    pub after_invitation: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SpaceDetailsPage {
    pub space: SpaceView,
    pub members: Vec<SpaceMemberView>,
    pub devices: Vec<SpaceDeviceView>,
    pub invitations: Vec<SpaceInvitationView>,
    pub next_member: Option<String>,
    pub next_device: Option<String>,
    pub next_invitation: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SpaceServicePage {
    pub space: SpaceView,
    /// Listing rows omit rules; the selected binding has one bounded rule page.
    pub bindings: Vec<SpaceServiceBindingView>,
    pub selected: Option<SpaceServiceBindingView>,
    pub next_service: Option<String>,
    pub next_rule: Option<String>,
}

/// No Debug/Clone: invitation acceptance consumes its secret exactly once.
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum SpaceAction {
    List,
    Read {
        space_id: String,
        cursor: SpacePageCursor,
    },
    Create {
        name: String,
    },
    Archive {
        space_id: String,
        request: SpaceRevisionRequest,
    },
    UpdateMember {
        space_id: String,
        account_id: String,
        request: SpaceMemberUpdate,
    },
    RemoveMember {
        space_id: String,
        account_id: String,
        request: SpaceMemberRemoval,
    },
    JoinDevice {
        space_id: String,
        request: SpaceDeviceJoin,
    },
    RemoveDevice {
        space_id: String,
        installation_id: String,
        request: SpaceDeviceRemoval,
    },
    Invite {
        space_id: String,
        request: SpaceInvitationRequest,
    },
    RevokeInvitation {
        space_id: String,
        invitation_id: String,
        request: SpaceRevisionRequest,
    },
    Accept {
        space_id: String,
        invitation_id: String,
        #[serde(with = "crate::action::secret")]
        token: Secret,
    },
    Audit {
        space_id: String,
    },
    Services {
        space_id: String,
        after_service: Option<String>,
        selected_service: Option<String>,
        after_rule: Option<String>,
    },
    BindService {
        space_id: String,
        service_id: String,
        request: SpaceServiceBindingRequest,
    },
    RevokeService {
        space_id: String,
        service_id: String,
        request: SpaceRevisionRequest,
    },
    GrantServiceRule {
        space_id: String,
        service_id: String,
        request: SpaceServiceRuleRequest,
    },
    RevokeServiceRule {
        space_id: String,
        service_id: String,
        rule_id: String,
        request: SpaceRevisionRequest,
    },
}

impl SpaceAction {
    pub fn space_id(&self) -> Option<&str> {
        match self {
            Self::List | Self::Create { .. } => None,
            Self::Read { space_id, .. }
            | Self::Archive { space_id, .. }
            | Self::UpdateMember { space_id, .. }
            | Self::RemoveMember { space_id, .. }
            | Self::JoinDevice { space_id, .. }
            | Self::RemoveDevice { space_id, .. }
            | Self::Invite { space_id, .. }
            | Self::RevokeInvitation { space_id, .. }
            | Self::Accept { space_id, .. }
            | Self::Audit { space_id }
            | Self::Services { space_id, .. }
            | Self::BindService { space_id, .. }
            | Self::RevokeService { space_id, .. }
            | Self::GrantServiceRule { space_id, .. }
            | Self::RevokeServiceRule { space_id, .. } => Some(space_id),
        }
    }

    pub fn selects_space(&self) -> bool {
        matches!(
            self,
            Self::List | Self::Read { .. } | Self::Create { .. } | Self::Accept { .. }
        )
    }

    pub fn reads(&self) -> bool {
        matches!(
            self,
            Self::List | Self::Read { .. } | Self::Audit { .. } | Self::Services { .. }
        )
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn valid_input(&self) -> bool {
        use nestlink_protocol::valid_id;
        let optional = |id: &Option<String>| id.as_ref().is_none_or(|id| valid_id(id));
        let revision = |value: u64| value > 0 && value < i64::MAX as u64;
        let (space, valid) = match self {
            Self::List => return true,
            Self::Create { name } => {
                return !name.trim().is_empty()
                    && name.chars().count() <= 80
                    && !name.chars().any(char::is_control);
            }
            Self::Read { space_id, cursor } => (
                space_id,
                optional(&cursor.after_member)
                    && optional(&cursor.after_device)
                    && optional(&cursor.after_invitation),
            ),
            Self::Archive { space_id, request } => (space_id, revision(request.expected_revision)),
            Self::UpdateMember {
                space_id,
                account_id,
                request,
            } => (
                space_id,
                valid_id(account_id)
                    && revision(request.expected_revision)
                    && revision(request.expected_member_epoch),
            ),
            Self::RemoveMember {
                space_id,
                account_id,
                request,
            } => (
                space_id,
                valid_id(account_id)
                    && revision(request.expected_revision)
                    && revision(request.expected_member_epoch),
            ),
            Self::JoinDevice { space_id, request } => (
                space_id,
                valid_id(&request.installation_id)
                    && revision(request.expected_revision)
                    && request.expected_membership_epoch < i64::MAX as u64,
            ),
            Self::RemoveDevice {
                space_id,
                installation_id,
                request,
            } => (
                space_id,
                valid_id(installation_id)
                    && revision(request.expected_revision)
                    && revision(request.expected_membership_epoch),
            ),
            Self::Invite { space_id, request } => (
                space_id,
                revision(request.expected_revision)
                    && optional(&request.target_account_id)
                    && request.expires_at_unix_ms > 0
                    && request.expires_at_unix_ms <= i64::MAX as u64,
            ),
            Self::RevokeInvitation {
                space_id,
                invitation_id,
                request,
            } => (
                space_id,
                valid_id(invitation_id) && revision(request.expected_revision),
            ),
            Self::Accept {
                space_id,
                invitation_id,
                token,
            } => (
                space_id,
                valid_id(invitation_id)
                    && token.expose().len() == 43
                    && token
                        .expose()
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            ),
            Self::Audit { space_id } => (space_id, true),
            Self::Services {
                space_id,
                after_service,
                selected_service,
                after_rule,
            } => (
                space_id,
                optional(after_service) && optional(selected_service) && optional(after_rule),
            ),
            Self::BindService {
                space_id,
                service_id,
                request,
            } => (
                space_id,
                valid_id(service_id)
                    && revision(request.expected_revision)
                    && revision(request.expected_service_revision),
            ),
            Self::RevokeService {
                space_id,
                service_id,
                request,
            } => (
                space_id,
                valid_id(service_id) && revision(request.expected_revision),
            ),
            Self::GrantServiceRule {
                space_id,
                service_id,
                request,
            } => {
                let subject = match &request.subject {
                    SpaceServiceSubject::Account { account_id } => valid_id(account_id),
                    SpaceServiceSubject::Device { installation_id } => valid_id(installation_id),
                };
                (
                    space_id,
                    valid_id(service_id)
                        && subject
                        && revision(request.expected_revision)
                        && revision(request.expected_binding_epoch)
                        && request.port > 0
                        && request.expires_at_unix_ms > 0
                        && request.expires_at_unix_ms <= i64::MAX as u64,
                )
            }
            Self::RevokeServiceRule {
                space_id,
                service_id,
                rule_id,
                request,
            } => (
                space_id,
                valid_id(service_id) && valid_id(rule_id) && revision(request.expected_revision),
            ),
        };
        valid_id(space) && valid
    }
}
