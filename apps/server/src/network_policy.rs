//! Deployment-administrator membership management. Space delegation, invites,
//! business admission and transport are separate capabilities, not granted here.
use crate::{ApiError, AppState, access, now_ms};
use axum::{Json, extract::{Path, State}, http::{HeaderMap, StatusCode}};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::network::SignedNetworkGrant;
use nestlink_protocol::network::{GrantClaims, SCHEMA_VERSION};
use nestlink_storage::{StorageError, Store, accounts::Principal, network_policy::{
    NetworkAuthorityUpdate, NetworkGrantRevocation, NetworkMembershipRequest,
    NetworkMembershipRevocation, NetworkMembershipUpdate, TrustedNetworkPolicySnapshot,
}};
use nestlink_protocol::api::{
    NetworkAuthorityRequest as AuthorityRequest, NetworkMemberRequest as MemberRequest,
    NetworkRevokeMemberRequest as RevokeMemberRequest, NetworkIssueRequest as IssueRequest,
    NetworkRevokeGrantRequest as RevokeGrantRequest, NetworkPolicyView as PolicyView,
    NetworkMemberView as MemberView, NetworkGrantView as GrantView,
};
fn admin(store: &Store, token: &str, now_ms: u64) -> Result<Principal, StorageError> {
    let actor = store.authenticate(token, now_ms / 1000)?;
    if !actor.is_admin { return Err(StorageError::Forbidden); }
    Ok(actor)
}

async fn admin_access(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let token = access(headers)?;
    let check = token.clone();
    let principal = state.db(move |s| admin(s, &check, now_ms()?)).await?;
    // Authenticate first: random bearer strings cannot fill trusted rate slots.
    state.limit(&format!("network-policy/{}", principal.session_id))?;
    Ok(token)
}

fn policy_view(snapshot: &TrustedNetworkPolicySnapshot) -> PolicyView {
    let context = snapshot.verification();
    PolicyView {
        schema_version: SCHEMA_VERSION,
        deployment_id: context.deployment_id.into(),
        space_id: context.space_id.into(),
        authority_public_key: URL_SAFE_NO_PAD.encode(context.authority_key),
        revision: snapshot.revision(),
        policy_epoch: snapshot.policy_epoch(),
        observed_at_unix_ms: context.now_ms,
    }
}

fn member_view(snapshot: &TrustedNetworkPolicySnapshot, installation: &str) -> Result<MemberView, StorageError> {
    let member = snapshot.member(installation).ok_or(StorageError::Forbidden)?;
    Ok(MemberView {
        installation_id: member.installation_id().into(),
        public_key: URL_SAFE_NO_PAD.encode(member.public_key()),
        membership_epoch: member.membership_epoch(),
        role: member.role(), active: member.active(), policy: policy_view(snapshot),
    })
}

fn grant_view(signed: SignedNetworkGrant) -> Result<GrantView, StorageError> {
    let claims = GrantClaims::decode_canonical(&signed.claims)?;
    if !matches!(&claims, GrantClaims::Membership(_)) { return Err(StorageError::Forbidden); }
    Ok(GrantView { schema_version: SCHEMA_VERSION, grant_id: claims.scope().grant_id.clone(),
        claims: URL_SAFE_NO_PAD.encode(signed.claims), signature: URL_SAFE_NO_PAD.encode(signed.signature) })
}

pub(crate) async fn configure(State(state): State<AppState>, headers: HeaderMap,
    Path(space): Path<String>, Json(body): Json<AuthorityRequest>) -> Result<Json<PolicyView>, ApiError> {
    let token = admin_access(&state, &headers).await?;
    let public_key = state.network_signer.public_key();
    state.db(move |s| {
        let now = now_ms()?;
        let actor = admin(s, &token, now)?;
        let snapshot = s.configure_network_authority(&actor, NetworkAuthorityUpdate {
            space_id: space, expected_revision: body.expected_revision, public_key,
        }, now)?;
        Ok(Json(policy_view(&snapshot)))
    }).await
}

pub(crate) async fn policy(State(state): State<AppState>, headers: HeaderMap,
    Path(space): Path<String>) -> Result<Json<PolicyView>, ApiError> {
    let token = admin_access(&state, &headers).await?;
    state.db(move |s| {
        let now = now_ms()?;
        admin(s, &token, now)?;
        Ok(Json(policy_view(&s.network_policy_snapshot(&space, now)?)))
    }).await
}

pub(crate) async fn member(State(state): State<AppState>, headers: HeaderMap,
    Path((space, installation)): Path<(String,String)>) -> Result<Json<MemberView>, ApiError> {
    let token = admin_access(&state, &headers).await?;
    state.db(move |s| {
        let now = now_ms()?;
        admin(s, &token, now)?;
        Ok(Json(member_view(&s.network_policy_snapshot(&space, now)?, &installation)?))
    }).await
}

pub(crate) async fn set_member(State(state): State<AppState>, headers: HeaderMap,
    Path((space, installation)): Path<(String,String)>, Json(body): Json<MemberRequest>) -> Result<Json<MemberView>, ApiError> {
    let token = admin_access(&state, &headers).await?;
    state.db(move |s| {
        let now = now_ms()?;
        let actor = admin(s, &token, now)?;
        let snapshot = s.set_network_membership(&actor, NetworkMembershipUpdate {
            space_id: space, installation_id: installation.clone(), expected_policy_revision: body.expected_policy_revision,
            expected_membership_epoch: body.expected_membership_epoch, role: body.role,
        }, now)?;
        Ok(Json(member_view(&snapshot, &installation)?))
    }).await
}

pub(crate) async fn revoke_member(State(state): State<AppState>, headers: HeaderMap,
    Path((space, installation)): Path<(String,String)>, Json(body): Json<RevokeMemberRequest>) -> Result<Json<MemberView>, ApiError> {
    let token = admin_access(&state, &headers).await?;
    state.db(move |s| {
        let now = now_ms()?;
        let actor = admin(s, &token, now)?;
        let snapshot = s.revoke_network_membership(&actor, NetworkMembershipRevocation {
            space_id: space, installation_id: installation.clone(), expected_policy_revision: body.expected_policy_revision,
            expected_membership_epoch: body.expected_membership_epoch,
        }, now)?;
        Ok(Json(member_view(&snapshot, &installation)?))
    }).await
}

pub(crate) async fn issue(State(state): State<AppState>, headers: HeaderMap,
    Path((space, installation)): Path<(String,String)>, Json(body): Json<IssueRequest>) -> Result<(StatusCode,Json<GrantView>), ApiError> {
    let token = admin_access(&state, &headers).await?;
    let signer = state.network_signer.clone();
    let view = state.db(move |s| {
        let now = now_ms()?;
        let actor = admin(s, &token, now)?;
        let signed = s.issue_network_membership(&actor, &signer, NetworkMembershipRequest {
            space_id: space, installation_id: installation, grant_id: body.grant_id,
            expected_policy_epoch: body.expected_policy_epoch, expected_membership_epoch: body.expected_membership_epoch,
            expires_at_ms: body.expires_at_unix_ms,
        }, now)?;
        grant_view(signed)
    }).await?;
    Ok((StatusCode::CREATED,Json(view)))
}

pub(crate) async fn read_grant(State(state): State<AppState>, headers: HeaderMap,
    Path((space, grant)): Path<(String,String)>) -> Result<Json<GrantView>, ApiError> {
    let token = admin_access(&state, &headers).await?;
    state.db(move |s| {
        let now = now_ms()?;
        let actor = admin(s, &token, now)?;
        Ok(Json(grant_view(s.network_membership_grant(&actor, &space, &grant, now)?)?))
    }).await
}

pub(crate) async fn revoke_grant(State(state): State<AppState>, headers: HeaderMap,
    Path((space, grant)): Path<(String,String)>, Json(body): Json<RevokeGrantRequest>) -> Result<Json<PolicyView>, ApiError> {
    let token = admin_access(&state, &headers).await?;
    state.db(move |s| {
        let now = now_ms()?;
        let actor = admin(s, &token, now)?;
        let snapshot = s.revoke_network_grant(&actor, NetworkGrantRevocation {
            space_id: space, grant_id: grant, expected_revision: body.expected_revision,
        }, now)?;
        Ok(Json(policy_view(&snapshot)))
    }).await
}
