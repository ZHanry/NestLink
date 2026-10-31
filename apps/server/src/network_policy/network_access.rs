//! Explicit destination-account approval, original graph readback and denial.
use super::*;
use nestlink_protocol::network_access::{
    NetworkAccessRequest, NetworkAccessStart, NetworkAccessView,
};
use nestlink_storage::network_policy::network_access::NetworkAccessBundle;

pub(super) fn view(bundle: NetworkAccessBundle) -> Result<NetworkAccessView, StorageError> {
    let [source, destination] = bundle.memberships;
    Ok(NetworkAccessView {
        source_membership: grant_view(source)?,
        destination_membership: grant_view(destination)?,
        access: grant_view(bundle.access)?,
        connectivity: grant_view(bundle.connectivity)?,
        path: grant_view(bundle.path)?,
        address_directory: bundle.address_directory,
        subnet_mappings: bundle
            .subnet_mappings
            .into_iter()
            .map(super::subnet::view)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub(crate) async fn issue_subnet(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(space): Path<String>,
    Json(body): Json<nestlink_protocol::subnet::management::SubnetNetworkAccessRequest>,
) -> Result<(StatusCode, Json<NetworkAccessView>), ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Issue).await?;
    let signer = state.network_signer.clone();
    let result = state
        .db(move |store| {
            let now = now_ms()?;
            let actor = store.authenticate(&token, now / 1000)?;
            let signer = store.network_authority_signer(&signer, &space, now)?;
            view(store.issue_subnet_network_access(&actor, &signer, &space, body, now)?)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

pub(crate) async fn issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(space): Path<String>,
    Json(body): Json<NetworkAccessRequest>,
) -> Result<(StatusCode, Json<NetworkAccessView>), ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Issue).await?;
    let signer = state.network_signer.clone();
    let result = state
        .db(move |store| {
            let now = now_ms()?;
            let actor = store.authenticate(&token, now / 1000)?;
            let signer = store.network_authority_signer(&signer, &space, now)?;
            view(store.issue_network_access(&actor, &signer, &space, body, now)?)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

pub(crate) async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, id)): Path<(String, String)>,
) -> Result<Json<NetworkAccessView>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Observe).await?;
    Ok(Json(
        state
            .db(move |store| {
                let now = now_ms()?;
                let actor = store.authenticate(&token, now / 1000)?;
                view(store.network_access(&actor, &space, &id, now)?)
            })
            .await?,
    ))
}

pub(crate) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, id)): Path<(String, String)>,
    Json(body): Json<RevokeGrantRequest>,
) -> Result<Json<PolicyView>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Revoke).await?;
    Ok(Json(
        state
            .db_revocation(move |store| {
                let now = now_ms()?;
                let actor = store.authenticate(&token, now / 1000)?;
                Ok(policy_view(&store.revoke_network_access(
                    &actor,
                    &space,
                    &id,
                    body.expected_revision,
                    now,
                )?))
            })
            .await?,
    ))
}

pub(crate) async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, id)): Path<(String, String)>,
    Json(body): Json<NetworkAccessStart>,
) -> Result<(StatusCode, Json<bool>), ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Issue).await?;
    state
        .db(move |store| {
            let now = now_ms()?;
            let actor = store.authenticate(&token, now / 1000)?;
            store.start_network_access(&actor, &space, &id, body, now)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(true)))
}
