//! Ordinary members may prepare only an already consented, fixed device pair.
use super::*;
use axum::extract::Query;
use nestlink_protocol::api::{NetworkRemotePreparationRequest, NetworkRemotePreparationView};
use nestlink_storage::network_policy::NetworkRemotePreparationBundle;

fn view(bundle: NetworkRemotePreparationBundle) -> Result<NetworkRemotePreparationView, StorageError> {
    let [controller, host] = bundle.memberships;
    let mut policy = policy_view(&bundle.snapshot);
    // Immutable observation time belongs to the original committed pair. Each
    // response still passes fresh transaction-local revocation/currentness.
    policy.observed_at_unix_ms = bundle.issued_at_ms;
    Ok(NetworkRemotePreparationView {
        request_id: bundle.request_id,
        connection_generation: bundle.binding.connection_generation,
        permit_sha256: bundle.binding.permit_sha256,
        policy,
        controller_membership: grant_view(controller)?,
        host_membership: grant_view(host)?,
    })
}

pub(crate) async fn prepare(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, request)): Path<(String, String)>,
    Json(body): Json<NetworkRemotePreparationRequest>,
) -> Result<Json<NetworkRemotePreparationView>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Issue).await?;
    let signer = state.network_signer.clone();
    let result = state.db(move |store| {
        let now = now_ms()?;
        let actor = store.authenticate(&token, now / 1000)?;
        let signer = store.network_authority_signer(&signer, &space, now)?;
        view(store.prepare_network_remote(&actor, &signer, &space, &request, body, now)?)
    }).await?;
    Ok(Json(result))
}

pub(crate) async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, request)): Path<(String, String)>,
    Query(binding): Query<NetworkRemotePreparationRequest>,
) -> Result<Json<NetworkRemotePreparationView>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Observe).await?;
    let result = state.db(move |store| {
        let now = now_ms()?;
        let actor = store.authenticate(&token, now / 1000)?;
        view(store.network_remote_preparation(&actor, &space, &request, binding, now)?)
    }).await?;
    Ok(Json(result))
}
