//! Bind a standard-client key only after the original destination has approved
//! its packet graph. No HTTP endpoint installs WireGuard or creates OS routes.
use super::*;
use nestlink_protocol::wireguard::management::*;
use nestlink_storage::network_policy::wireguard::WireGuardClientBindingBundle;
fn view(bundle:WireGuardClientBindingBundle)->Result<WireGuardClientBindingView,StorageError> {
    Ok(WireGuardClientBindingView{binding:bundle.binding,packet_access:super::network_access::view(bundle.packet_access)?,policy:policy_view(&bundle.policy),total_byte_ceiling:bundle.total_byte_ceiling,committed_bytes:bundle.committed_bytes})
}
pub(crate) async fn issue(State(state):State<AppState>,headers:HeaderMap,Path(space):Path<String>,Json(request):Json<WireGuardClientBindingRequest>)->Result<(StatusCode,Json<WireGuardClientBindingView>),ApiError> {
    let token=member_access(&state,&headers,MemberOperation::Issue).await?;
    let signer=state.network_signer.clone();
    let result=state.db(move|store|{
        let now=now_ms()?;
        let actor=store.authenticate(&token,now/1000)?;
        let signer=store.network_authority_signer(&signer,&space,now)?;
        view(store.issue_wireguard_client_binding(&actor,&signer,&space,request,now)?)
    }).await?;
    Ok((StatusCode::CREATED,Json(result)))
}
pub(crate) async fn read(State(state):State<AppState>,headers:HeaderMap,Path((space,id)):Path<(String,String)>)->Result<Json<WireGuardClientBindingView>,ApiError> {
    let token=member_access(&state,&headers,MemberOperation::Observe).await?;
    let result=state.db(move|store|{
        let now=now_ms()?;
        let actor=store.authenticate(&token,now/1000)?;
        view(store.wireguard_client_binding(&actor,&space,&id,now)?)
    }).await?;
    Ok(Json(result))
}
pub(crate) async fn revoke(State(state):State<AppState>,headers:HeaderMap,Path((space,id)):Path<(String,String)>,Json(request):Json<WireGuardClientRevoke>)->Result<Json<PolicyView>,ApiError> {
    let token=member_access(&state,&headers,MemberOperation::Revoke).await?;
    let result=state.db_revocation(move|store|{
        let now=now_ms()?;
        let actor=store.authenticate(&token,now/1000)?;
        Ok(policy_view(&store.revoke_wireguard_client(&actor,&space,&id,request,now)?))
    }).await?;
    Ok(Json(result))
}
