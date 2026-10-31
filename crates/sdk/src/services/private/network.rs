//! Private-business adapter over the existing authenticated NRD1/NRD2 carrier.
use super::*;
use crate::native::AddressPolicy;
use nestlink_identity::network::{NetworkVerification, verify_private_service_grant};
use nestlink_protocol::network::{GrantClaims, PeerId};
use nestlink_transport_quic::routed::{AdjacencyEndpoint, RouteAuthorization, RouteRevocation, RoutedEstablishment, RoutedTransport};
use nestlink_transport_stream::owner::TaskOwner;
use std::{collections::BTreeSet, io, sync::Arc, time::Duration};
use tokio::time::Instant;

/// Local relay dialing scope. Signed endpoints also need this machine's
/// approval for private prefixes or loopback. Default is public unicast only.
/// These settings never change the fixed backend target or business rights.
#[derive(Clone, Default)]
pub struct PrivateServiceRelayPolicy {
    prefixes: Vec<String>,
    allow_loopback_node: bool,
}
impl PrivateServiceRelayPolicy {
    pub fn from_local_choice(prefixes: &[String], allow_loopback_node: bool) -> Result<Self, SdkError> {
        AddressPolicy::new(prefixes)?;
        Ok(Self { prefixes: prefixes.to_vec(), allow_loopback_node })
    }
}

pub(super) fn fingerprint(grant: &PrivateServiceGrant) -> Result<[u8;32], SdkError> {
    // A delegation may refresh its time; the original lease and complete
    // signed route remain immutable for the lifetime of this owner.
    Ok(digest(&serde_json::to_vec(&(&grant.lease, &grant.network))?))
}
pub(super) struct RelayOwner {
    transport: RoutedTransport,
    revocation: Arc<RouteRevocation>,
    observer: Option<TaskOwner>,
}
impl RelayOwner {
    pub(super) fn connection(&self) -> io::Result<&quinn::Connection> { self.transport.connection() }
    pub(super) fn request_close(&self) {
        self.revocation.revoke();
        self.transport.request_close();
        if let Some(observer) = &self.observer { observer.request_close(); }
    }
    pub(super) async fn close_and_wait(&mut self, deadline: Instant) -> io::Result<()> {
        self.request_close();
        if let Some(observer) = &self.observer { observer.close_and_wait(deadline).await?; }
        self.observer = None;
        self.transport.close_and_wait(deadline).await
    }
}
impl Drop for RelayOwner { fn drop(&mut self) { self.request_close(); } }
struct RevokeOnDrop(Arc<RouteRevocation>);
impl Drop for RevokeOnDrop { fn drop(&mut self) { self.0.revoke(); } }

pub(super) async fn connect(
    sdk: &Sdk,
    local: &DeviceIdentity,
    grant: &PrivateServiceGrant,
    policy: &PrivateServiceRelayPolicy,
) -> Result<RelayOwner, SdkError> {
    let policy_issuer: [u8;32] = URL_SAFE_NO_PAD.decode(&sdk.health.node_policy_issuer)
        .map_err(|_|SdkError::Trust)?.try_into().map_err(|_|SdkError::Trust)?;
    let (lease, path, connectivity, transits) = verify_private_service_grant(
        grant, &policy_issuer, &sdk.trust.deployment_id, private_wall_ms()?,
    )?;
    if lease.lease().claims().security_epoch != sdk.health.security_epoch { return Err(SdkError::Trust); }
    let c = lease.claims();
    let base = lease.lease().claims();
    let local_key = local.identity.public_key();
    if !((local.device_id == c.consumer_device_id && local_key == c.consumer_public_key)
        || (local.device_id == base.definition.host_device_id && local_key == c.host_public_key)) {
        return Err(SdkError::Trust);
    }
    let route = grant.network.relay.as_ref().ok_or(SdkError::Trust)?;
    let revoked = BTreeSet::new();
    let context = NetworkVerification { authority_key: &c.network_authority_key,
        deployment_id: &base.deployment_id, space_id: &c.space_id,
        policy_epoch: c.space_policy_epoch, now_ms: private_wall_ms()?, revoked_grant_ids: &revoked };
    let (authorization, revocation) = match transits.as_slice() {
        [transit] => RouteAuthorization::private_service(&context, &path, &connectivity, transit, &lease)?,
        [_, _] => RouteAuthorization::private_service_chain(&context, &path, &connectivity, &transits, &lease)?,
        _ => return Err(SdkError::Trust),
    };
    let local_peer = PeerId::from_public_key(&local_key);
    let index = if transits.len() == 1 || local_peer == authorization.peers().first { 0 }
        else if local_peer == authorization.peers().second { 1 } else { return Err(SdkError::Trust); };
    let GrantClaims::Transit(transit) = transits[index].claims() else { return Err(SdkError::Trust); };
    let node = &route.nodes[index];
    let endpoint = url::Url::parse(node.endpoints.quic_uri.as_deref().ok_or(SdkError::Trust)?)
        .map_err(|_|SdkError::Trust)?;
    let host = endpoint.host().ok_or(SdkError::Trust)?;
    let port = endpoint.port().filter(|p| *p != 0).ok_or(SdkError::Trust)?;
    let deadline = authorization.deadline().min(Instant::now()+Duration::from_secs(3));
    let client = sdk.client.clone();
    let origin = sdk.origin.clone();
    let token = Secret::from_text(sdk.login.as_ref().ok_or(SdkError::SignIn)?.access.expose().into());
    let grant_id = &grant.network.grant_id;
    let request_path = format!("{}/private-access/{grant_id}", resource("services", &base.service_id)?);
    let original = fingerprint(grant)?;
    let deployment = sdk.trust.deployment_id.clone();
    let security_epoch = sdk.health.security_epoch;
    let addresses = tokio::time::timeout_at(deadline, crate::native::resolve_signed_node_host(host, port))
        .await.map_err(|_|SdkError::Timeout)??;
    let address_policy = AddressPolicy::new(&policy.prefixes)?;
    if addresses.is_empty() || addresses.iter().any(|address| {
        let ip = address.ip().to_canonical();
        if ip.is_loopback() { !(policy.allow_loopback_node && node.endpoints.allow_loopback) }
        else { !address_policy.allows(ip) }
    }) { return Err(SdkError::Trust); }
    let address = addresses[0];
    let bind = if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().map_err(|_|SdkError::Invalid)?;
    let mut pending = if transits.len() == 1 {
        AdjacencyEndpoint::bind_node(bind, &local.identity, transit.relay)
    } else { AdjacencyEndpoint::bind_chain_node(bind, &local.identity, transit.relay) }.map_err(SdkError::NodeQuic)?;
    let binding = authorization.binding_digest();
    let adjacency = if transits.len() == 1 {
        pending.connect_node(address, &local.identity, &local.device_id, &transit.scope.grant_id, binding, deadline).await
    } else {
        pending.connect_chain_node(address, &local.identity, &transit.scope.grant_id, binding, deadline).await
    };
    let adjacency = match adjacency {
        Ok(adjacency) => adjacency,
        Err(error) => { revocation.revoke(); pending.close_and_wait(Instant::now()+Duration::from_secs(5)).await?; return Err(SdkError::NodeQuic(error)); }
    };
    let fixed_deadline = authorization.deadline();
    let mut establishing = RoutedEstablishment::new(authorization, adjacency);
    if let Err(error) = establishing.establish(&local.identity, deadline).await {
        revocation.revoke();
        establishing.close_and_wait(Instant::now()+Duration::from_secs(5)).await?;
        return Err(SdkError::NodeQuic(error));
    }
    let revocation = Arc::new(revocation);
    let transport = match establishing.take_transport() {
        Ok(transport)=>transport,
        Err(error)=>{
            revocation.revoke();
            establishing.close_and_wait(Instant::now()+Duration::from_secs(5)).await?;
            return Err(error.into());
        }
    };
    let mut owner = RelayOwner { transport, revocation: revocation.clone(), observer: None };
    let current = tokio::time::timeout_at(deadline, sdk.current_private_service_bundle(&base.service_id, grant_id)).await;
    let current_matches = match current { Ok(Ok((current,_))) => fingerprint(&current).ok() == Some(original), _=>false };
    if !current_matches || Instant::now() >= deadline {
        owner.close_and_wait(Instant::now()+Duration::from_secs(5)).await?;
        return Err(SdkError::Trust);
    }
    owner.observer = Some(TaskOwner::new(tokio::spawn(async move {
        let _revoke = RevokeOnDrop(revocation);
        let mut tick = tokio::time::interval_at(Instant::now()+Duration::from_secs(1),Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {biased; _=tokio::time::sleep_until(fixed_deadline)=>return, _=tick.tick()=>{} }
            let result = tokio::time::timeout_at(fixed_deadline.min(Instant::now()+Duration::from_secs(2)),
                crate::request::<PrivateServiceGrant>(&client,&origin,Method::GET,&request_path,None,Some(token.expose()))).await;
            let Ok(Ok(Some(current)))=result else { return; };
            if fingerprint(&current).ok()!=Some(original) { return; }
            let Ok((business,_,_,_))=verify_private_service_grant(&current,&policy_issuer,&deployment,private_wall_ms().unwrap_or(u64::MAX)) else { return; };
            if business.lease().claims().security_epoch != security_epoch { return; }
        }
    })));
    Ok(owner)
}
