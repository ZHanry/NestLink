//! Typed management calls shared by native and browser clients. A response
//! envelope is not a verified network connection or a business permission.
use super::*;
use nestlink_identity::network::SignedNetworkGrant;
use nestlink_protocol::network::{CLAIM_BYTES, GrantClaims, SCHEMA_VERSION as NETWORK_SCHEMA};
mod authority;
mod network_access;
mod offline;
pub use offline::ConsumedOfflineBundle;
mod route_sets;
mod subnet;
mod wireguard;

fn base(space: &str) -> Result<String, SdkError> {
    if !valid_id(space) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("/network/spaces/{space}"))
}
fn member(space: &str, installation: &str) -> Result<String, SdkError> {
    if !valid_id(installation) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("{}/members/{installation}", base(space)?))
}
fn grant(space: &str, grant: &str) -> Result<String, SdkError> {
    if !valid_id(grant) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("{}/grants/{grant}", base(space)?))
}
fn path(space: &str, path: &str) -> Result<String, SdkError> {
    if !valid_id(path) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("{}/paths/{path}", base(space)?))
}
fn relay(space: &str, allocation: &str) -> Result<String, SdkError> {
    if !valid_id(allocation) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("{}/relays/{allocation}", base(space)?))
}

/// Decode exact bounded bytes for independent verification. This function does
/// not check a signature, current policy, member binding or business authority.
pub fn decode_network_grant(view: &NetworkGrantView) -> Result<SignedNetworkGrant, SdkError> {
    if view.schema_version != NETWORK_SCHEMA
        || view.claims.len() > CLAIM_BYTES.div_ceil(3) * 4
        || view.signature.len() != 86
    {
        return Err(SdkError::Invalid);
    }
    let signed = SignedNetworkGrant {
        claims: URL_SAFE_NO_PAD
            .decode(&view.claims)
            .map_err(|_| SdkError::Invalid)?,
        signature: URL_SAFE_NO_PAD
            .decode(&view.signature)
            .map_err(|_| SdkError::Invalid)?,
    };
    let claims = GrantClaims::decode_canonical(&signed.claims)?;
    if claims.scope().grant_id != view.grant_id || signed.signature.len() != 64 {
        return Err(SdkError::Invalid);
    }
    Ok(signed)
}

impl Sdk {
    /// Delegate only manager-approved publication prefixes to a registered node.
    /// The returned envelope still needs pinned authority verification.
    pub async fn issue_network_route_export(
        &self,
        space: &str,
        node: &str,
        request: NetworkRouteExportRequest,
    ) -> Result<NetworkGrantView, SdkError> {
        if !valid_id(node) {
            return Err(SdkError::Invalid);
        }
        self.required(
            Method::POST,
            &format!("{}/route-exports/{node}", base(space)?),
            Some(&request),
        )
        .await
    }
    pub async fn network_route_export(
        &self,
        space: &str,
        id: &str,
    ) -> Result<NetworkGrantView, SdkError> {
        if !valid_id(id) {
            return Err(SdkError::Invalid);
        }
        self.required(
            Method::GET,
            &format!("{}/route-export-grants/{id}", base(space)?),
            None::<&()>,
        )
        .await
    }
    pub async fn revoke_network_route_export(
        &self,
        space: &str,
        id: &str,
        expected_revision: u64,
    ) -> Result<NetworkPolicyView, SdkError> {
        if !valid_id(id) {
            return Err(SdkError::Invalid);
        }
        self.required(
            Method::DELETE,
            &format!("{}/route-export-grants/{id}", base(space)?),
            Some(&NetworkRevokeGrantRequest { expected_revision }),
        )
        .await
    }
    pub async fn network_policy(&self, space: &str) -> Result<NetworkPolicyView, SdkError> {
        self.required(
            Method::GET,
            &format!("{}/policy", base(space)?),
            None::<&()>,
        )
        .await
    }
    pub async fn configure_network_authority(
        &self,
        space: &str,
        expected_revision: u64,
    ) -> Result<NetworkPolicyView, SdkError> {
        self.required(
            Method::PUT,
            &format!("{}/authority", base(space)?),
            Some(&NetworkAuthorityRequest { expected_revision }),
        )
        .await
    }
    pub async fn network_member(
        &self,
        space: &str,
        installation: &str,
    ) -> Result<NetworkMemberView, SdkError> {
        self.required(Method::GET, &member(space, installation)?, None::<&()>)
            .await
    }
    pub async fn set_network_member(
        &self,
        space: &str,
        installation: &str,
        request: NetworkMemberRequest,
    ) -> Result<NetworkMemberView, SdkError> {
        self.required(Method::PUT, &member(space, installation)?, Some(&request))
            .await
    }
    pub async fn revoke_network_member(
        &self,
        space: &str,
        installation: &str,
        request: NetworkRevokeMemberRequest,
    ) -> Result<NetworkMemberView, SdkError> {
        self.required(
            Method::DELETE,
            &member(space, installation)?,
            Some(&request),
        )
        .await
    }
    pub async fn issue_network_membership(
        &self,
        space: &str,
        installation: &str,
        request: NetworkIssueRequest,
    ) -> Result<NetworkGrantView, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/grants", member(space, installation)?),
            Some(&request),
        )
        .await
    }
    pub async fn network_membership_grant(
        &self,
        space: &str,
        id: &str,
    ) -> Result<NetworkGrantView, SdkError> {
        self.required(Method::GET, &grant(space, id)?, None::<&()>)
            .await
    }
    pub async fn revoke_network_membership_grant(
        &self,
        space: &str,
        id: &str,
        expected_revision: u64,
    ) -> Result<NetworkPolicyView, SdkError> {
        self.required(
            Method::DELETE,
            &grant(space, id)?,
            Some(&NetworkRevokeGrantRequest { expected_revision }),
        )
        .await
    }
    pub async fn issue_network_remote_path(
        &self,
        space: &str,
        request_id: &str,
        request: NetworkRemotePathRequest,
    ) -> Result<NetworkRemotePathView, SdkError> {
        if !valid_id(request_id) {
            return Err(SdkError::Invalid);
        }
        self.required(
            Method::POST,
            &format!("{}/remote/{request_id}/paths", base(space)?),
            Some(&request),
        )
        .await
    }
    pub async fn network_remote_path(
        &self,
        space: &str,
        id: &str,
    ) -> Result<NetworkRemotePathView, SdkError> {
        self.required(Method::GET, &path(space, id)?, None::<&()>)
            .await
    }
    pub async fn revoke_network_remote_path(&self, space: &str, id: &str) -> Result<(), SdkError> {
        self.call::<_, serde_json::Value>(Method::DELETE, &path(space, id)?, None::<&()>, true)
            .await
            .map(|_| ())
    }
    /// Issue a separate immutable one-hop reservation using the current business
    /// permit and the participating device's existing allocation proof domain.
    /// Returned grants still require independent current-chain verification.
    pub async fn reserve_network_remote_relay(
        &self,
        space: &str,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        mut request: NetworkRemoteRelayRequest,
    ) -> Result<NetworkRemoteRelayView, SdkError> {
        let business = permit.claims();
        if business.deployment_id != self.trust.deployment_id
            || business.security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        if !valid_id(&request.allocation.allocation_id)
            || !valid_id(&request.allocation.node_id)
            || !valid_id(&request.transit_grant_id)
            || request.allocation.device_id != installation.device_id
        {
            return Err(SdkError::Invalid);
        }
        let actor = &self.login.as_ref().ok_or(SdkError::SignIn)?.principal;
        let transcript = nestlink_identity::relay::allocation_transcript(
            business,
            &actor.account_id,
            &installation.device_id,
            &request.allocation.allocation_id,
            &request.allocation.node_id,
        )?;
        request.allocation.signature =
            URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&transcript)?);
        self.required(
            Method::POST,
            &format!("{}/remote/{}/relays", base(space)?, business.session_id),
            Some(&request),
        )
        .await
    }
    pub async fn network_remote_relay(
        &self,
        space: &str,
        allocation_id: &str,
    ) -> Result<NetworkRemoteRelayView, SdkError> {
        self.required(Method::GET, &relay(space, allocation_id)?, None::<&()>)
            .await
    }
    pub async fn revoke_network_remote_relay(
        &self,
        space: &str,
        allocation_id: &str,
    ) -> Result<(), SdkError> {
        self.call::<_, serde_json::Value>(
            Method::DELETE,
            &relay(space, allocation_id)?,
            None::<&()>,
            true,
        )
        .await
        .map(|_| ())
    }

    /// Atomically reserve the two ordered nodes using the participating device's
    /// signature over the complete business/path/topology request.
    pub async fn reserve_network_remote_chain(
        &self,
        space: &str,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        mut request: NetworkRemoteRelayChainRequest,
    ) -> Result<NetworkRemoteRelayChainView, SdkError> {
        let business = permit.claims();
        if business.deployment_id != self.trust.deployment_id
            || business.security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        if request.device_id != installation.device_id {
            return Err(SdkError::Invalid);
        }
        let actor = &self.login.as_ref().ok_or(SdkError::SignIn)?.principal;
        let transcript = nestlink_identity::network::remote_chain_reservation_transcript(
            business,
            &actor.account_id,
            space,
            &request,
        )?;
        request.signature = URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&transcript)?);
        self.required(
            Method::POST,
            &format!(
                "{}/remote/{}/relay-chains",
                base(space)?,
                business.session_id
            ),
            Some(&request),
        )
        .await
    }
    pub async fn network_remote_chain(
        &self,
        space: &str,
        route: &str,
    ) -> Result<NetworkRemoteRelayChainView, SdkError> {
        if !valid_id(route) {
            return Err(SdkError::Invalid);
        }
        self.required(
            Method::GET,
            &format!("{}/relay-chains/{route}", base(space)?),
            None::<&()>,
        )
        .await
    }
    pub async fn revoke_network_remote_chain(
        &self,
        space: &str,
        route: &str,
    ) -> Result<(), SdkError> {
        if !valid_id(route) {
            return Err(SdkError::Invalid);
        }
        self.call::<_, serde_json::Value>(
            Method::DELETE,
            &format!("{}/relay-chains/{route}", base(space)?),
            None::<&()>,
            true,
        )
        .await
        .map(|_| ())
    }
}
