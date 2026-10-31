//! The service issuer pins the independent network signer in the business
//! lease. Fresh authenticated management readback supplies policy currentness;
//! a peer's membership or remote-control permission cannot replace this chain.
use super::*;
use crate::network_management::decode_network_grant;
use nestlink_identity::network::{
    NetworkVerification, VerifiedMembership, VerifiedNetworkPath, private_service_path_peers,
    verify_network_grant,
};

pub(super) fn verify(
    lease: &VerifiedPrivateServiceLease,
    network: &PrivateServiceNetworkPath,
    now: u64,
) -> Result<VerifiedNetworkPath, SdkError> {
    let c = lease.claims();
    let base = lease.lease().claims();
    let usage: nestlink_protocol::service_plane::ServiceUsageBudgetGrantClaims =
        nestlink_protocol::service_plane::decode_service_message(
            &base.usage_grant.claims,
            nestlink_protocol::service_plane::SERVICE_USAGE_BYTES,
        )?;
    if usage.grant_id != network.grant_id {
        return Err(SdkError::Trust);
    }
    let revoked = std::collections::BTreeSet::new();
    let context = NetworkVerification {
        authority_key: &c.network_authority_key,
        deployment_id: &base.deployment_id,
        space_id: &c.space_id,
        policy_epoch: c.space_policy_epoch,
        now_ms: now,
        revoked_grant_ids: &revoked,
    };
    let verify = |view: &nestlink_protocol::api::NetworkGrantView| {
        Ok::<_, SdkError>(verify_network_grant(
            &decode_network_grant(view)?,
            &context,
        )?)
    };
    let consumer = VerifiedMembership::from_grant(
        verify(&network.consumer_membership)?,
        &context,
        &c.consumer_device_id,
        &c.consumer_public_key,
        c.consumer_membership_epoch,
    )?;
    let host = VerifiedMembership::from_grant(
        verify(&network.host_membership)?,
        &context,
        &base.definition.host_device_id,
        &c.host_public_key,
        c.host_membership_epoch,
    )?;
    let connectivity = verify(&network.connectivity)?;
    let path = VerifiedNetworkPath::from_grants(
        &context,
        [consumer, host],
        connectivity.clone(),
        verify(&network.path)?,
        lease.digest(),
    )?;
    private_service_path_peers(&context, &path, &connectivity, lease)?;
    path.check_route(&context, &[])?;
    Ok(path)
}
