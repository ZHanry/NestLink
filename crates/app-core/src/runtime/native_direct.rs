//! Signed space admission reuses the original native endpoint and business owner.
use super::*;
use nestlink_protocol::api::NetworkRemotePathRequest;
use nestlink_sdk::network::routed::PinnedNetworkSpace;

fn path_id(permit: &VerifiedPermit, member_ids: [&str; 2], kind: u8) -> String {
    let mut input = b"NestLink/network/v1/product-direct-path\0".to_vec();
    input.extend_from_slice(&permit.digest());
    input.push(kind);
    for member in member_ids {
        input.extend_from_slice(member.as_bytes());
    }
    let digest = nestlink_identity::digest(&input);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn establish(
    client: &Client,
    identity: &DeviceIdentity,
    config: &NativeSessionConfig,
    permit: VerifiedPermit,
    peer_key: &[u8; 32],
    key: &NativeSessionKey,
    options: NativeSessionOptions,
    fence: sdk_call::DispatchFence,
) -> Result<NativeConnection, Failure> {
    let scope = config
        .space_path
        .as_ref()
        .ok_or_else(|| Failure::local(FailureKind::Invalid))?;
    scope
        .validate()
        .map_err(|_| Failure::local(FailureKind::Invalid))?;
    if scope.deployment_id != client.server.deployment_id
        || config.relay_node_id.is_some()
        || !options
            .local_paths
            .contains(nestlink_protocol::Path::Direct)
    {
        return Err(Failure::local(FailureKind::Trust));
    }
    let pin = PinnedNetworkSpace::new(scope.space_id.clone(), scope.authority_key)
        .map_err(Failure::from)?;
    let members = [
        &scope.controller_membership_grant_id[..],
        &scope.host_membership_grant_id[..],
    ];
    let path = path_id(&permit, members, 1);
    let network = config.network().subscribe();
    let baseline = *network.borrow();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let prepare = async {
        fence.check()?;
        if !key.is_host {
            let policy = client
                .sdk
                .network_policy(&scope.space_id)
                .await
                .map_err(Failure::from)?;
            if policy.deployment_id != scope.deployment_id
                || policy.space_id != scope.space_id
                || URL_SAFE_NO_PAD
                    .decode(&policy.authority_public_key)
                    .map_err(|_| Failure::local(FailureKind::Trust))?
                    .as_slice()
                    != scope.authority_key
            {
                return Err(Failure::local(FailureKind::Trust));
            }
            let now = unix_millis().ok_or_else(|| Failure::local(FailureKind::Trust))?;
            let mut expires = permit
                .claims()
                .expires_at_unix_ms
                .min(now.saturating_add(30_000));
            for id in members {
                let view = client
                    .sdk
                    .network_membership_grant(&scope.space_id, id)
                    .await
                    .map_err(Failure::from)?;
                let grant = nestlink_sdk::network_management::decode_network_grant(&view)
                    .map_err(Failure::from)?;
                let claims =
                    nestlink_protocol::network::GrantClaims::decode_canonical(&grant.claims)
                        .map_err(|_| Failure::local(FailureKind::Trust))?;
                expires = expires.min(claims.scope().expires_at_ms);
            }
            let request = NetworkRemotePathRequest {
                connectivity_grant_id: path_id(&permit, members, 2),
                path_grant_id: path.clone(),
                controller_membership_grant_id: members[0].into(),
                host_membership_grant_id: members[1].into(),
                expected_policy_epoch: policy.policy_epoch,
                expires_at_unix_ms: expires,
            };
            match client
                .sdk
                .issue_network_remote_path(&scope.space_id, &key.request_id, request)
                .await
            {
                Ok(_) => {}
                Err(nestlink_sdk::SdkError::Api(reqwest::StatusCode::CONFLICT, _)) => {}
                Err(error) => return Err(Failure::from(error)),
            }
        }
        let admission = loop {
            fence.check()?;
            match client
                .sdk
                .verified_network_remote_direct(&pin, identity, &permit, peer_key, &path)
                .await
            {
                Ok(admission) => break admission,
                Err(nestlink_sdk::SdkError::Api(
                    reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::NOT_FOUND,
                    _,
                )) if key.is_host => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => return Err(Failure::from(error)),
            }
        };
        if admission.membership_grant_ids() != members {
            return Err(Failure::local(FailureKind::Trust));
        }
        let media =
            native_recovery::prepare_media(client, identity, config, &permit, &fence).await?;
        Ok((admission, media))
    };
    let (admission, media) = tokio::select! { biased;
        _ = wait_for_fence_invalidation(fence.clone()) => return Err(Failure::local(FailureKind::NativeSessionCancelled)),
        result = tokio::time::timeout_at(deadline, prepare) => result.map_err(|_| Failure::local(FailureKind::Timeout))??,
    };
    fence.check()?;
    if !baseline.available
        || !network.borrow().available
        || network.borrow().generation != baseline.generation
    {
        return Err(Failure::local(FailureKind::NetworkChanged));
    }
    let policy = config
        .address_policy()
        .map_err(|_| Failure::local(FailureKind::Invalid))?;
    let endpoint = if config.bind_address == std::net::SocketAddr::from(([0, 0, 0, 0], 0)) {
        NativeEndpoint::new_dual_stack_monitored(
            identity,
            peer_key,
            permit,
            config.stun_servers.clone(),
            policy,
            config.network(),
        )
    } else {
        NativeEndpoint::new_monitored(
            config.bind_address,
            identity,
            peer_key,
            permit,
            config.stun_servers.clone(),
            policy,
            config.network(),
        )
    }
    .map_err(map_dial_failure)?;
    let (cancel, cancelled) = watch::channel(false);
    let connect = admission.establish(
        LegacyEndpoint::new(endpoint),
        &client.sdk,
        identity,
        peer_key,
        nestlink_sdk::native::NativeMediaSessionOptions {
            session: options,
            media,
            relay_node_id: None,
            pcp_gateway: config.pcp_gateway,
        },
        config.stun_servers.clone(),
        cancelled,
    );
    tokio::pin!(connect);
    let connected = tokio::select! { biased;
        _ = wait_for_fence_invalidation(fence.clone()) => None,
        _ = native_routed::wait_network_change(network.clone(), baseline.generation) => None,
        result = &mut connect => Some(result),
    };
    let Some(connected) = connected else {
        cancel.send_replace(true);
        if let Ok((mut session, _)) = connect.await {
            let _ = session
                .close_and_wait(
                    StopReason::ExplicitExit,
                    tokio::time::Instant::now() + Duration::from_secs(5),
                )
                .await;
        }
        return Err(Failure::local(FailureKind::NativeSessionCancelled));
    };
    let (mut session, admission) = connected.map_err(map_establish_failure)?;
    if fence.check().is_err()
        || !network.borrow().available
        || network.borrow().generation != baseline.generation
    {
        let _ = session
            .close_and_wait(
                StopReason::NetworkChanged,
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await;
        return Err(Failure::local(FailureKind::NetworkChanged));
    }
    Ok(NativeConnection::Direct {
        session: Box::new(session),
        admission: Box::new(admission),
        network_generation: baseline.generation,
    })
}
