//! Complete NRD2 readback and dialing through the existing business and
//! management observer owner. Grant bytes supplied by a peer are not readback.
use super::*;
use nestlink_identity::network::{RemoteChainBinding, remote_chain_binding};
use nestlink_protocol::{api::NetworkRemoteRelayChainView, network::PeerId};

/// An original, short-lived management readback for one permit, device and
/// login. The pinned authority verifies the ordered signed path and grants;
/// the authenticated management origin supplies the node UUID/endpoint mapping.
/// Its complete original view is frozen for handoff and continuous observation.
pub struct VerifiedRemoteChain {
    pin: PinnedNetworkSpace,
    deployment: String,
    security_epoch: u64,
    origin: String,
    login_session: String,
    local_device: String,
    local_key: [u8; 32],
    peer_key: [u8; 32],
    policy_epoch: u64,
    revoked: BTreeSet<String>,
    permit_digest: [u8; 32],
    path: VerifiedNetworkPath,
    connectivity: VerifiedNetworkGrant,
    transits: [VerifiedNetworkGrant; 2],
    binding: RemoteChainBinding,
    view: NetworkRemoteRelayChainView,
    fingerprint: [u8; 32],
    verified_at_ms: u64,
    fetched: Instant,
    deadline: Instant,
}

impl VerifiedRemoteChain {
    pub fn route_id(&self) -> &str {
        &self.view.route_id
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn node_ids(&self) -> [&str; 2] {
        [&self.view.nodes[0].node_id, &self.view.nodes[1].node_id]
    }

    fn context(&self) -> Result<NetworkVerification<'_>, SdkError> {
        Ok(NetworkVerification {
            authority_key: &self.pin.authority_key,
            deployment_id: &self.deployment,
            space_id: &self.pin.space_id,
            policy_epoch: self.policy_epoch,
            now_ms: unix_ms()?.max(self.verified_at_ms),
            revoked_grant_ids: &self.revoked,
        })
    }

    fn bound_to(
        &self,
        sdk: &Sdk,
        permit: &VerifiedPermit,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
    ) -> bool {
        sdk.trust.deployment_id == self.deployment
            && sdk.health.security_epoch == self.security_epoch
            && sdk.origin.as_str() == self.origin
            && sdk
                .login
                .as_ref()
                .is_some_and(|login| login.principal.session_id == self.login_session)
            && permit.digest() == self.permit_digest
            && local.device_id == self.local_device
            && local.identity.public_key() == self.local_key
            && peer_key == &self.peer_key
            && Instant::now() < self.deadline
            && self.fetched.elapsed() < Duration::from_secs(5)
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_handoff(
        &self,
        sdk: &Sdk,
        permit: &VerifiedPermit,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        current: &NetworkRemoteRelayChainView,
        stop: &watch::Receiver<Option<StopReason>>,
        cancel: &watch::Receiver<bool>,
        deadline: Instant,
    ) -> Result<(), SessionEstablishError> {
        let current_matches = self.bound_to(sdk, permit, local, peer_key)
            && response_digest(current)? == self.fingerprint;
        if super::super::setup_is_stopped(stop) {
            return Err(RemoteError::Stopped.into());
        }
        if cancel_is_stopped(cancel) {
            return Err(SessionEstablishError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(SdkError::Timeout.into());
        }
        if !current_matches {
            return Err(SdkError::Trust.into());
        }
        Ok(())
    }
}

impl Sdk {
    /// Read current management state, then authenticate the complete ordered
    /// chain against the operator pin and the exact business endpoint keys.
    pub async fn verified_network_remote_chain(
        &self,
        pin: &PinnedNetworkSpace,
        local: &DeviceIdentity,
        permit: &VerifiedPermit,
        peer_key: &[u8; 32],
        route_id: &str,
    ) -> Result<VerifiedRemoteChain, SdkError> {
        let started = Instant::now();
        let view = self.network_remote_chain(&pin.space_id, route_id).await?;
        self.verify_chain_readback(pin, local, permit, peer_key, route_id, view, started)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_chain_readback(
        &self,
        pin: &PinnedNetworkSpace,
        local: &DeviceIdentity,
        permit: &VerifiedPermit,
        peer_key: &[u8; 32],
        route_id: &str,
        view: NetworkRemoteRelayChainView,
        started: Instant,
    ) -> Result<VerifiedRemoteChain, SdkError> {
        let now = unix_ms()?;
        let business = permit.claims();
        let controller = business.controller_device_id == local.device_id;
        let host = business.host_device_id == local.device_id;
        let (controller_key, host_key) = if controller {
            (local.identity.public_key(), *peer_key)
        } else {
            (*peer_key, local.identity.public_key())
        };
        if controller == host
            || permit.issuer() != self.trust.permit_issuer
            || business.deployment_id != self.trust.deployment_id
            || business.security_epoch != self.health.security_epoch
            || business.controller_key_sha256 != digest(&controller_key)
            || business.host_key_sha256 != digest(&host_key)
            || business.issued_at_unix_ms > now
            || business.expires_at_unix_ms <= now
            || view.route_id != route_id
            || !nestlink_protocol::valid_id(route_id)
            || view.path.request_id != business.session_id
            || started.elapsed() >= Duration::from_secs(5)
            || view.nodes[0].node_id == view.nodes[1].node_id
            || view.topology_digests.contains(&[0; 32])
        {
            return Err(SdkError::Trust);
        }
        for node in &view.nodes {
            if !nestlink_protocol::valid_id(&node.node_id)
                || node.revision == 0
                || node.endpoints.quic_uri.is_none()
            {
                return Err(SdkError::Trust);
            }
            node.endpoints.validate()?;
        }
        let signed_path = crate::network_management::decode_network_grant(&view.path.path)?;
        let claims = GrantClaims::decode_canonical(&signed_path.claims)?;
        let policy_epoch = claims.scope().policy_epoch;
        let revoked = BTreeSet::new();
        // The epoch is authenticated by the operator key below. Only this
        // current authenticated management transaction supplies its freshness.
        let context = NetworkVerification {
            authority_key: &pin.authority_key,
            deployment_id: &self.trust.deployment_id,
            space_id: &pin.space_id,
            policy_epoch,
            now_ms: now,
            revoked_grant_ids: &revoked,
        };
        let mut members = Vec::with_capacity(2);
        for (member, installation, key) in [
            (
                &view.path.controller_membership,
                &business.controller_device_id,
                &controller_key,
            ),
            (
                &view.path.host_membership,
                &business.host_device_id,
                &host_key,
            ),
        ] {
            let grant = verify_network_grant(
                &crate::network_management::decode_network_grant(member)?,
                &context,
            )?;
            let GrantClaims::Membership(claims) = grant.claims() else {
                return Err(SdkError::Trust);
            };
            let epoch = claims.membership_epoch;
            members.push(VerifiedMembership::from_grant(
                grant,
                &context,
                installation,
                key,
                epoch,
            )?);
        }
        let connectivity = verify_network_grant(
            &crate::network_management::decode_network_grant(&view.path.connectivity)?,
            &context,
        )?;
        let path = VerifiedNetworkPath::from_grants(
            &context,
            [members.remove(0), members.remove(0)],
            connectivity.clone(),
            verify_network_grant(&signed_path, &context)?,
            permit.digest(),
        )?;
        if path.claims().policy.allow_direct {
            return Err(SdkError::Trust);
        }
        let transits = [
            verify_network_grant(
                &crate::network_management::decode_network_grant(&view.transits[0])?,
                &context,
            )?,
            verify_network_grant(
                &crate::network_management::decode_network_grant(&view.transits[1])?,
                &context,
            )?,
        ];
        for (index, grant) in transits.iter().enumerate() {
            let GrantClaims::Transit(transit) = grant.claims() else {
                return Err(SdkError::Trust);
            };
            if transit.route_id != route_id
                || transit.scope.grant_id != view.transits[index].grant_id
            {
                return Err(SdkError::Trust);
            }
        }
        let binding = remote_chain_binding(&context, &path, &connectivity, &transits, permit)?;
        let (authorization, _owner) =
            RouteAuthorization::remote_chain(&context, &path, &connectivity, &transits, permit)?;
        let deadline = authorization.deadline();
        let fingerprint = response_digest(&view)?;
        Ok(VerifiedRemoteChain {
            pin: pin.clone(),
            deployment: self.trust.deployment_id.clone(),
            security_epoch: self.health.security_epoch,
            origin: self.origin.as_str().into(),
            login_session: self
                .login
                .as_ref()
                .ok_or(SdkError::SignIn)?
                .principal
                .session_id
                .clone(),
            local_device: local.device_id.clone(),
            local_key: local.identity.public_key(),
            peer_key: *peer_key,
            policy_epoch,
            revoked,
            permit_digest: permit.digest(),
            path,
            connectivity,
            transits,
            binding,
            view,
            fingerprint,
            verified_at_ms: now,
            fetched: started,
            deadline,
        })
    }

    /// Select the endpoint's fixed first or last relay from its original chain,
    /// complete symmetric node possession and reuse the existing business proof
    /// owner. The management observer never renews this original grant deadline.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_network_remote_chain(
        &self,
        route: VerifiedRemoteChain,
        bind: SocketAddr,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        setup: SessionSetup,
        address_policy: &AddressPolicy,
        mut cancel: watch::Receiver<bool>,
        deadline: Instant,
    ) -> Result<ChannelRuntime, SessionEstablishError> {
        let permit = setup.session.current_verified_permit().clone();
        if !route.bound_to(self, &permit, local, peer_key) {
            return Err(SdkError::Trust.into());
        }
        let deadline = deadline.min(route.deadline);
        let context = route.context()?;
        let (authorization, _keep) = RouteAuthorization::remote_chain(
            &context,
            &route.path,
            &route.connectivity,
            &route.transits,
            &permit,
        )
        .map_err(RemoteError::from)?;
        if authorization.binding_digest() != route.binding.digest {
            return Err(SdkError::Trust.into());
        }
        let local_peer = PeerId::from_public_key(&local.identity.public_key());
        let index = if local_peer == route.binding.peers.first {
            0
        } else if local_peer == route.binding.peers.second {
            1
        } else {
            return Err(SdkError::Trust.into());
        };
        let node = &route.view.nodes[index];
        let allocation_id = &route.view.transits[index].grant_id;
        let uri = url::Url::parse(node.endpoints.quic_uri.as_deref().ok_or(SdkError::Trust)?)
            .map_err(|_| SdkError::Invalid)?;
        let host = uri.host().ok_or(SdkError::Invalid)?;
        let port = uri
            .port()
            .filter(|port| *port != 0)
            .ok_or(SdkError::Invalid)?;
        let mut stop = setup.lifecycle.stop.clone();
        let addresses = tokio::select! { biased;
            _ = super::super::wait_setup_stop(&mut stop) => return Err(RemoteError::Stopped.into()),
            _ = cancelled(&mut cancel) => return Err(SessionEstablishError::Cancelled),
            result = tokio::time::timeout_at(deadline, crate::native::resolve_signed_node_host(host, port)) => result.map_err(|_| SdkError::Timeout)??,
        };
        if addresses.iter().any(|address| {
            let ip = address.ip().to_canonical();
            if ip.is_loopback() {
                !(route.pin.allow_loopback_node && node.endpoints.allow_loopback)
            } else {
                !address_policy.allows(ip)
            }
        }) {
            return Err(SdkError::Trust.into());
        }
        let address = addresses
            .into_iter()
            .find(|address| address.is_ipv4() == bind.is_ipv4())
            .ok_or(SdkError::Invalid)?;
        let mut pending = nestlink_transport_quic::routed::AdjacencyEndpoint::bind_chain_node(
            bind,
            &local.identity,
            route.binding.relays[index],
        )
        .map_err(SdkError::NodeQuic)?;
        let connected = tokio::select! { biased;
            _ = super::super::wait_setup_stop(&mut stop) => Err(SessionEstablishError::Remote(RemoteError::Stopped)),
            _ = cancelled(&mut cancel) => Err(SessionEstablishError::Cancelled),
            result = pending.connect_chain_node(address, &local.identity, allocation_id, route.binding.digest, deadline) => result.map_err(SdkError::NodeQuic).map_err(SessionEstablishError::from),
        };
        let adjacency = match connected {
            Ok(adjacency) => adjacency,
            Err(error) => {
                pending
                    .close_and_wait(Instant::now() + Duration::from_secs(5))
                    .await
                    .map_err(RemoteError::Cleanup)?;
                return Err(error);
            }
        };
        let observer = RemoteRouteObserver {
            client: self.client.clone(),
            origin: self.origin.clone(),
            token: Secret::from_text(
                self.login
                    .as_ref()
                    .ok_or(SdkError::SignIn)?
                    .access
                    .expose()
                    .into(),
            ),
            path: format!(
                "/network/spaces/{}/relay-chains/{}",
                route.pin.space_id, route.view.route_id
            ),
            fingerprint: route.fingerprint,
            deadline: route.deadline,
            kind: ReadbackKind::Chain,
            cancel: Some(cancel.clone()),
        };
        let proved = super::super::authorize_remote_observed(
            RemoteChainAuthority {
                context: &context,
                path: &route.path,
                connectivity: &route.connectivity,
                transits: &route.transits,
            },
            adjacency,
            setup,
            local,
            peer_key,
            deadline,
            Some(observer),
            Some(cancel.clone()),
        )
        .await;
        let mut channels = match proved {
            Ok(channels) => channels,
            Err(error) => {
                if cancel_is_stopped(&cancel) && !matches!(&error, RemoteError::Cleanup(_)) {
                    return Err(SessionEstablishError::Cancelled);
                }
                return Err(error.into());
            }
        };
        let current = tokio::select! { biased;
            _ = super::super::wait_setup_stop(&mut stop) => Err(SessionEstablishError::Remote(RemoteError::Stopped)),
            _ = cancelled(&mut cancel) => Err(SessionEstablishError::Cancelled),
            result = tokio::time::timeout_at(deadline, self.network_remote_chain(&route.pin.space_id, &route.view.route_id)) => {
                result.map_err(|_| SdkError::Timeout).and_then(|value| value).map_err(SessionEstablishError::from)
            },
        };
        let handoff = current.and_then(|current| {
            route.validate_handoff(
                self, &permit, local, peer_key, &current, &stop, &cancel, deadline,
            )
        });
        if let Err(error) = handoff {
            let _ = channels.lease_control().stop(StopReason::Revoked);
            tokio::time::timeout(Duration::from_secs(5), channels.wait_stopped())
                .await
                .map_err(|_| RemoteError::Cleanup(io::ErrorKind::TimedOut.into()))??;
            return Err(error);
        }
        Ok(channels)
    }
}
