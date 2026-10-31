//! One selected member enters the existing proof, channels and cleanup owner.
//! The other member's availability never becomes this member's revocation.
use super::*;

impl Sdk {
    /// Connect a fixed candidate in its original transport group. Both peers
    /// must select the same allocation; this does not negotiate a switch.
    /// Continuous management observation checks this selected member and the
    /// original immutable group, without renewing either grant or byte budget.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_network_remote_route_candidate(
        &self,
        route: VerifiedRemoteRouteSet,
        selected: usize,
        bind: SocketAddr,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        setup: SessionSetup,
        address_policy: &AddressPolicy,
        cancel: watch::Receiver<bool>,
        deadline: Instant,
    ) -> Result<ChannelRuntime, SessionEstablishError> {
        self.connect_original_route_candidate(
            &route,
            selected,
            bind,
            local,
            peer_key,
            setup,
            address_policy,
            cancel,
            deadline,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn connect_original_route_candidate(
        &self,
        route: &VerifiedRemoteRouteSet,
        selected: usize,
        bind: SocketAddr,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        setup: SessionSetup,
        address_policy: &AddressPolicy,
        mut cancel: watch::Receiver<bool>,
        deadline: Instant,
    ) -> Result<ChannelRuntime, SessionEstablishError> {
        let permit = setup.session.current_verified_permit().clone();
        let candidate = route
            .candidate_for_admission(self, local, &permit, peer_key, selected)
            .ok_or(SdkError::Trust)?;
        let deadline = deadline.min(route.deadline);
        let revoked = BTreeSet::new();
        let context = NetworkVerification {
            authority_key: &route.pin.authority_key,
            deployment_id: &route.deployment,
            space_id: &route.pin.space_id,
            policy_epoch: route.policy_epoch,
            now_ms: unix_ms()?,
            revoked_grant_ids: &revoked,
        };
        let (authorization, _keep) = RouteAuthorization::remote(
            &context,
            &route.grants.path,
            &route.grants.connectivity,
            &route.grants.transits[selected],
            &permit,
        )
        .map_err(RemoteError::from)?;
        if authorization.binding_digest() != candidate.route_binding()
            || authorization.relay() != candidate.relay()
        {
            return Err(SdkError::Trust.into());
        }
        let node = candidate.node();
        let uri = url::Url::parse(node.endpoints.quic_uri.as_deref().ok_or(SdkError::Trust)?)
            .map_err(|_| SdkError::Invalid)?;
        let host = uri.host().ok_or(SdkError::Invalid)?;
        let port = uri
            .port()
            .filter(|port| *port != 0)
            .ok_or(SdkError::Invalid)?;
        let mut stop = setup.lifecycle.stop.clone();
        let addresses = tokio::select! { biased;
            _ = super::super::super::wait_setup_stop(&mut stop) => return Err(RemoteError::Stopped.into()),
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
        let mut pending =
            routed::AdjacencyEndpoint::bind_node(bind, &local.identity, candidate.relay())
                .map_err(SdkError::NodeQuic)?;
        let connected = tokio::select! { biased;
            _ = super::super::super::wait_setup_stop(&mut stop) => Err(SessionEstablishError::Remote(RemoteError::Stopped)),
            _ = cancelled(&mut cancel) => Err(SessionEstablishError::Cancelled),
            result = pending.connect_node(address, &local.identity, &local.device_id, candidate.allocation_id(), candidate.route_binding(), deadline) => result.map_err(SdkError::NodeQuic).map_err(SessionEstablishError::from),
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
                "/network/spaces/{}/route-sets/{}",
                route.pin.space_id, route.view.set_id
            ),
            fingerprint: route.fingerprint,
            deadline: route.deadline,
            kind: ReadbackKind::RouteSet { selected },
            cancel: Some(cancel.clone()),
        };
        let proved = super::super::super::authorize_remote_observed(
            RemoteRouteAuthority {
                context: &context,
                path: &route.grants.path,
                connectivity: &route.grants.connectivity,
                transit: &route.grants.transits[selected],
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
            _ = super::super::super::wait_setup_stop(&mut stop) => Err(SessionEstablishError::Remote(RemoteError::Stopped)),
            _ = cancelled(&mut cancel) => Err(SessionEstablishError::Cancelled),
            result = tokio::time::timeout_at(deadline, self.verified_network_remote_route_set(
                &route.pin, local, &permit, peer_key, &route.view.set_id,
            )) => result.map_err(|_| SdkError::Timeout).and_then(|value| value).map_err(SessionEstablishError::from),
        };
        let handoff = current.and_then(|current| {
            if super::super::super::setup_is_stopped(&stop) {
                return Err(RemoteError::Stopped.into());
            }
            if cancel_is_stopped(&cancel) {
                return Err(SessionEstablishError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(SdkError::Timeout.into());
            }
            if !route.is_current_for(self, local, &permit, peer_key)
                || current.fingerprint != route.fingerprint
                || current
                    .candidate_for_admission(self, local, &permit, peer_key, selected)
                    .is_none()
            {
                return Err(SdkError::Trust.into());
            }
            Ok(())
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
