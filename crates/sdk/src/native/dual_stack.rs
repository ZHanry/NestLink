use super::*;

pub(super) struct AdditionalFamily {
    pub(super) endpoint: quinn::Endpoint,
    pub(super) socket: Arc<DiscoverySocket>,
}

impl NativeEndpoint {
    /// One authorization owner for independent IPv4 and IPv6 sockets. An OS
    /// without one family retains the family it can actually bind; relay-only
    /// permits create neither socket.
    pub fn new_dual_stack(
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        permit: VerifiedPermit,
        stun_servers: Vec<SocketAddr>,
        address_policy: AddressPolicy,
    ) -> Result<Self, DialError> {
        let now = live(&permit)?;
        let deadline =
            Instant::now() + Duration::from_millis(permit.claims().expires_at_unix_ms - now);
        let v4 = SocketAddr::from(([0, 0, 0, 0], 0));
        let v6 = SocketAddr::from(([0_u16; 8], 0));
        let mut endpoint = match Self::new(
            v4,
            local,
            peer_key,
            permit.clone(),
            stun_servers.clone(),
            address_policy.clone(),
        ) {
            Ok(mut endpoint) => {
                if endpoint.socket.is_some() {
                    // IPv6 availability is a local fact, not authorization
                    // to change transport policy or retry a new permit.
                    if let Ok((endpoint_v6, socket)) = nestlink_transport_quic::discovery_endpoint(
                        v6,
                        &local.identity,
                        digest(peer_key),
                        stun_servers.clone(),
                    ) {
                        endpoint.additional_family = Some(AdditionalFamily {
                            endpoint: endpoint_v6,
                            socket,
                        });
                    }
                }
                endpoint
            }
            Err(DialError::Setup) => {
                Self::new(v6, local, peer_key, permit, stun_servers, address_policy)?
            }
            Err(error) => return Err(error),
        };
        endpoint.cap_authorization_deadline(deadline)?;
        endpoint.check()?;
        Ok(endpoint)
    }

    /// Capture the OS baseline once, before either family is constructed.
    pub fn new_dual_stack_monitored(
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        permit: VerifiedPermit,
        stun_servers: Vec<SocketAddr>,
        address_policy: AddressPolicy,
        monitor: &NetworkMonitor,
    ) -> Result<Self, DialError> {
        Self::with_monitor(monitor, || {
            Self::new_dual_stack(local, peer_key, permit, stun_servers, address_policy)
        })
    }

    pub(super) fn with_monitor(
        monitor: &NetworkMonitor,
        build: impl FnOnce() -> Result<Self, DialError>,
    ) -> Result<Self, DialError> {
        let receiver = monitor.subscribe();
        let baseline = *receiver.borrow();
        if !baseline.available {
            return Err(DialError::NetworkChanged);
        }
        let mut endpoint = build()?;
        endpoint.local_generation = baseline.generation;
        endpoint
            .network_generation
            .store(baseline.generation, Ordering::Release);
        endpoint.lifecycle.send_replace(baseline);
        let sockets = endpoint.discovery_sockets();
        for socket in &sockets {
            if baseline.generation > socket.generation() {
                socket
                    .invalidate_network(baseline.generation)
                    .map_err(|_| DialError::Setup)?;
            }
        }
        let lifecycle = endpoint.lifecycle.clone();
        let mut changes = receiver.clone();
        endpoint.monitor_task = Some(MonitorTask(
            nestlink_transport_stream::owner::TaskOwner::new(tokio::spawn(async move {
                loop {
                    let closed = changes.changed().await.is_err();
                    let mut state = *changes.borrow_and_update();
                    if closed {
                        state.available = false;
                        state.reason = Reason::Unavailable;
                    }
                    // A later OS event cannot undo explicit endpoint invalidation.
                    lifecycle.send_modify(|current| {
                        state.generation = state.generation.max(current.generation);
                        state.available &= current.available;
                        *current = state;
                    });
                    for socket in &sockets {
                        let generation =
                            state.generation.max(socket.generation().saturating_add(1));
                        let _ = socket.invalidate_network(generation);
                    }
                    if closed || !state.available {
                        break;
                    }
                }
            })),
        ));
        endpoint.monitor = Some((receiver, baseline.generation));
        endpoint.check()?;
        Ok(endpoint)
    }

    /// All bound local families, without inventing an IPv6 address on an OS
    /// where only IPv4 could be bound. The original local_addr API returns the
    /// primary member for callers that explicitly request one socket.
    pub fn local_addrs(&self) -> Result<Vec<SocketAddr>, DialError> {
        self.discovery_sockets()
            .iter()
            .map(|socket| socket.local_addr().map_err(|_| DialError::Setup))
            .collect()
    }

    pub(super) fn discovery_sockets(&self) -> Vec<Arc<DiscoverySocket>> {
        self.socket
            .iter()
            .cloned()
            .chain(
                self.additional_family
                    .iter()
                    .map(|family| family.socket.clone()),
            )
            .collect()
    }

    pub(super) fn endpoint_for(&self, address: SocketAddr) -> Option<&quinn::Endpoint> {
        if self
            .socket
            .as_ref()
            .and_then(|socket| socket.local_addr().ok())
            .is_some_and(|bound| bound.is_ipv4() == address.is_ipv4())
        {
            self.endpoint.as_ref()
        } else {
            self.additional_family
                .as_ref()
                .filter(|family| {
                    family
                        .socket
                        .local_addr()
                        .is_ok_and(|bound| bound.is_ipv4() == address.is_ipv4())
                })
                .map(|family| &family.endpoint)
        }
    }

    pub(super) async fn gather_direct_candidates(
        &self,
        stun_servers: Vec<SocketAddr>,
    ) -> Result<Vec<Candidate>, SessionEstablishError> {
        if stun_servers.len() > 4 {
            return Err(SdkError::Invalid.into());
        }
        let sockets = self.discovery_sockets();
        if sockets.is_empty() {
            return Err(SessionEstablishError::Binding);
        }
        let mut pending = FuturesUnordered::new();
        for socket in sockets {
            let bound = socket.local_addr().map_err(|_| DialError::Setup)?;
            let servers = stun_servers
                .iter()
                .copied()
                .filter(|server| server.is_ipv4() == bound.is_ipv4())
                .collect();
            let permit = &self.permit;
            let policy = &self.address_policy;
            pending.push(async move {
                let gathered =
                    crate::discovery::gather_with_policy(permit, socket.clone(), servers, policy)
                        .await;
                (bound.is_ipv4(), socket, gathered)
            });
        }
        let mut gathered_families = Vec::new();
        while let Some((ipv4, socket, gathered)) = pending.next().await {
            self.check()?;
            if let Ok(gathered) = gathered {
                if gathered.network_generation != self.local_generation {
                    return Err(DialError::NetworkChanged.into());
                }
                gathered_families.push((ipv4, socket, gathered));
            }
        }
        if gathered_families.is_empty() {
            return Err(SdkError::Invalid.into());
        }
        self.check()?;
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for (ipv4, socket, gathered) in gathered_families {
            // A cached first-family observation may expire while the second
            // family is still gathering. Validate the original owner/lifetime
            // immediately before publishing the combined candidates.
            gathered.check_current(&self.permit, &socket)?;
            if ipv4 {
                v4.extend(gathered.candidates);
            } else {
                v6.extend(gathered.candidates);
            }
        }
        Ok(interleave_families(v4, v6))
    }

    pub(super) async fn accept_direct(&self) -> Result<quinn::Connection, DialError> {
        let primary = self.endpoint.as_ref().ok_or(DialError::Binding)?;
        let accept = |endpoint: quinn::Endpoint| async move {
            endpoint
                .accept()
                .await
                .ok_or(DialError::Setup)?
                .await
                .map_err(|_| DialError::Setup)
        };
        let first = accept(primary.clone());
        let Some(other) = &self.additional_family else {
            return first.await;
        };
        let second = accept(other.endpoint.clone());
        tokio::pin!(first, second);
        tokio::select! {
            biased;
            result = &mut first => match result { Ok(connection) => Ok(connection), Err(_) => second.await },
            result = &mut second => match result { Ok(connection) => Ok(connection), Err(_) => first.await },
        }
    }
}

fn interleave_families(v4: Vec<Candidate>, v6: Vec<Candidate>) -> Vec<Candidate> {
    let mut first = v4.into_iter();
    let mut second = v6.into_iter();
    let mut candidates = Vec::new();
    loop {
        let next4 = first.next();
        let next6 = second.next();
        if next4.is_none() && next6.is_none() {
            break;
        }
        candidates.extend(next4);
        candidates.extend(next6);
        if candidates.len() >= CANDIDATE_COUNT as usize {
            break;
        }
    }
    bounded_unique(candidates, CANDIDATE_COUNT as usize)
}

#[cfg(test)]
#[path = "dual_stack/tests.rs"]
mod tests;
