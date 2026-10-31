use super::*;
use nestlink_traversal::turn::TurnAuthorization;
mod network;
mod topology;
fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn clock(monotonic_ms: u64, unix_ms: u64) -> ClockSample {
    ClockSample {
        monotonic_ms,
        unix_ms,
    }
}
fn lease() -> NodeLeaseClaims {
    NodeLeaseClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 1,
        node_id: id(2),
        runtime_id: id(3),
        runtime_generation: 1,
        node_key_sha256: vec![1; 32],
        request_id: id(4),
        nonce: vec![1; 32],
        roles: vec![NodeRole::NodeRelay as i32],
        policy_revision: 2,
        lease_sequence: 3,
        issued_at_unix_ms: 10000,
        expires_at_unix_ms: 20000,
        server_forwarding_allowed: true,
        public_ingress_allowed: false,
        max_connections: 2,
        bytes_per_second: 10000,
    }
}
fn grant() -> RelayAllocationClaims {
    RelayAllocationClaims {
        node_endpoint_revision: 0,
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 1,
        allocation_id: id(5),
        session_id: id(6),
        node_id: id(2),
        runtime_id: id(3),
        runtime_generation: 1,
        node_key_sha256: vec![1; 32],
        controller_device_id: id(7),
        host_device_id: id(8),
        controller_key_sha256: vec![2; 32],
        host_key_sha256: vec![3; 32],
        controller_account_id: id(9),
        host_account_id: id(10),
        connection_generation: 1,
        policy_revision: 2,
        quota_revision: 1,
        session_binding_sha256: vec![4; 32],
        transports: vec![
            RelayTransport::QuicDatagram as i32,
            RelayTransport::WssStream as i32,
        ],
        grant_sequence: 1,
        issued_at_unix_ms: 10000,
        expires_at_unix_ms: 20000,
        bytes_per_second: 1000,
        bytes_per_allocation: 1600,
    }
}
fn snapshot(
    seq: u64,
    now: ClockSample,
    grants: Vec<RelayAllocationClaims>,
) -> NodeResourceSnapshotClaims {
    NodeResourceSnapshotClaims {
        topology_publications_json: Vec::new(),
        network_routes: Vec::new(),
        query: Some(NodeResourceQueryClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: id(1),
            security_epoch: 1,
            node_id: id(2),
            runtime_id: id(3),
            runtime_generation: 1,
            policy_revision: 2,
            lease_sequence: 3,
            request_id: id(11),
            request_sequence: seq,
            issued_at_unix_ms: now.unix_ms,
            expires_at_unix_ms: now.unix_ms + 1000,
        }),
        query_sha256: vec![5; 32],
        allocation_issuer: vec![6; 32],
        quota_revision: 1,
        issued_at_unix_ms: now.unix_ms,
        expires_at_unix_ms: now.unix_ms + 1000,
        allocations: grants,
    }
}
fn active(c: &RelayAllocationClaims) -> Result<Resources, ContractError> {
    let mut resources = Resources::default();
    resources.accept(
        snapshot(1, clock(0, 10000), vec![c.clone()]),
        &lease(),
        0,
        clock(0, 10000),
    )?;
    Ok(resources)
}
#[test]
fn delayed_snapshot_preserves_signed_expiry_without_deducting_response_latency_twice()
-> Result<(), ContractError> {
    for delay in [300, 600] {
        let mut c = grant();
        c.expires_at_unix_ms = 10800;
        let mut resources = Resources::default();
        resources.accept(
            snapshot(1, clock(0, 10000), vec![c.clone()]),
            &lease(),
            0,
            clock(delay, 10000 + delay),
        )?;
        let current = resources
            .snapshot
            .as_ref()
            .ok_or_else(|| error(ErrorCode::InternalError))?;
        assert_eq!(current.deadline, 1000);
        assert_eq!(current.entries[&c.allocation_id].deadline, 800);
        resources.inspect(&c, 0, clock(799, 10799))?;
        assert!(resources.inspect(&c, 0, clock(800, 10800)).is_err());
    }
    Ok(())
}
#[test]
fn snapshot_and_allocation_keep_request_caps_when_wall_and_monotonic_elapsed_time_differ()
-> Result<(), ContractError> {
    for (unix, snapshot_deadline, grant_deadline) in [(10000, 1000, 800), (10700, 900, 700)] {
        let mut c = grant();
        c.expires_at_unix_ms = 10800;
        let mut resources = Resources::default();
        resources.accept(
            snapshot(1, clock(0, 10000), vec![c.clone()]),
            &lease(),
            0,
            clock(600, unix),
        )?;
        let current = resources
            .snapshot
            .as_ref()
            .ok_or_else(|| error(ErrorCode::InternalError))?;
        assert_eq!(current.deadline, snapshot_deadline);
        assert_eq!(current.entries[&c.allocation_id].deadline, grant_deadline);
        resources.expire(clock(snapshot_deadline, unix));
        assert!(resources.snapshot.is_none());
    }
    assert!(deadline(0, 10000, 1000, clock(600, 10000)).is_err());
    assert!(deadline(u64::MAX - 500, 11000, 1000, clock(u64::MAX - 499, 10000)).is_err());
    Ok(())
}
#[test]
fn close_receipt_waits_for_both_actual_io_ends_and_uses_latest_grant_counters()
-> Result<(), ContractError> {
    let mut c = grant();
    let mut r = active(&c)?;
    let (a, _) = r.reserve(&c, 0, clock(0, 10000))?;
    let (b, stopped) = r.reserve(&c, 1, clock(0, 10000))?;
    r.admit(&c.allocation_id, &a, 42, clock(0, 10000), || Ok(()))?;
    c.grant_sequence += 1;
    c.issued_at_unix_ms = 10250;
    c.expires_at_unix_ms = 20250;
    r.accept(
        snapshot(2, clock(250, 10250), vec![c.clone()]),
        &lease(),
        250,
        clock(250, 10250),
    )?;
    assert!(r.close_after_io(&c.allocation_id, &a, Some(10260), false));
    assert!(*stopped.borrow());
    assert!(r.pending_closes.is_empty());
    assert!(r.close_after_io(&c.allocation_id, &b, Some(10270), false));
    let fact = &r
        .pending_closes
        .front()
        .ok_or_else(|| error(ErrorCode::InternalError))?
        .claims;
    assert_eq!(fact.observed_grant_sequence, 2);
    assert_eq!(
        (
            fact.opened_connections,
            fact.closed_connections,
            fact.admitted_bytes
        ),
        (2, 2, 42)
    );
    assert_eq!(fact.closed_at_unix_ms, 10270);
    assert!(!r.close_after_io(&c.allocation_id, &b, Some(10280), false));
    assert_eq!(r.pending_closes.len(), 1);
    assert!(r.reserve(&c, 0, clock(280, 10280)).is_err());
    Ok(())
}
#[test]
fn delayed_carrier_drain_and_cancelled_cleanup_never_refund_early() -> Result<(), ContractError> {
    for cancelled in [false, true] {
        let c = grant();
        let mut r = active(&c)?;
        let (a, _) = r.reserve(&c, 0, clock(0, 10000))?;
        let (b, _) = r.reserve(&c, 1, clock(0, 10000))?;
        r.close_after_io(&c.allocation_id, &a, None, true);
        r.close_after_io(&c.allocation_id, &b, None, true);
        assert_eq!(
            r.pairs[&c.allocation_id]
                .meter
                .counters()
                .closed_connections,
            2
        );
        assert!(r.pending_closes.is_empty());
        r.complete_io(&c.allocation_id, &a, Some(10010));
        assert!(r.pending_closes.is_empty());
        r.complete_io(
            &c.allocation_id,
            &b,
            if cancelled { None } else { Some(10020) },
        );
        assert_eq!(r.pending_closes.len(), usize::from(!cancelled));
        assert!(r.pairs.is_empty());
        assert!(r.reserve(&c, 0, clock(30, 10030)).is_err());
    }
    Ok(())
}
#[test]
fn unconfirmed_resource_destruction_cannot_create_a_signed_cleanup_fact()
-> Result<(), ContractError> {
    let c = grant();
    let mut r = active(&c)?;
    let (a, _) = r.reserve(&c, 0, clock(0, 10000))?;
    let (b, _) = r.reserve(&c, 1, clock(0, 10000))?;
    r.close(&c.allocation_id, &a);
    r.close_after_io(&c.allocation_id, &b, Some(10010), false);
    assert!(r.pending_closes.is_empty());
    assert!(r.pairs.is_empty());
    Ok(())
}
#[test]
fn failed_ack_queue_reserves_a_bounded_slot_for_each_admitted_allocation()
-> Result<(), ContractError> {
    let mut r = Resources::default();
    for n in 0..NODE_RELAY_CLOSE_PENDING {
        let mut c = grant();
        c.allocation_id = uuid::Uuid::new_v4().to_string();
        r.accept(
            snapshot(n + 1, clock(0, 10000), vec![c.clone()]),
            &lease(),
            0,
            clock(0, 10000),
        )?;
        let (a, _) = r.reserve(&c, 0, clock(0, 10000))?;
        assert!(r.close_after_io(&c.allocation_id, &a, Some(10000), false));
    }
    assert_eq!(r.pending_closes.len(), NODE_RELAY_CLOSE_PENDING as usize);
    let mut c = grant();
    c.allocation_id = uuid::Uuid::new_v4().to_string();
    r.accept(
        snapshot(
            NODE_RELAY_CLOSE_PENDING + 1,
            clock(0, 10000),
            vec![c.clone()],
        ),
        &lease(),
        0,
        clock(0, 10000),
    )?;
    assert_eq!(
        r.reserve(&c, 0, clock(0, 10000)).err().map(|e| e.code),
        Some(ErrorCode::CapacityExceeded)
    );
    r.pending_closes.pop_front(); // Only a verified ACK does this in the reporter.
    r.reserve(&c, 0, clock(0, 10000))?;
    assert_eq!(
        r.pairs.len() + r.pending_closes.len(),
        NODE_RELAY_CLOSE_PENDING as usize
    );
    Ok(())
}
#[test]
fn pair_shares_rate_and_lifetime_bytes_and_failed_enqueue_does_not_charge()
-> Result<(), ContractError> {
    let c = grant();
    let mut r = active(&c)?;
    let (a, _) = r.reserve(&c, 0, clock(0, 10000))?;
    let (b, _) = r.reserve(&c, 1, clock(0, 10000))?;
    r.admit(&c.allocation_id, &a, 600, clock(0, 10000), || Ok(()))?;
    assert!(
        r.admit(&c.allocation_id, &b, 401, clock(0, 10000), || Ok(()))
            .is_err()
    );
    assert!(
        r.admit(&c.allocation_id, &b, 400, clock(0, 10000), || Err::<(), _>(
            error(ErrorCode::CapacityExceeded)
        ))
        .is_err()
    );
    assert_eq!(
        r.pairs[&c.allocation_id].meter.counters().admitted_bytes,
        600
    );
    r.admit(&c.allocation_id, &b, 400, clock(0, 10000), || Ok(()))?;
    assert!(
        r.admit(&c.allocation_id, &a, 1, clock(0, 10000), || Ok(()))
            .is_err()
    );
    r.admit(&c.allocation_id, &a, 600, clock(600, 10600), || Ok(()))?;
    assert!(
        r.admit(&c.allocation_id, &b, 1, clock(601, 10601), || Ok(()))
            .is_err()
    );
    assert_eq!(
        r.pairs[&c.allocation_id].meter.counters().admitted_bytes,
        1600
    );
    Ok(())
}
#[test]
fn duplicate_role_stale_cleanup_and_closed_allocation_cannot_reset_usage()
-> Result<(), ContractError> {
    let c = grant();
    let mut r = active(&c)?;
    let (a, stopped_a) = r.reserve(&c, 0, clock(0, 10000))?;
    assert!(r.reserve(&c, 0, clock(0, 10000)).is_err());
    let (b, stopped_b) = r.reserve(&c, 1, clock(0, 10000))?;
    assert!(!r.close(&c.allocation_id, &id(12)));
    assert!(!*stopped_a.borrow());
    assert!(!*stopped_b.borrow());
    assert!(r.close(&c.allocation_id, &a));
    assert!(*stopped_a.borrow());
    assert!(*stopped_b.borrow());
    assert!(!r.close(&c.allocation_id, &a));
    assert!(
        r.admit(&c.allocation_id, &b, 1, clock(1, 10001), || Ok(()))
            .is_err()
    );
    assert!(r.reserve(&c, 0, clock(1, 10001)).is_err());
    assert!(r.close(&c.allocation_id, &b));
    assert!(r.pairs.is_empty());
    r.accept(
        snapshot(2, clock(100, 10100), vec![c.clone()]),
        &lease(),
        100,
        clock(100, 10100),
    )?;
    assert!(r.reserve(&c, 0, clock(100, 10100)).is_err());
    Ok(())
}
#[test]
fn same_grant_cannot_extend_monotonic_expiry_and_late_renewal_cannot_revive()
-> Result<(), ContractError> {
    let mut c = grant();
    c.expires_at_unix_ms = 10800;
    let mut r = active(&c)?;
    let (_, stopped) = r.reserve(&c, 0, clock(0, 10000))?;
    // A fresh snapshot with a lagging wall clock cannot recalculate the grant's deadline.
    r.accept(
        snapshot(2, clock(500, 10000), vec![c.clone()]),
        &lease(),
        500,
        clock(500, 10000),
    )?;
    assert_eq!(r.pairs[&c.allocation_id].deadline, 800);
    r.expire(clock(800, 10300));
    assert!(*stopped.borrow());
    c.grant_sequence += 1;
    c.issued_at_unix_ms = 10400;
    c.expires_at_unix_ms = 11400;
    r.accept(
        snapshot(3, clock(900, 10400), vec![c.clone()]),
        &lease(),
        900,
        clock(900, 10400),
    )?;
    assert!(*stopped.borrow());
    assert!(r.reserve(&c, 1, clock(900, 10400)).is_err());
    Ok(())
}
#[test]
fn higher_grant_renews_a_live_pair_without_resetting_its_byte_budget() -> Result<(), ContractError>
{
    let mut c = grant();
    c.expires_at_unix_ms = 10800;
    let mut r = active(&c)?;
    let (a, stopped) = r.reserve(&c, 0, clock(0, 10000))?;
    r.admit(&c.allocation_id, &a, 1000, clock(0, 10000), || Ok(()))?;
    c.grant_sequence += 1;
    c.issued_at_unix_ms = 10500;
    c.expires_at_unix_ms = 11500;
    r.accept(
        snapshot(2, clock(500, 10500), vec![c.clone()]),
        &lease(),
        500,
        clock(500, 10500),
    )?;
    assert_eq!(r.pairs[&c.allocation_id].deadline, 1500);
    r.admit(&c.allocation_id, &a, 600, clock(900, 10900), || Ok(()))?;
    assert!(!*stopped.borrow());
    assert!(
        r.admit(&c.allocation_id, &a, 1, clock(901, 10901), || Ok(()))
            .is_err()
    );
    Ok(())
}
#[test]
fn missing_revoked_changed_and_expired_snapshots_stop_idle_guards() -> Result<(), ContractError> {
    for change in 0..4 {
        let c = grant();
        let mut r = active(&c)?;
        let (_, stopped) = r.reserve(&c, 0, clock(0, 10000))?;
        match change {
            0 => r.accept(
                snapshot(2, clock(250, 10250), Vec::new()),
                &lease(),
                250,
                clock(250, 10250),
            )?,
            1 => {
                let mut next = snapshot(2, clock(250, 10250), Vec::new());
                next.quota_revision += 1;
                r.accept(next, &lease(), 250, clock(250, 10250))?;
            }
            2 => {
                let mut next = snapshot(2, clock(250, 10250), vec![c.clone()]);
                next.allocation_issuer = vec![7; 32];
                r.accept(next, &lease(), 250, clock(250, 10250))?;
            }
            _ => r.expire(clock(1000, 11000)),
        }
        assert!(*stopped.borrow());
        assert!(r.reserve(&c, 1, clock(1000, 11000)).is_err());
    }
    Ok(())
}
#[test]
fn replay_wrong_runtime_key_binding_and_unobserved_grants_are_rejected() -> Result<(), ContractError>
{
    let c = grant();
    for change in 0..6 {
        let mut r = active(&c)?;
        let mut next = snapshot(2, clock(100, 10100), vec![c.clone()]);
        match change {
            0 => {
                next.query
                    .as_mut()
                    .ok_or_else(|| error(ErrorCode::InvalidMessage))?
                    .request_sequence = 1
            }
            1 => {
                next.query
                    .as_mut()
                    .ok_or_else(|| error(ErrorCode::InvalidMessage))?
                    .runtime_id = id(12);
                next.allocations[0].runtime_id = id(12);
            }
            2 => next.allocations[0].node_key_sha256 = vec![7; 32],
            3 => next.allocations[0].bytes_per_allocation += 1,
            4 => next.allocations[0].expires_at_unix_ms += 1,
            _ => {
                next.query
                    .as_mut()
                    .ok_or_else(|| error(ErrorCode::InvalidMessage))?
                    .lease_sequence += 1
            }
        }
        assert!(
            r.accept(next, &lease(), 100, clock(100, 10100)).is_err(),
            "mutation {change}"
        );
    }
    let mut r = active(&c)?;
    let mut future = c.clone();
    future.grant_sequence += 1;
    assert!(r.reserve(&future, 0, clock(0, 10000)).is_err());
    let mut unknown = c.clone();
    unknown.allocation_id = id(12);
    assert!(r.reserve(&unknown, 0, clock(0, 10000)).is_err());
    Ok(())
}
fn live_guard(
    ttl: u64,
) -> Result<
    (
        RelayResourceReservation,
        watch::Sender<bool>,
        watch::Sender<bool>,
    ),
    Error,
> {
    live_guard_with_node_ttl(ttl, 10000)
}
fn live_guard_with_node_ttl(
    ttl: u64,
    node_ttl: u64,
) -> Result<
    (
        RelayResourceReservation,
        watch::Sender<bool>,
        watch::Sender<bool>,
    ),
    Error,
> {
    let key = NodeIdentity::generate();
    let master = nestlink_identity::PermitSigner::from_seed([91; 32]);
    let signer = master.node_policy_signer()?;
    let mut gate = NodeGate::new(
        id(1),
        id(2),
        id(3),
        key.public_key(),
        signer.public_key(),
        vec![NodeRole::NodeRelay],
    )?;
    let started = Instant::now();
    let now = sample(started)?;
    let mut l = lease();
    l.issued_at_unix_ms = now.unix_ms;
    l.expires_at_unix_ms = now.unix_ms + node_ttl;
    l.node_key_sha256 = digest(&key.public_key()).to_vec();
    let challenge = NodeChallenge {
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 1,
        node_id: id(2),
        node_key_sha256: l.node_key_sha256.clone(),
        request_id: l.request_id.clone(),
        nonce: l.nonce.clone(),
        expires_at_unix_ms: now.unix_ms + 5000,
    };
    gate.accept(
        &signer.sign(&l)?.encode_to_vec(),
        &challenge,
        now.monotonic_ms,
        now,
    )?;
    let mut c = grant();
    c.issued_at_unix_ms = now.unix_ms;
    c.expires_at_unix_ms = now.unix_ms + 10000;
    c.node_key_sha256 = l.node_key_sha256.clone();
    let mut s = snapshot(1, now, vec![c.clone()]);
    s.expires_at_unix_ms = now.unix_ms + ttl;
    s.query.as_mut().ok_or(Error::Control)?.expires_at_unix_ms = s.expires_at_unix_ms;
    let mut resources = Resources::default();
    resources.accept(s, &l, now.monotonic_ms, now)?;
    let (token, resource_stop) = resources.reserve(&c, 0, now)?;
    let resource_signal = resources
        .pairs
        .get(&c.allocation_id)
        .and_then(|p| p.slots[0].as_ref())
        .ok_or(Error::Control)?
        .stop
        .clone();
    let (node_signal, node_stop) = watch::channel(false);
    let mut meter = Meter::default();
    meter.reserve(l.max_connections)?;
    Ok((
        RelayResourceReservation {
            state: Arc::new(Mutex::new(Runtime {
                gate,
                meter,
                ready: true,
                service_shutdown: false,
                resources,
                service_resource_owner: None,
                service_usage: Arc::new(crate::service_usage::ServiceUsageStore::for_test()?),
                topology: Default::default(),
            })),
            started,
            allocation_id: c.allocation_id,
            token,
            controller: true,
            resource_stop,
            node_stop,
            io_stopped: false,
            io_deferred: false,
        },
        resource_signal,
        node_signal,
    ))
}
#[tokio::test]
async fn reservation_wait_observes_both_resource_and_global_stop_without_traffic()
-> Result<(), Error> {
    for global in [false, true] {
        let (guard, resource_signal, node_signal) = live_guard(1000)?;
        guard.check_live()?;
        let started = Instant::now();
        let task = async {
            resource_signal.send_replace(false); // A live snapshot update is not a stop.
            tokio::time::sleep(Duration::from_millis(30)).await;
            if global {
                node_signal.send_replace(true);
            } else {
                resource_signal.send_replace(true);
            }
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(guard.wait_stopped(), task);
        })
        .await
        .map_err(|_| Error::Control)?;
        assert!(started.elapsed() >= Duration::from_millis(20));
        assert!(guard.admit(1, || Ok(())).is_err());
    }
    Ok(())
}
#[tokio::test]
async fn resource_guard_owns_its_exact_expiry_timer_without_a_control_watchdog() -> Result<(), Error>
{
    let (guard, _resource, _node) = live_guard(500)?;
    guard.check_live()?;
    tokio::time::timeout(Duration::from_secs(1), guard.wait_stopped())
        .await
        .map_err(|_| Error::Control)?;
    assert!(guard.check_live().is_err());
    assert!(guard.admit(1, || Ok(())).is_err());
    Ok(())
}

struct CandidateFixture {
    control: NodeControl,
    claims: RelayAllocationClaims,
    ticket: Vec<u8>,
    endpoint: nestlink_identity::InstallationIdentity,
    lease: NodeLeaseClaims,
}
impl CandidateFixture {
    fn new(ticket_ttl: u64) -> Result<Self, Error> {
        Self::with_node_ttl(ticket_ttl, 10000)
    }
    fn with_node_ttl(ticket_ttl: u64, node_ttl: u64) -> Result<Self, Error> {
        let (guard, _resource_signal, node_signal) = live_guard_with_node_ttl(1000, node_ttl)?;
        let started = guard.started;
        let state = guard.state.clone();
        let now = sample(started)?;
        let issuer = nestlink_identity::PermitSigner::generate();
        let endpoint = nestlink_identity::InstallationIdentity::generate();
        let (claims, lease) = {
            let mut runtime = state.lock().map_err(|_| Error::Control)?;
            let l = runtime.gate.current(now)?.clone();
            let mut c = grant();
            c.node_key_sha256 = l.node_key_sha256.clone();
            c.controller_key_sha256 = endpoint.fingerprint().to_vec();
            c.issued_at_unix_ms = now.unix_ms;
            c.expires_at_unix_ms = now.unix_ms + ticket_ttl;
            let mut s = snapshot(2, now, vec![c.clone()]);
            s.allocation_issuer = issuer.public_key().to_vec();
            runtime.resources = Resources::default();
            runtime.resources.accept(s, &l, now.monotonic_ms, now)?;
            runtime.meter = Meter::default();
            (c, l)
        };
        let control = NodeControl {
            terminal_failure: Default::default(),
            state,
            started,
            stopped: guard.node_stop.clone(),
            stop_signal: node_signal,
            turn_authorization: Arc::new(TurnAuthorization::new(4).map_err(|_| Error::Control)?),
            pump: tokio::spawn(std::future::pending()),
            _usage_pump: tokio::spawn(async { Ok(()) }),
            runtime_id: id(3),
        };
        drop(guard); // Its old token cannot close a future reservation.
        Ok(Self {
            control,
            ticket: issuer.sign_relay_allocation(&claims)?.encode_to_vec(),
            claims,
            endpoint,
            lease,
        })
    }
    fn prepare(&self) -> Result<RelayEndpointCandidate, Error> {
        let nonce = [19; 32];
        let action = node_relay_transcript(
            &self.claims,
            &self.claims.controller_device_id,
            RelayTransport::WssStream,
            &nonce,
        )?;
        self.control.prepare_relay_endpoint(
            &self.ticket,
            RelayEndpointProof {
                device_id: &self.claims.controller_device_id,
                public_key: &self.endpoint.public_key(),
                transport: RelayTransport::WssStream,
                signature: &self.endpoint.sign_action(&action)?,
            },
            &nonce,
        )
    }
    fn renew_node(&self, now: ClockSample) -> Result<NodeLeaseClaims, Error> {
        let mut lease = self.lease.clone();
        lease.lease_sequence += 1;
        lease.request_id = id(12);
        lease.nonce = vec![12; 32];
        lease.issued_at_unix_ms = now.unix_ms;
        lease.expires_at_unix_ms = now.unix_ms + 10000;
        let challenge = NodeChallenge {
            schema_version: SCHEMA_VERSION,
            deployment_id: lease.deployment_id.clone(),
            security_epoch: lease.security_epoch,
            node_id: lease.node_id.clone(),
            node_key_sha256: lease.node_key_sha256.clone(),
            request_id: lease.request_id.clone(),
            nonce: lease.nonce.clone(),
            expires_at_unix_ms: now.unix_ms + 5000,
        };
        let signer = nestlink_identity::PermitSigner::from_seed([91; 32]).node_policy_signer()?;
        let mut runtime = self.control.state.lock().map_err(|_| Error::Control)?;
        runtime.gate.accept(
            &signer.sign(&lease)?.encode_to_vec(),
            &challenge,
            now.monotonic_ms,
            now,
        )?;
        Ok(lease)
    }
}
#[tokio::test]
async fn pending_legacy_candidates_cannot_revive_after_omission_expiry_or_resource_stop()
-> Result<(), Error> {
    for interruption in 0..3 {
        let f = CandidateFixture::new(5000)?;
        let candidate = f.prepare()?;
        let prepared = sample(f.control.started)?;
        let offset = if interruption == 1 { 1000 } else { 250 };
        let now = clock(prepared.monotonic_ms + offset, prepared.unix_ms + offset);
        {
            let mut runtime = f.control.state.lock().map_err(|_| Error::Control)?;
            let issuer = runtime
                .resources
                .snapshot
                .as_ref()
                .ok_or(Error::Control)?
                .claims
                .allocation_issuer
                .clone();
            match interruption {
                0 => {
                    let mut missing = snapshot(3, now, Vec::new());
                    missing.allocation_issuer = issuer.clone();
                    runtime
                        .resources
                        .accept(missing, &f.lease, now.monotonic_ms, now)?;
                }
                1 => runtime.resources.expire(now),
                _ => runtime.resources.stop(),
            }
            let mut restored = snapshot(4, now, vec![f.claims.clone()]);
            restored.allocation_issuer = issuer;
            runtime
                .resources
                .accept(restored, &f.lease, now.monotonic_ms, now)?;
            // New current authority is live, but the old preparation has lost
            // continuity and must fail even if its waiter never ran in the gap.
            runtime.resources.inspect(&f.claims, 0, now)?;
            assert!(
                candidate.check_at(&mut runtime, now).is_err(),
                "interruption {interruption}"
            );
        }
        assert!(candidate.reserve_at(Some(now)).is_err());
        assert_eq!(f.control.counters()?, Counters::default());
    }
    Ok(())
}
#[tokio::test]
async fn a_prepared_legacy_ticket_keeps_the_original_node_authorization_cutoff() -> Result<(), Error>
{
    let f = CandidateFixture::with_node_ttl(5000, 3000)?;
    let candidate = f.prepare()?;
    let prepared = sample(f.control.started)?;
    let lease = f.renew_node(clock(prepared.monotonic_ms + 500, prepared.unix_ms + 500))?;
    for sequence in 3..=9 {
        let offset = (sequence - 2) * 500;
        let now = clock(prepared.monotonic_ms + offset, prepared.unix_ms + offset);
        let mut runtime = f.control.state.lock().map_err(|_| Error::Control)?;
        let issuer = runtime
            .resources
            .snapshot
            .as_ref()
            .ok_or(Error::Control)?
            .claims
            .allocation_issuer
            .clone();
        let mut next = snapshot(sequence, now, vec![f.claims.clone()]);
        next.allocation_issuer = issuer;
        runtime
            .resources
            .accept(next, &lease, now.monotonic_ms, now)?;
    }
    let now = clock(prepared.monotonic_ms + 3500, prepared.unix_ms + 3500);
    {
        let mut runtime = f.control.state.lock().map_err(|_| Error::Control)?;
        runtime
            .gate
            .authorize_forwarding(NodeRole::NodeRelay, false, now)?;
        runtime.resources.inspect(&f.claims, 0, now)?;
    }
    assert!(candidate.reserve_at(Some(now)).is_err());
    assert_eq!(f.control.counters()?, Counters::default());
    Ok(())
}
#[tokio::test]
async fn preparation_grants_no_capacity_and_commit_rechecks_revocation_issuer_and_global_stop()
-> Result<(), Error> {
    for change in 0..3 {
        let f = CandidateFixture::new(1000)?;
        let candidate = f.prepare()?;
        assert_eq!(f.control.counters()?, Counters::default());
        let stopped = candidate.wait_stopped();
        if change == 2 {
            f.control.stop();
        } else {
            let now = sample(f.control.started)?;
            let mut runtime = f.control.state.lock().map_err(|_| Error::Control)?;
            let mut next = snapshot(
                3,
                now,
                if change == 0 {
                    vec![]
                } else {
                    vec![f.claims.clone()]
                },
            );
            next.allocation_issuer = if change == 0 {
                runtime
                    .resources
                    .snapshot
                    .as_ref()
                    .ok_or(Error::Control)?
                    .claims
                    .allocation_issuer
                    .clone()
            } else {
                vec![29; 32]
            };
            runtime
                .resources
                .accept(next, &f.lease, now.monotonic_ms, now)?;
        }
        tokio::time::timeout(Duration::from_secs(1), stopped)
            .await
            .map_err(|_| Error::Control)?;
        assert!(candidate.reserve().is_err(), "change {change}");
        assert_eq!(f.control.counters()?, Counters::default());
    }
    Ok(())
}
#[tokio::test]
async fn renewed_authority_and_a_lagging_wall_clock_cannot_extend_a_prepared_ticket()
-> Result<(), Error> {
    let f = CandidateFixture::new(800)?;
    let candidate = f.prepare()?;
    let original = candidate.deadline;
    let renew = clock(500, f.claims.issued_at_unix_ms + 500);
    {
        let mut runtime = f.control.state.lock().map_err(|_| Error::Control)?;
        let issuer = runtime
            .resources
            .snapshot
            .as_ref()
            .ok_or(Error::Control)?
            .claims
            .allocation_issuer
            .clone();
        let mut grant = f.claims.clone();
        grant.grant_sequence += 1;
        grant.issued_at_unix_ms = renew.unix_ms;
        grant.expires_at_unix_ms = renew.unix_ms + 1000;
        let mut next = snapshot(3, renew, vec![grant]);
        next.allocation_issuer = issuer;
        runtime
            .resources
            .accept(next, &f.lease, renew.monotonic_ms, renew)?;
        assert!(
            runtime
                .resources
                .snapshot
                .as_ref()
                .ok_or(Error::Control)?
                .entries[&f.claims.allocation_id]
                .deadline
                > original
        );
    }
    // The wall ticket and renewed authority both remain live; its fixed
    // preparation deadline alone must prevent this late commit.
    assert!(f.claims.expires_at_unix_ms > renew.unix_ms);
    assert!(
        candidate
            .reserve_at(Some(clock(original, renew.unix_ms)))
            .is_err()
    );
    assert_eq!(f.control.counters()?, Counters::default());
    Ok(())
}
#[tokio::test]
async fn pending_ticket_expiry_stops_its_waiter_without_a_control_watchdog() -> Result<(), Error> {
    let f = CandidateFixture::new(200)?;
    let candidate = f.prepare()?;
    tokio::time::timeout(Duration::from_secs(1), candidate.wait_stopped())
        .await
        .map_err(|_| Error::Control)?;
    assert!(candidate.reserve().is_err());
    assert_eq!(f.control.counters()?, Counters::default());
    Ok(())
}
