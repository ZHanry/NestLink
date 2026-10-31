# Private Quinn carrier replacement feasibility experiment

Status: implemented source, not yet executed or verified. W14 and AC22 remain
incomplete. The experiment is absent from production builds and introduces no
negotiated migration capability or unchecked public route constructor.

## Existing component and necessary adaptation

The locked dependencies are Quinn 0.11.12 and quinn-proto 0.11.19. The mature
`Endpoint::rebind_abstract` interface replaces an endpoint's abstract UDP socket
and updates its existing connections. It keeps the previous socket only until
a packet arrives on the new socket, or the previous socket reports failure.
This avoids introducing another scheduler or independently implementing QUIC
migration. The existing virtual UDP adaptation remains the data plane.

Reviewed upstream interfaces:

- [Quinn endpoint at quinn-0.11.12](https://github.com/quinn-rs/quinn/blob/quinn-0.11.12/quinn/src/endpoint.rs):
  `new_with_abstract_socket`, `rebind_abstract`, previous-socket receive handling.
- [Quinn connection at quinn-0.11.12](https://github.com/quinn-rs/quinn/blob/quinn-0.11.12/quinn/src/connection.rs):
  `ConnectionEvent::Rebind`, `stable_id`, TLS exporter, connection statistics.
- [Protocol connection at quinn-proto-0.11.19](https://github.com/quinn-rs/quinn/blob/quinn-proto-0.11.19/quinn-proto/src/connection/mod.rs):
  `local_address_changed` changes the remote CID and schedules a ping. It does
  not reset the RTT, congestion or PMTU estimates.
- [Statistics at quinn-proto-0.11.19](https://github.com/quinn-rs/quinn/blob/quinn-proto-0.11.19/quinn-proto/src/connection/stats.rs):
  measured RTT, minimum RTT, congestion window/events, loss, PLPMTUD probes,
  current logical UDP payload size and UDP byte counters.

An alternative would be an independently implemented socket that switches
active queues and wakes Quinn readers and writers. The mature rebind interface
already provides this behavior, so the experiment uses it directly. Another
alternative creates a new inner connection on the second carrier; it cannot
prove original-connection continuity and is outside this experiment.

The private `routed::migration_experiment` module reuses the original
`RoutedSocket`, `RouteAuthorization::remote`, `AdjacencyEndpoint`,
`RelayForwarder`, bounded reassembly and physical socket/task receipts. A thin
measurement wrapper counts actual logical packets without changing their
payload, authorization, routing, timing or delivery semantics. Test fixture
provisioning supports two relays while retaining the same original verified
PathGrant, Permit, connectivity and transport group. Each relay has a distinct
original signed TransitGrant, unchanged lifetime and cumulative quota. The
single-relay fixture continues to use its original entry points and values.

## Explicit Actions experiment

Run on an ordinary GitHub-hosted Linux runner:

```sh
python3 -B scripts/network-rewrite-migration.py \
  --output "$RUNNER_TEMP/network-migration-evidence"
```

The script records the exact clean source SHA, locked dependency hash, fresh
executable SHA-256, Actions identity, commands, processes and execution facts.
It builds the transport-quic **libtest** executable with:

```sh
cargo test -p nestlink-transport-quic --locked --lib --no-run --message-format=json
```

Five roles are explicitly run with `--ignored --exact --nocapture
--test-threads=1`, prefixed with `routed::migration_experiment::`:
`prepare_fixture`, `first_process`, `second_process`, `relay_a_process` and
`relay_b_process`. Ordinary tests ignoring these roles provide no execution
evidence. Both dedicated cases must actually execute: `switch` and `cancel`.

Each case creates four isolated kernel network namespaces, two endpoints and
two independent relay processes. The endpoint processes run under the original
ordinary runner UID. There are no external/default routes or kernel IP
forwarding. Four real veth links form the two preauthenticated QUIC relay
paths. Kernel netem applies 5ms egress delay on the old path and 35ms delay,
1% loss and a 4Mbit rate on the new path. Link MTUs are 1280 and 1450 bytes.
Offloads are disabled for complete packet captures. Actual drop counters must
be nonzero; configuration values alone do not qualify the damage.

The endpoints create one pinned inner Quinn connection and open one
bidirectional application stream. Fresh phase-tagged bytes from an OS file
cross the first route and are verified with digest acknowledgments. After
both endpoints rebind to the already authenticated second carrier, the old
receiver tasks are joined, abstract socket release receipts are collected,
all four old physical UDP endpoints are closed and rebound, and every old
veth end is administratively down. Only then are another 262144 application
bytes transferred on the original stream. The original Quinn `stable_id`,
stream ID and TLS exporter digest must remain unchanged. The two endpoints
must agree on the exporter digest. Old logical counters must remain frozen.

For every transfer round the receipt records actual RTT, minimum RTT, cwnd,
congestion events, lost packets/bytes, sent/lost PLPMTUD probes, black-hole
counts, current logical MTU, packet sizes and byte counters. Measured logical
packets larger than 1200 bytes and actual PLPMTUD probes must occur. Complete
physical captures must contain full-sized outer Initial packets, bidirectional
traffic, no IP fragmentation, no owned application plaintext marker, and no
outer UDP payload larger than the existing 1200-byte carrier budget.

The cancellation case additionally polls an original stream read until it is
observably pending, requests close, requires the pending read to fail within
500ms and collects the original cleanup receipts. Each role reports two
physical UDP releases; endpoint roles also report two receiver joins and two
abstract socket release receipts. All original endpoint and relay ports must
actually rebind. A failed role, forced process cleanup, surviving namespace,
missing capture or missing receipt fails the experiment.

## Interpretation and outstanding boundaries

The experiment tests whether the existing locked Quinn connection can survive
replacement of two already authorized real carriers. Its out-of-band fixture
markers coordinate a laboratory replacement; they are not a production
authenticated migration proposal, acknowledgment or commit protocol. Production
`PATH_EPOCH` remains one, server migration settings retain their existing
semantics, and production SDK/remote entry points cannot invoke this test code.

NRD fragments logical packets of up to 1400 bytes onto an outer QUIC path fixed
at 1200 bytes. The inner PLPMTUD statistics therefore describe the logical
adaptation. They cannot establish physical dynamic PMTU convergence. RTT and
congestion trajectories are retained without assuming Quinn resets them on a
rebind or declaring convergence from a configuration field.

These are authenticated transport stream checks. They do not run business
SessionPermit endpoint proof, the FileRead worker, native input/media recovery,
arbitrary TCP replay, SDK signaling, public NATs or installed-device acceptance.
Simultaneous proposals, lost/late acknowledgments, path epochs, restricted new
carrier control, bounded drain, revoke/expiry during commit, input release,
media keyframes and safe application recovery remain W14 implementation and
acceptance work. No W14/AC22 pass may be inferred before exact-source Actions
execution, or from this feasibility experiment alone.
