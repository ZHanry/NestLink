# ADR 0033: Signed route-set application recovery

Status: implemented source; exact-source Actions and product integration pending.

Applies to W14 / AC21 / AC22 / AC23. This ADR does not close those work packages
or replace their platform, input, media and target-device evidence.

## Decision and alternatives

Quinn `rebind_abstract` feasibility is documented by the private experiment in
ADR 0027. That experiment preserves a connection and its TLS exporter, but it
does not implement a production bilateral migration protocol or application
proof. Directly promoting the W13 standby would also reuse an allocation that
the node has already consumed and would bypass business-generation cleanup.

The first production recovery slice reuses the existing independent management
plane, device action signatures, generation CAS, durable reconnection receipt,
network-authority verification and remote business proof. It explicitly creates
a new business generation and new single-relay network authority. The old
connection is closed. Arbitrary TCP requests, input, clipboard writes, media
frames and audio are never forwarded from an old queue into the new runtime.

Normal optimization and complete old-path loss use the same bounded recovery
exchange. The latter requires no surviving old-path control stream. Actual
in-place migration, bilateral monotonic path-epoch commit and bounded old-path
draining remain separate W14 work. Each new generation in this slice starts at
the existing production path epoch 1.

## Wire compatibility and explicit opt-in

`ReconnectionChoice.network_recovery` is optional with serde default and omission
when absent. Legacy choices serialize in their original field order with exactly
their original bytes. Their signature transcript and receipt digest are unchanged.
The identity tests compare those bytes and independently verify the new signed
request and tamper rejection.

The extension has version 1 and the exact capability
`network-route-recovery-v1`. It does not claim `path-migration-v1`. Both SDK
endpoints explicitly opt in through the typed route-set recovery source and the
checked coordinator. The generic legacy host signature/coordinator rejects an
extension; an old binary rejects its unknown JSON field. Failure is terminal for
that attempt and cannot silently fall back to a legacy exchange with a different
nonce. A public release number does not negotiate this contract.

Both device signatures bind the previous business digest, next business and
lease generations, one random nonce, original space/set/path, an immutable
original claims fingerprint, transport group, previous path epoch, exact target
node and old route binding, and the original fixed path expiration. The
fingerprint hashes the canonical original PathGrant and the two TransitGrant
claims in allocation order. Changing availability cannot change that group.

## Roles, simultaneous triggers and lost acknowledgements

The controller is the only offer and fresh-reservation writer. The host can
trigger recovery at the same time; it waits for and signs the controller's one
choice. Its local scheduler suggestion need not match, but the accepted target
must exactly match one still-admissible member of its own original typed group.
The host never creates a competing nonce or target proposal.

The Store refuses replacement of an active offer and uses the existing
generation/lease CAS and exact submission receipt. Repeated offer and approval
are idempotent. A committed response can be recovered by the same submission or
the authenticated status endpoint. Duplicate approval racing with commit reads
the committed receipt. Late, different or revoked requests cannot replace it.

Fresh allocation, connectivity, path and transit UUIDs are derived with distinct
domains from the complete signed choice, using the existing SHA-256 and UUID
components. HTTP retries use the same IDs. After a lost reservation response,
the controller reads the exact committed authority rather than minting another
allocation. The host only reads that fixed allocation; it does not POST another
reservation. An original Pair/seen allocation, including a prepared hot standby,
is never readmitted for new business.

## Authorization, deadlines and resource ownership

`ContinuousRouteSetSession::into_recovery_source` consumes the unique old owner.
A live session requires a current unexpired scheduler proposal. Without one,
only an already stopped TransportLost or NetworkChanged generation is eligible.
The SDK waits for real ChannelRuntime cleanup and active/spare carrier receipts,
requires successful stop effects, and obtains the original ReconnectionBudget.
The application must complete its input/media/business owners before calling
this transfer. Other terminal reasons cannot recover.

The source retains the stopped original owner, its original budget, operator pin
and exact group. It is not a raw caller-supplied set of claims. Before signing,
the SDK checks independent local permissions, paths, capabilities and actual
media evidence using the existing Session binding code. Both device keys and the
management login remain bound to the old authorization.

The Store validates current membership, network policy/authority, original path
revocation and expiration, both original signed transits, and the exact target
node key/runtime/endpoint binding. A recovered single-relay reservation is
restricted to the signed target, derived IDs, original membership credentials
and exact original expiration. Each readback and node resource delegation also
checks that recovery parent, so original-group revocation invalidates the new
route and lost-response receipt. Original capacity promises remain held, and the
existing cumulative quota admission accounts for the new reservation without
refunding or resetting any original allocation or byte meter.

Legacy management authorization uses seconds; network snapshots enforce a
millisecond anti-rollback clock. The HTTP recovery handlers therefore use new
`*_at_ms` Store entries with actual milliseconds. Existing seconds APIs delegate
without changing legacy behavior. No rounding tolerance is introduced.

After obtaining the signed successor, the SDK performs a fresh pinned management
readback, mutual node challenge admission, inner QUIC TLS and existing business
session proof. Only the resulting ChannelRuntime is returned. It owns its actual
carrier and readback observer. A new NativeSessionControl uses the same lease and
real observation; it does not fabricate a media renewal coordinator.

`RecoveredNetworkSession` retains the receipt and original monotonic budget.
Cancellation during transport establishment goes through the existing owner so
physical cleanup can be joined. A subsequent network failure is terminal for
this first recovery slice; repeated multi-generation recovery needs a new
explicitly authorized source contract. Applications rebuild platform resources,
release inputs, discard old queues and request a fresh video keyframe.

## Validation and remaining evidence

The following source tests must run in Actions; none has been executed locally:

- identity legacy JSON byte compatibility, signed extension tampering, distinct
  deterministic request IDs and invalid capability/epoch/deadline rejection;
- Store two-device exchange, controller-only competing offer rejection, duplicate
  acknowledgements and exact lost-response receipt, fixed new target and IDs,
  original capacity retention, current node endpoint/space/fingerprint checks,
  expiration and original-group revocation of the successor;
- real HTTP, two NodeControl owners and an already-consumed TLS standby, complete
  original listener shutdown, simultaneous two-endpoint recovery, injected loss
  of offer/approval/commit/reservation responses, fresh node/inner/business proof,
  OS-file bytes sent on FileRead, permanent old-sender failure, shared stop and
  immediate physical UDP rebind;
- live source, terminal stop, cancellation and narrower local-consent rejection
  before a new offer can be signed.

Run the relevant identity, Store control route-set and SDK network_relay route-set
targets in the network workflow, along with format, clippy and protocol/schema
generation. Keep exact workflow/job/run/attempt/SHA and logs as evidence. App-core
owner driving, user-facing opt-in selection, actual platform input/media cleanup,
keyframe behavior, mixed installed versions, target devices and full in-place
migration are not established by these SDK tests.
