# 0.8.0RC implementation checkpoint

This records development work on 2026-10-30, Asia/Shanghai. It does not establish
release eligibility or completion of an acceptance group.

## Current implementation

- The existing AppCore native start/recovery paths now retain the original
  endpoint and business runtime in one legacy owner. Closing joins business,
  carrier, monitor and physical socket receipts; an external holder can keep
  cleanup pending. The original stop reason and close budget survive retries.
- Membership authority, policy/member epochs, exact signed credentials,
  revocation and restore fences are persisted. Administrator HTTP APIs and
  typed SDK calls manage them without editing SQLite. A remote path is issued
  only for an existing approved, currently valid business request, both current
  memberships and direct business consent. Readback revalidates exact durable
  connectivity/path metadata and current business generation. This first
  issuance slice does not issue relay/transit or raw-IP authority.
- Web Network and nodes now has administrative enrollment, role change,
  removal and readback. Writes bind the actual policy revision and membership
  epoch; first initialization/enrollment is an explicit version-zero operation.
  Failed requests invalidate write snapshots and retain drafts. Scope/session
  changes discard snapshots; late replies cannot initiate the second request
  after logout or populate another panel. Role labels do not grant delegated
  space-management or business rights in this first administrative slice.
- The independently versioned one-hop datagram adapter uses existing
  Quinn/rustls, fixed authenticated adjacencies and the shared bounded assembler.
  Its 52-byte envelope binds the verified route transcript. Up to two 900-byte
  fragments carry inner packets up to 1400 bytes over outer 1200-byte QUIC UDP.
  See ADR 0003 for exact budgets, counters, expiry and limits.
- The opt-in SDK routed adapter derives route admission from the actual
  SessionSetup permit, checks local/remote device bindings, selects Relay only
  before proof and caps the business deadline. It runs the existing mutual
  business proof and returns existing bounded channels retaining the original
  routed transport owner. This is an explicit adapter API, not automatic
  enablement on the existing AppCore/desktop connect button.

## Observed Actions and pending checks

At source `5ede5d00f72deff02c4221f5741517182bb1452a`, network run
[41034692058](https://github.com/ZHanry/NestLink/actions/runs/41034692058)
finished with failure. Linux selected contract clippy/tests and independent
vectors passed; the full run failed formatting and socket experiments. Core
run [41034692064](https://github.com/ZHanry/NestLink/actions/runs/41034692064)
passed dependency, WASM, OpenAPI and platform jobs, while both full core jobs
stopped at formatting. These results do not verify the later changes.

The socket artifact records an actual 262144-byte FileRead match in the success
case and a pending next-chunk request plus client ExplicitExit in the cancel
case. Both host assertions failed because client code-0 close reached the host
before the driver's local stop; production maps that close to Revoked.
The one-way kernel blackhole passed and retained complete QUIC Initial captures,
static neighbor facts and actual dropped-packet counters. No failed case is
recorded as acceptance success.

The revised success/cancel experiments isolate teardown only after business
assertions and separately measure both local ExplicitExit states. A fourth,
unisolated peer-close experiment requires actual ApplicationClosed(code=0) and
the host's precise Revoked result. The protocol mapping has not changed.
Those changes require a new Actions run.

New transport tests exercise real three-node sockets, inner Initials, complete
1280-byte IPv6 datagrams, reverse boundaries, pin/grant/header/next-hop failures,
replay, shared budgets, expiry, revoke and physical rebind. New SDK tests perform
business proof, FileRead frames, denied Input and cleanup. These are source for
Actions execution; they do not substitute for independent network namespaces,
two relays, real NAT, OS TUN injection or complete AC10/AC11 evidence.

New real-browser tests use the compiled production controls, SDK, actual server
and SQLite to test explicit initialization, duplicate/conflicting writes, role
draft recovery, revoke/rejoin and late-reply isolation. Fixture middleware delays
actual GET replies without replacing their content or status. The receipt
validator requires all cases and the exact helper digest. Execution is pending.

## Remaining release work

W07 still needs server/node admission and durable grant reservations, production
activation, full carrier/PMTU/fault experiments and later route work. W18 still
needs named space lifecycle, one-use invitations, delegated owner/admin actions
and detailed rules. W08-W17 and the remaining network, gateway, proxy, TUN,
WireGuard, HA, offline, media and qualification work are not completed by these
slices. Missing implementation is not classified as an external blocker.

Real Windows/GPU/VPN coexistence targets, Android/iOS WireGuard clients,
independent NAT sites, public fixed ingress/two edges, signing and cross-day
24-hour qualification remain required external execution resources. Continue
independent implementation and Actions validation while preparing those cases.

The public product remains `0.7.0-rc.1`. No `0.8.0RC` tag or release has been
created. User authorization to publish and retain only main remains in force;
it does not change functionality/evidence gates. Local and remote heads were
checked as main only at source 5ede5d0; recheck after final delivery.
