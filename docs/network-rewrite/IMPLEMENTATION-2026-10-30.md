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
- NodeRelay now serves the independently versioned network ALPN on the same
  operator-configured UDP listener as legacy node QUIC. Current signed resource
  snapshots carry the original verified business permit and complete network
  chain. Dynamic mTLS pins, a fresh device-signed challenge, fixed route binding,
  direction/hop checks and the existing cumulative meter guard all forwarding.
  Node shutdown joins accepted tasks before waiting for the original physical
  socket receipt. New nodes reject unsupported network resource versions.
- The SDK has fresh management readback and pinned-space admission, validates
  the complete DNS answer against local destination consent, connects only the
  signed node, proves the business permission and keeps a revocation observer.
  Caller cancellation and sender loss cover node setup, inner QUIC and business
  proof; handoff rechecks terminal facts and the original absolute deadline.

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

At source `57fb9f030126a56e4994c91b1b08cd85631ef165`, network run
[41049646558](https://github.com/ZHanry/NestLink/actions/runs/41049646558)
failed at compilation/lint before either network experiment ran. The new listener
referred to rustls without a direct dependency, retained an unnecessary mutable
binding, and the storage readback had a needless transaction borrow. Independent
vectors succeeded. The pending repair moves the peer-identity type extraction
into the existing TLS crate and applies the reviewed Actions formatting patch.
No failed experiment is counted as passing or as external target evidence.

An additional SDK integration test now starts the actual management HTTP server,
node control connection, signed resource poll and dual-ALPN node listener. It
requests the route through production APIs, connects both SDK endpoints, proves
the existing business permit, transfers FileRead data, rejects Input, revokes the
route, joins cleanup and rebinds the original UDP addresses. It also cancels an
unpaired endpoint. Linux and ordinary-token Windows CI run it independently
before formatting. Its first Actions execution remains pending.

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

Source `bdbc0424acdced4fbdd1ad8c93ea15f812f44061` passed the routed NAT and
production socket experiments, including the previously failing peer-close
case. Both Linux and ordinary-token Windows passed nine space storage tests,
the actual HTTP SDK space flow, and all scoped discovery/dual-stack cases.
Linux contract clippy and selected-package tests passed. SDK routed tests
incorrectly read a stopped-session recovery budget from live sessions; the
following source uses a checked live-lease deadline observation while preserving
the recovery fence. The relay fixture's Drop-owner struct update and ICE
fixture's retained candidate/socket owners are also repaired in following
source. Actions formatting and generated OpenAPI were reviewed and imported.
Every repair remains pending verification. See
`evidence/development-run-bdbc042.json` for exact run identities and limits.

At source `e3a18a1e502767f1d7c267842a1817afcaac3fea`, the real routed
transport experiment passed success, blackhole and cancellation through one
authenticated relay and two Linux kernel SNAT gateways. The separate production
socket experiment passed mutual proof, actual 262144-byte FileRead, one-way
blackhole and cancellation, but its peer-close case failed because local cleanup
overwrote the observable connection cause. Linux contract clippy and the 14
evidence-tool tests passed; format, historical-schema fixtures and two
direct-only request fixtures failed. Core's 14 routed cases had three failures
and its new relay integration target failed compilation. Exact run/artifact
identities and limitations are recorded in
`evidence/development-run-e3a18a1.json`. These partial successes do not mark an
acceptance group or the later source as verified.

The next source slice adds production named-space/account/device/invitation
flows (`SPACE-PRODUCT-SLICE.md`), bounded current-interface discovery and STUN
provenance (ADR 0005), and a mature ICE to Quinn same-socket feasibility target
(ADR 0004). Each has Linux and ordinary-token Windows Actions checks before
formatting. The space browser helper uses the compiled production controls and
real HTTP/SQLite fixture. These checks and generated OpenAPI/format changes must
be reviewed from the new SHA before claiming a result. Detailed service ACLs,
production bilateral ICE signaling and external-network qualification remain
unfinished.

W07 has source for server/node admission and durable grant reservations; it still
needs same-source verification, production activation, full carrier/PMTU/fault
experiments and later route work. W18 now has named space lifecycle, one-use
invitations and delegated owner/admin source; detailed service rules and
exact-source verification remain. W08-W17 and the remaining network, gateway, proxy, TUN,
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

## Follow-up after exact-source 1249075 Actions

Core run 41057091566 and network run 41057091684 exposed remaining failures;
no complete acceptance group is marked passed. The new source publishes the
original routed carrier terminal facts before Quinn's inner endpoint teardown,
installs the existing lifecycle carrier observation and distinguishes synthetic
local INTERNAL_ERROR cleanup from a genuine protocol failure. A regression
covers revoke, transport loss and malformed protocol precedence.

The actual HTTP relay fixture now limits the route to the observed node lease
and sends all 256 KiB in existing 64-KiB-or-smaller FileRead chunks. ICE cleanup
requires successful physical rebind within the same original five-second budget,
allowing dependency-owned background tasks to release after Agent.close signals
them. The full browser lifecycle is paced at its existing production 30/60-second
space-session rate boundary; neither the service limit nor individual operation
and cleanup deadlines are increased. Full workspace clippy/tests run even when
an earlier scoped check or formatting gate fails; all failures still fail CI.

These repairs require new exact-source Actions evidence. The detailed run
observations and imported formatting digest are in
`evidence/development-run-1249075.json`. Production bilateral ICE signaling and
the unimplemented W10-W40 scope remain active work, not external validation gaps.

At source `4492f59febb5c4548e55b1f3eedc674fd01ad025`, both GitHub-hosted Linux
and ordinary-token Windows passed all scoped routed, actual HTTP/node relay,
ICE/Quinn original-socket cleanup, discovery, dual-stack and space checks. Both
platforms' selected contract clippy and tests also passed, including original
carrier failure precedence. Formatting still failed and its digest-verified
Actions patch was imported. Full Linux workspace checks independently exposed
two SDK lints, boxed outer WebSocket classification, native inbox and idle QUIC
recovery failures; these remain real gates. The next source repairs the first
three and continues investigation of the latter two.

The full production space browser lifecycle now passes. Its required rate-window
pacing consumes the historical fixture's original 120-second envelope before
media starts. The fixture reserves an explicit additional 61 seconds of management
setup in its one original deadline and records that budget. The 36-second steady
media observation, 15-second cleanup reserve, application leases and production
rate limit are preserved. This change still needs exact-source browser evidence.
See `evidence/development-run-4492f59.json` for run identities and limitations.

The following source addresses the remaining native inbox and idle QUIC recovery
failures. ADR 0006 specifies candidate-free, device-signed combined-relay
rendezvous through each endpoint's existing trusted management origin. Candidate
address validation and business proof stay mandatory; an added real AppCore
relay-only case requires no direct candidate or private destination consent.
Completed carrier cleanup now records its successful receipt before releasing
the failure sender. Only that empty post-receipt closure is cleanup; lost live
observation and recorded revocation still deny recovery. Protocol and lifecycle
regressions and complete real-session tests require matching Actions execution.

## Production follow-up on 2026-10-31

The next source fixes native inbox wake-up for authenticated address-free relay
signals; the previous filter required a literal candidate and left an approved
host asleep until its controller permit expired. Real Store regressions retain
signature, account/device, expiry and revocation checks. Browser membership and
space fixtures now consume actual HTTP responses through the existing bounded
CDP observer. Exact 8007458 observations, including the original failures and
CodeQL attempt-2 success, are in evidence/development-run-8007458.json.

W04 adds deployment-admin authority CAS, deterministic per-space key rotation,
retired-key history, permanent revocation and policy-epoch advance. Currentness
removes revoked paths from node snapshots instead of failing the entire poll.
W18 adds explicit space rules for already-approved service publication, enforcing
the same rule and deadline on issue, readback, renewal and node resources. Rule
revocation and membership changes drain existing publications. This is publication
permission, not the still-unimplemented authenticated private-service consumer ACL.

W09 now has production signed native ICE on the original mature candidate socket,
with a kernel filter for one approved remote tuple and existing Quinn/business
proof. Both signed device capabilities and the signed permit gate the dialect;
old registrations retain legacy. ADR 0008 records ownership, fallback, cleanup,
compatibility and single-candidate limits. The original prototype imports this
same socket adapter. New production tests require actual FileRead and rebinds.
All of this new source remains pending exact-source Actions, including formatting
and generated OpenAPI. No acceptance group, external execution or release result
is inferred from its implementation. Remaining W10-W40 scope stays active.

The exact-source 5f01330 runs are retained in
`evidence/development-run-5f01330.json`. The three network experiment jobs passed,
but native compilation, WASM/site compilation and two downgraded-schema fixtures
failed; browser/native execution was skipped by its failed site dependency.
The follow-up source imports verified Actions format/OpenAPI outputs and repairs
the mature ICE API/coercion, per-render Web handler capture and fixture table
cleanup. Management response expectations now bind to the next requestId so a
late earlier response cannot supply a later CAS assertion. Assertions, product
limits and cleanup budgets are preserved. These repairs need new Actions.
