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

The b0ad444 follow-up passed both platforms' contract clippy/tests and the
original routed, relay, ICE feasibility, inbox and spaces checks. Production
native ICE shutdown still failed (Windows reports transport cleanup timeout;
Linux's old log does not locate its elapsed timeout). Web compilation exposed
another option ownership error and browser execution did not run. Exact failed
and successful evidence stays in `evidence/development-run-b0ad444.json`.

The next source preserves the ICE adapter during Quinn terminal-close draining,
then joins its original tasks and physically rebinds original sockets; Drop
still requests immediate task cleanup without a receipt. Native tests now name
each unchanged timeout stage and require the peer's terminal Revoked report.
The independent browser-contract job runs even if the site cannot build.

W04 now exposes current revision/epoch/public-key readback, signing-key rotation,
policy-epoch advance and explicitly confirmed permanent revoke in the production
Web membership screen. Every mutation uses the readback CAS, and stale scope or
login results are discarded. The real two-page browser helper requires rotation,
conflict/re-read, epoch advance, irreversible revoke and disabled terminal UI.

W11 adds schema32 independent advisory relay region and cost-weight metadata,
admin CAS/API/SDK/Web editing and unchanged old registration/lease/grant bytes.
Unknown cost remains unknown rather than zero. Separate candidate discovery
keeps the original signed discovery and its node-ID order; additional attributes
only describe its signed identities. Checked selection retains the original
five-second budget and revalidates permit, login, origin, device and node expiry.
Native automatic selection consumes the checked hints while retaining peer
rendezvous and previous-node priority. Fees remain advisory, not a hard budget.
An actual two-NodeControl test transfers business bytes on distinct routes and
requires revoking one node to preserve traffic on the other, held quota and
physical cleanup. Two independent deployed Linux hosts remain external evidence.

The new W09 Actions job builds the existing locked SDK codecs, then runs actual
SDK enrollment/approval/signed ICE, Quinn and bidirectional 256-KiB FileRead
frames in ordinary-user endpoint processes behind two actual Linux SNATs.
pcap/STUN/conntrack evidence must link the original physical candidate socket,
kernel-observed mapping and Quinn Initial; legacy fallback cannot qualify.
Blackhole and pending-read cancellation cases retain explicit physical cleanup.
These are new implemented-unverified sources, not passing AC13/14 evidence.
The W11 real-browser helper uses a separately registered relay-only node and
requires default unknown values, explicit zero, persisted readback, stale-writer
Conflict, revision-preserving clear, and delayed-response unmount/logout
isolation. Its bounded response observers must also close successfully. These
browser receipts remain pending the new exact-source Actions run.
Remaining advanced NAT, topology, migration, private service consumers, gateways,
media and final delivery scope stays active. No 0.8.0RC release has been created.

The 24be9e7 Actions run passed site/WASM compilation, both platforms' metadata
and candidate-unit regressions, and the original routed/socket experiments.
The real browser completed authority rotation, conflict, epoch advance and
permanent revoke; relay metadata reached default/zero/conflict but stopped at
clearing fields because the pinned browser driver's fill("") emitted no input
event. Its helper now uses real keyboard deletion and retains exact null/zero
request assertions. New native NAT roles did not execute because their diagnostic
tried to Debug-print a non-Debug Frame; that diagnostic is repaired.

Native ICE owner draining now completes within the existing test budget. The
new peer assertion must expect TransportLost, matching the existing authenticated
retry close code for a NetworkChanged stop; this does not imply revocation.
Locked webrtc-ice's srflx gatherer supplies a wildcard socket bind; the production
factory now resolves that local request to its already-selected interface while
retaining same-family, single-socket and approved-peer restrictions. The two-node
test still has failures, with stage-specific diagnostics added for the next run.

W11 adds a per-session Desktop relay UUID choice through backward-compatible
local IPC, Core and SDK, retaining it during recovery and both initial/refreshed
signed discovery. An explicit choice cannot use combined or another node; bad,
missing or revoked selections fail closed. New real business regressions and
Core input/compatibility checks are wired to both ordinary-token platform jobs.
These latest sources require new Actions; full W11 and release gates remain open.

The 76dbb0e Web run passed all production browser/native synthetic-owned media,
input, files, spaces, authority and relay-metadata checks, including null clear,
stale writers, logout/unmount isolation and six response-owner cleanup receipts.
The network run passed existing routed/socket/vector and scoped contract tests,
but native SNAT failed before permit issuance; the fixture now waits for actual
issuance and binds both peers to its digest. Both OS scoped native/session and
selection checks passed. Multi-node routing and full workspace failures remain
open, with HTTP and admission diagnostics added without changing limits. Exact
observations are in the separate 76dbb0e browser and network evidence records.

W10 starts an explicit PCP-only slice using crab_nat 0.8.1, with component
selection and limitations in ADR 0009. Core, Desktop, SDK and the server now
require independent default-off local and deployment consent. The mapping
retains the real ICE socket and nonce before cancelable requests; the existing
agent publishes only the acknowledged same-port tuple. Renewal cannot extend
the original authorization or change its signed tuple. Cleanup joins renewal,
requires exact deletion acknowledgment and physically releases original sockets.
Controlled UDP component, actual HTTP policy/config and historical-settings
regressions are wired to GitHub-hosted Windows/Linux jobs. These sources still
require exact-source compilation and execution. TCP/symmetric NAT/NAT-PMP/UPnP
and actual router qualification remain unimplemented or unverified as recorded.

The product and browser-fixture locks were generated exclusively by Actions run
41113590665, preserving all existing package identities, checksums and external
dependency edges. Original ZIP and receipt file hashes were verified before
import. The earlier derivation with unrelated edge drift was rejected. See
evidence/pcp-lock-derivation-f09ac21.json. Generated OpenAPI and formatting must
be refreshed from the integrated source; no release or acceptance is implied.

At 8186f75 the Linux contract lint/tests passed, including actual UDP PCP
component integration. Scoped SDK policy, pre-agent socket cleanup and private
server configuration reload also passed. The new field was missing from one
Core file-store test initializer; that fixture now also checks persistent local
PCP consent. Native SNAT clippy caught a binary-digest/String comparison; readback
now compares the exact original bytes. Verified Actions OpenAPI and formatter
outputs were imported. Full current results remain in development-run-8186f75.

Two-node establishment again returned HTTP 429. Short-lived database bursts
previously had no admission wait: the ninth concurrent call failed even if a
worker completed immediately afterwards. The source keeps eight blocking
workers and adds at most eight async waiters with a 200ms admission deadline.
Overflow/expiry still fails 429; cancellation cannot leave queued Store work.
New tests cover the worker cap, queue bound, cancellation and expiration. The
separate authenticated rate limits and every route/business deadline remain
unchanged. This change requires Actions and does not yet prove the relay failure
resolved; the rate-budget versus database rejection source remains under review.

e158101 exposed an omitted audit-maintenance caller of the former semaphore;
the new admission now preserves its nonwaiting tick and permanent-close error.
The verified Actions formatting patch was reviewed and imported. Independently,
the periodic route observer cannot share a 30/minute issuance bucket: it polls
every second. ADR 0010 introduces bounded observation and separate revocation,
retains issuance/admin budgets, and removes a redundant immediate periodic tick.
Actual HTTP regressions cover signed readbacks, exhausted issuance, revocation,
invalid credentials and the hard read budget. All repairs require new Actions.

At bd1f298 the Linux contract clippy/tests and all four native ICE NAT cases
passed, while formatting, the new reverse-initiator fixture and two-node TLS
admission remained failed. Exact-chain reuse alone did not fix the node failure.
Following source corrects request/receipt expiry conversion and pending-resource
continuity without changing signed lifetimes, snapshot TTL, query or proof
budgets. Eight added regressions cover delayed responses, request ceilings,
continuous observation and non-revival after omission/expiry/stop; both original
node authorization cutoffs remain frozen. ADR 0012 records the boundaries.
The reverse-initiator fixture now signs membership digests and supplies relay
neighbors in canonical peer order while retaining controller/host business
roles. Actions-generated formatting was reviewed and imported.

The new Edge lab failed before browser startup because archive extraction left
its sandbox helper without root ownership. The workflow restores and verifies
the verified helper's ordinary SUID permissions while retaining the sandbox.
The crab_nat package's explicit MIT declaration and original author metadata
are paired with separately identified official SPDX standard text; its missing
upstream LICENSE is disclosed rather than invented. Existing NOTICE collector
and missing-file checks remain unchanged. Node, browser and packaging repairs
all require new exact-source Actions; no release qualification is implied.

At c7d1ae1 the exact-source Linux SDK scoped suite passed all 16 tests,
including both inner-QUIC initiators with real FileRead, input denial and
physical socket release. The real management/two-node relay suite passed all
five tests on Linux, including independent node revocation while the other
route continued. The Windows scoped relay step is failed and remains under
investigation; complete workspace results and the new browser matrix are not
substituted by the Linux result. The ARM64 actual image has complete Cargo
notices and the exact crab_nat standard-text supplement and disclosure.

W12 source now includes an independently signed topology contract, explicit
space-scoped publisher delegation, current registered runtime/endpoint checks,
a durable SQLite replay/withdrawal journal and nonce-bound full/delta HTTP
routes. Prefix issuance stays closed pending the stored RouteExport chain.
Seven new SQLite regressions and eight protocol/identity regressions are to be
executed on GitHub Actions. Graph consumption, node reporting, the atomic
two-relay reservation and NRD2 four-node carrier remain required implementation,
so neither W12 nor AC18/AC19 is complete. ADR 0013 records this first slice.

The 68c21fe focused Actions job ran all 15 new topology tests successfully
(3 protocol, 5 identity, 7 SQLite; no failures or ignores). The wider jobs rejected
a missing ErrorCode import in the new HTTP handler before compiling the server;
the following source corrects it and adds a real HTTP report/query/revoke test.
The reviewed Actions formatting was imported for the protocol/Store/handler
slice, and the same source's generated OpenAPI artifact was checked by digest
and imported. Its ZIP SHA256 is 61830cf3c956cdee2d49064e313a46a3981980e3609c98bb4a63cf89ad2b3326;
OpenAPI bytes hash is cbc34201b08e777d15bfd7ebdae4c5b254ccb740912d8d6fd5338dbbcf0e0dff.

The Windows c7d1ae1 two-node failure occurred at authenticated node revocation,
not at TLS or business transmission. ADR 0014 reserves one of the existing eight
blocking workers for revocation, retaining seven ordinary workers, eight shared
waiters and the original 200 ms admission/700 ms node budgets. Both real HTTP
saturation and permission/timeout/cancellation regressions accompany the fix.
They and the unchanged Windows two-node scenario require new Actions. The new
topology revoke also uses the reserved lane for authentication and mutation.

The 929bf79 focused topology job passed the signed journal and real HTTP
publication/query/revocation tests. Windows contract clippy and tests passed;
formatting failed and reviewed Actions output was imported for unchanged source
files. This is not full-workspace or target acceptance.

The next source adds a bounded petgraph topology consumer, original live
envelope proofs, deterministic two-relay candidates and replay fences. An
independent source audit found incomplete delta pagination and failed-batch
time-watermark gaps; both are repaired with regressions. NodeControl owns
non-evicted per-space report sequences and original lease/deadline receipts.
Thirteen node tests include actual HTTP mismatch, size, redirect, timeout,
cancellation and concurrency cases. NRD2 is a separately negotiated codec;
NRD1 retains its existing wire and single-relay behavior.

Both dependency locks were generated by Actions 41132562360 against a19a112.
All existing package identities, versions and checksums remain fixed. Direct
petgraph default features require its already-locked serde edge; the original
failed derivation was rejected, the exact extra edge was reviewed, and the
workflow permits only that edge while preserving all other external blocks.
Original archives and output file hashes were verified before importing locks.
This is lock provenance, not compilation or quality qualification. ADR 0015
records this slice; atomic reservations, real adjacency integration and the
four-node business carrier remain required before W12 is complete.

The 0618e08 contract jobs found an ambiguous integer in the NRD2 fragmentation
test and a node reporter sort lint. Both source repairs are included alongside
the reviewed Actions formatting output. The observed socket and routed-kernel
experiments passed, while the new topology and full workspace results remain
separate and incomplete; those passing experiments do not qualify the new chain.

ADR 0016 adds full ordered two-relay grant verification and a separately
negotiated NRD2 mode to the existing physical adjacency, bounded forwarding and
virtual UDP owners. The binding includes both transit digests and original
business generation; forward and reverse hop positions come from verified fixed
neighbors. New actual four-node component tests cover inner QUIC, IPv6-sized
packets, reverse traffic, streams, opaque relay captures, revocation propagation
and rebinding all six physical sockets, alongside the retained NRD1 tests. These
new sources require exact-source Actions. Authority reservation, production node
admission/report integration and four-node SessionPermit/FileRead still remain
required W12 work; no release or AC18/AC19 completion is claimed.

ADR 0017 adds an atomic two-relay authority reservation, current reciprocal
topology validation, a device signature over the complete ordered request,
schema34 durable hop promises, exact readback and reserved-lane HTTP revocation.
Both hops share the mature global/account/node capacity view; the second check
sees the first insert, and any failure rolls back all grants and promises.
Restart fencing, legacy/TURN collisions and historical migration fixtures are
updated. Typed SDK methods use the separate chain endpoint. Source regressions
cover signatures, concurrent admission, second/global/account limits, audit
rollback, original one-hop migration, topology invalidation and actual HTTP
readback/revocation. These new sources are unverified until exact-source Actions.

The graph/codec/four-node carrier and reporter checks have a separate hosted job
so a large server build cannot prevent collecting independent transport results.
All original assertions and timeouts are retained. Production node-resource
delegation/admission, continuous real adjacency reporting and four-node business
acceptance still remain required; all later mandatory packages remain active.

The 0c0a2d2 Actions ran all eight atomic-chain storage tests: six passed;
concurrency setup hit the strict lifecycle clock and logout correctly rejected
the original admin's usage read. The next source repairs the fixtures while
retaining the exact quota assertions. Graph completeness also failed when a
fresh full snapshot superseded pagination at the same cursor, and server clippy
found the chain handlers missing from the actual router. Both are repaired.
The 41e70c8 real reporter HTTP test renewed leases indefinitely during cleanup;
it now explicitly stops the owner and asserts bounded task termination.

ADR 0018 delegates complete NRD2 chains through the existing policy-signed node
resource snapshot, adds strict versioned bundle fields, pins exact adjacent
endpoint/relay identities and admits fresh NRD2 neighbor possession through the
existing resource slots, meters, deadlines and pending-candidate fences. New
storage and node regressions require exact-source Actions. Reviewed 41e70c8
Actions formatting was imported only for applicable unchanged transport/codec
and graph-test files; current modified files await new formatting output.
Production listener/dialer, real continuous adjacency reporting and four-node
business acceptance remain required before W12 can be qualified.

The 976ec97 hosted carrier job passed 16 graph, 10 NRD2 codec, 15 routed
transport, 13 reporter and 7 node resource/admission tests, all without failures
or ignored cases. Its topology job passed the real HTTP reporter and chain
reservation/readback/revocation scenarios, but the new two-node snapshot test
returned Forbidden. The fixture now retains original NodeLeaseClaims rather
than guessing security/policy/sequence fields, and adds diagnostic context;
exact-source revalidation is still required. The same-source real socket,
routed kernel NAT and native ICE kernel NAT jobs passed. Full matrix and release
qualification remain separate.

ADR 0019 adds complete NRD2 authority to the existing SDK business runtime,
with two real four-node approved OS FileRead source scenarios covering both
canonical endpoint orders and complete six-socket release. Strict Actions
inventory includes the nested test module and preserves exact source/result
equality with zero failed/ignored cases. The reviewed, hash-verified OpenAPI
from 976ec97 Actions is imported. New SDK sources await hosted validation;
production registered-node chain dialing/reporting and all later mandatory
packages remain required.
