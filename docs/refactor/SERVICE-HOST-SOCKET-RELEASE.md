# Service startup socket release (2026-10-16)

The TLS-update Linux development batch executed 227 passing tests, six failures
and four ignored cases. The service-start cancellation case returned
`AddrInUse` while checking that the cancelled client's exact UDP port could be
rebound. Its process window had no observed wall/monotonic clock step. The SDK
renewal and node-relay process windows did contain clock steps; their separate
failures remain under review. The original batch and read-only clock evidence
are retained in `artifacts/tls-dependency-review-20261016/`.

The service startup error path previously closed its QUIC connection and awaited
`Endpoint::wait_idle`. That observes connection draining. The endpoint's runtime
driver can still hold the socket or a writable poller after the last application
handle is dropped, so that wait could not substantiate the startup API's promise
to finish cleanup before returning `Interrupted`.

The service client's UDP adapter now records release of the actual OS socket.
Every writable poller retains the same owner, and its inner poller drops before
that retained owner. The final socket reference drops before its completion
signal. `Connected::close_and_wait` drains connections, consumes the client
owner, then awaits that signal. Startup cancellation first releases its separate
revocation guard's connection clone, then awaits physical release. Failed dials
also retain this release completion. The adapter delegates send/receive,
segmentation and fragmentation behavior to the existing Tokio/Quinn socket and
binds the peer's address family explicitly.

New regressions cover immediate exact-port rebinding after authenticated IPv4
and IPv6 service connections, and a real socket kept alive solely by its writable
poller. The existing SDK cancellation case keeps its five-second deadline and
immediate exact-port assertion, with added failure context. Original source bytes
and source-guarded verification helpers are retained in
`artifacts/service-endpoint-release-followup-20261016/`. Its `FROZEN.json`
records the four final source files and patch SHA-256
`d76e7b2601f38dd9ba23b5cf084d1d2ce932524c8fd26375e6954657f4bd0684`.
The Windows eight-package batch passed 236 cases, with zero failures and three
explicitly ignored cases. Windows and Linux workspace/all-target strict Clippy,
formatting and Windows TURN example checks passed. All three new socket/poller
regressions and the SDK cancellation test passed on both platforms.

Two original Linux eight-package attempts remain failed: 232/4/4 and 231/5/4
(passed/failed/ignored). Their retained process-window clock observations do not
prove every failure's cause. After explicit authorization to pause WSL
systemd-timesyncd temporarily and select the available Hyper-V clocksource, the
complete Linux workspace runtime attempt03 passed **1100 cases, zero failures,
12 explicitly ignored cases** across 132 targets including doctests. Its 857
guarded inputs were unchanged, log hashes matched and owned scratch was removed.
The independent wall/monotonic observer recorded no clock steps. The bounded
wrapper restored `tsc` and the original active timesyncd state; an independent
readback confirmed both. The summary and original receipts are retained at
`artifacts/core-verification/native-workspace-linux-runtime-20261015-attempt03-summary.json`.
These later results do not reclassify earlier failures.

Android BuildAttempt15 / MatrixAttempt13 includes these source bytes; all 112
API30–36 emulator instrumentation cases passed, with both ABI release/all-target
strict Clippy passing. These checks establish the recorded development scope;
installed-product, external-network, ARM64 hardware and signing acceptance remain
separate.
