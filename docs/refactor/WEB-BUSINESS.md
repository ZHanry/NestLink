# Browser file and text clipboard implementation

2026-10-15 current source: local browser clipboard API calls have one original
30-second production deadline and retain the actual unresolved Promise after the
UI waiter ends. Controlled lifecycle fixtures use a shorter 250 ms deadline.
Timeout, revocation and clock interruption latch the first terminal result. A late
read cannot send an RPC, and a late write cannot turn an unconfirmed result into
success. Local direction approvals use opaque `Rc` tickets; revoking and approving
again in the same JavaScript turn cannot revive the old operation. Missing APIs,
synchronous exceptions and non-Promise returns are classified without a WASM panic.

The current WASM library and verification binary passed all-target/all-feature strict
Clippy in `web-clipboard-lifecycle-wasm-clippy-20261015-attempt03.log`. Both verification
and production sites then passed release Trunk builds with pinned wasm-bindgen
0.2.129 and Binaryen 133, in the two
`web-clipboard-lifecycle-optimized-*-build-20261015-attempt03.log` records. Both
entries now run the optimizer with the bulk-memory and nontrapping float-to-int
features used by the generated WASM. The earlier production optimizer failure and
unoptimized verification build are retained as attempt01.

`web-clipboard-lifecycle-optimized-three-browsers-20261015-attempt02.json` records
Chrome 155.0.8059.40, Edge 155.0.4283.45 and the Playwright patched Firefox 157.0
engine passing all selected local checks (`passed=true`, `incomplete=false`). This
includes storage, real clipboard RPC, all seven controlled Promise lifecycle cases,
peer closure and the fresh-context read without user activation. The probe now waits
35 seconds to observe the existing 30-second production deadline; it does not change
the product deadline or browser preferences. The earlier incomplete attempt01,
which observed that read for only 20 seconds, remains preserved. Site-input and
command receipts confirm unchanged built/source bytes, closed owned local servers
and reclaimed command scratch. These are development fixtures against saved site
artifacts. The patched Firefox result retains that original engine scope.

The separate `web-stock-firefox-bidi-20261015-attempt01.json` now records official
stable Firefox **158.0** passing all 14 selected local cases (`passed=true`,
`incomplete=false`). The same probe functions run through WebDriver BiDi using
pinned puppeteer-core 25.14.0, with real isolated browser contexts and trusted
input actions. It covers the production trust screen, Web Lock contention, OPFS
failure/recovery across page closure, real SCTP clipboard read/write, all seven
controlled lifecycle cases, no-user-activation refusal and actual peer closure.
The production clipboard deadline remains 30 seconds. Locale/theme/motion
emulation is not applied by the BiDi adapter; launcher automation defaults are
used without custom clipboard preferences.

The official stable-version metadata and Mozilla SHA512SUMS, valid Mozilla
Authenticode installer, privately extracted browser bytes, Node and npm integrity
lock are bound in `firefox-stable-tools-20261015-attempt04.json`. The browser was
not installed into the user's normal profile. Its owned process exited, its
private test profile was removed, both owned local servers closed, and source/site
input receipts confirm unchanged bytes. Tool-only dependency/license details are
in [the tooling review](web-browser-tooling-review-2026-10-15.json); the three
failed tool-preparation attempts remain preserved. Stable headless development
checks do not establish installed-host, graphical accessibility, external-network
or fixed signed-product acceptance.

The controller uses four independently authorized, reliable ordered binary WebRTC
DataChannels on the same mutually proved peer. Their fixed labels, immutable original
permit/transcript digest, message ordering and fragment budgets are defined in
`protocol-spec/webrtc-data.rs`. Current permit and TURN authority are checked independently
of that immutable binding. Normal lease renewal never rewrites the identity of an already
proved data connection.

`browser_data.rs` bounds fragments, partial-message time, RPC time, queued replies and
SCTP buffered bytes. `browser_rpc.rs` owns each submitted RPC until it validates and
consumes the exact native response, even if its UI waiter disappears. A revoked read
consent discards the result after consuming its sequence; completed write receipts remain
observable and are never automatically replayed.

`browser_files.rs` reuses the native root, browse, FileRead and FileWrite contracts. Upload
uses a browser-selected immutable File snapshot, reads bounded slices and hashes the full
source before opening a remote destination. Downloads stream into a uniquely named
origin-private directory, verify every chunk and the final manifest digest, and expose a
Save action only after the browser writer has closed, the completed file size matches,
and bounded slices of the actual committed private file match the manifest SHA-256.
At most eight retained artifacts and four GiB of private file data belong to one owner.
Active deletion still counts against these limits. Cleanup failure retains the exact
private directory and remains retryable; closing a waiter cannot declare a disk promise
complete. The origin's private storage is held under one browser-managed Web Lock
for the owner's full lifetime. Other live tabs fail with Busy and cannot remove
its files. After a crash or reload releases the old execution context, bounded
recovery removes only canonical UUIDv4 directories in `nestlink-private-v15`.
Recovery retains the real iterator and a failed deletion across passes, preserving
other entries. New download allocation waits for that recovery to complete.

`browser_clipboard.rs` keeps text in short-lived zeroizing staging, outside page signals,
logs and serialized UI state. Receiving remote text is separate from an explicit local
Copy click, so clipboard writes obey Firefox/Chrome/Edge user-activation rules. Sending
local text starts the browser read during the click, checks consent again before dispatch,
consumes the exact write receipt and reports its effect without retrying it.

The remote page starts all local data directions disabled. It requests each permission
separately and retains stopped runs until startup/data owners have stopped, private
files have been removed, and the server has confirmed request and temporary endpoint
revocation. Failed cleanup blocks a replacement owner and exposes an explicit retry
action. Collapsing the data panel revokes all four local directions.

## Current verification boundary

The full library, page and feature-gated verification binary passed WASM all-target,
all-feature strict Clippy, including actual private-file readback, storage locks
and revocation retention, in
`artifacts/core-verification/web-business-verification-wasm-clippy-20261015-attempt04.log`.
SDK/remote library regression passed 20 and 18 tests respectively in
`artifacts/core-verification/sdk-web-data-owner-tests-20261015-attempt05.log`.
Their all-target strict Clippy passed in
`artifacts/core-verification/sdk-web-data-owner-clippy-20261015-attempt05.log`.
These commands retain before/after hashes of their selected source scopes, log
hashes and owned scratch cleanup receipts; they are development checks.
This includes actual ordered SCTP DataChannels carrying the mutually proved native
FileRead/FileWrite/clipboard services and their real owner cleanup, plus rejection
and actual peer closure on pre-proof business data. It uses local native WebRTC peers;
it is not a browser-to-installed-host acceptance result.

Daemon browser-specific local selection/clipboard approval is under concentrated verification. Native
session roots/consent never grant a separate browser session local authority. The current
release site builds and successful selected local browser evidence are recorded
above, including the separate stock stable Firefox run; installed-host integration
still requires verification.
These development checks do not establish installed-product or cross-network acceptance.

The separate `browser-verification.html` entry selects the binary requiring the
`browser-verification` Cargo feature. The production entry explicitly selects
`nestlink-web`; the verification hooks are absent from its source module graph.
`scripts/refactor-web-browser-check.cjs` exercises the real storage owner and
browser clipboard RPC implementation through locally served, isolated test pages.
Its browser SCTP peer is a local fixture, so it does not establish endpoint proof
or a complete browser-to-installed-host session. The isolated entry was built by
Trunk 0.21.14 and wasm-bindgen 0.2.129 in
`artifacts/core-verification/web-isolated-browser-site-build-20261015-attempt02.log`;
this first site build uses the development profile and is not a release artifact.
