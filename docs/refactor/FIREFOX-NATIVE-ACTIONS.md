# Stable Firefox in the production Web/native Actions matrix

The production Web/native job now includes Chrome, Edge and official stable
Firefox as three independent jobs with fail-fast disabled. Each uses the same
release site and builds the same original optimized native fixture. The Firefox
adapter has been implemented; its exact-source hosted execution is pending.
Neither the historical stock Firefox 158.0 Windows view result nor the earlier
Playwright patched Firefox result establishes this new Linux integration pass.

Mozilla's official product-details metadata read on 2026-11-02 reports stable
Firefox 159.0, released 2026-10-27. The exact Linux x86_64 en-US archive and its
official SHA512SUMS entry are frozen in
`docs/refactor/firefox-stable-linux.lock.json`. Actions downloads that official
archive, checks the fixed SHA512 before safe extraction, checks the actual
executable's `--version`, and retains its SHA256, archive source/checksum, lock
digest and Actions run/attempt/source in the browser source receipt. The runner
compares that executable with the browser report, which independently verifies
the actual Firefox product and runtime version. The sanitized artifact is
`nestlink-browser-native-evidence-firefox`; the Chrome and Edge artifacts retain
their separate names. A newer stable release requires a reviewed lock change;
the job does not silently download a moving version.

The existing pinned puppeteer-core 25.14.0 launches Firefox with WebDriver BiDi,
a fresh owned profile and `acceptInsecureCerts=false`. Firefox159's original
`NSSCertDBTrustDomain::GetCertTrust` admits NSS CA anchors for trust, so this
engine uses a standard fresh local CA and leaf chain. The one-day CA has
critical pathlen0 and nameConstraints permitting only127.0.0.1, plus serverAuth
usage. Its signed leaf retains the127.0.0.1 IP SAN, one-day validity and CA:FALSE
constraint. NSS certutil imports only that exact constrained root (`C,,`) into
the new profile's cert9 database and reads it back to compare complete DER
bytes. Both private keys remain in the attempt's0700 directory with0600 modes.
Enterprise-root import is disabled for this owned Firefox profile. No normal
browser profile or OS trust store changes. Normal chain, hostname and validity
checks remain enabled. The runner's independent TLS connection also verifies
the exact served leaf and same-run production index before the browser starts.
Firefox has no Chromium SPKI switch and receives no broad certificate-error
bypass, custom clipboard grants or user-activation bypass. The fixed verifier
source is `https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_RELEASE/security/certverifier/NSSCertDBTrustDomain.cpp`.

The original trusted Puppeteer input, real SDK/server/SQLite controls, isolated
recipient context, OPFS and Web Locks tests remain in the common probe. Six
mutation assertions use the real request's `fetchPostData` on Firefox because
the synchronous CDP `postData` accessor is unsupported there. Chromium retains
its original cached accessor. A missing, malformed or oversized request body
is an error; DOM drafts never substitute for transmitted bytes.

Permit/renewal observation uses Puppeteer's existing BiDi data collector and
actual request/response/requestfinished events. Only exact owned-origin POST
permit/renew paths are admitted. One request object owns its completion and
body; no HTTP re-fetch, network interception, response replacement or extra
grant is performed. The helper bounds tracked requests at128, pending requests
at32, projected response bodies at262144bytes, request/body retrieval at15/3
seconds and shutdown drain at5seconds. Puppeteer's native collector itself uses
an independent20MB encoded buffer, so these are adapter projection bounds,
not a claim that Firefox buffers only262144bytes. The existing permit claim
validator is shared with Chromium and publishes only the same fixed safe
claims. Raw returned byte buffers are cleared; protocol/JSON exception text
does not enter the report. Missing data support, an unavailable original body,
an incomplete load or a failed cleanup remains a failed integration.

The Firefox download context uses Puppeteer's standard `downloadBehavior`.
The adapter observes the pinned BiDi connection's standard
`browsingContext.downloadWillBegin` and `browsingContext.downloadEnd` events,
correlated to the exact page context, owned blob URL, download ID, nullable
navigation and fixed filename. Firefox159's original NavigationManager assigns
a download UUID while its navigation is null for a Blob save with no ongoing
document navigation. The adapter uses that actual download ID, never a fabricated
navigation. This follows the fixed official release sources:

- `https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_RELEASE/remote/shared/NavigationManager.sys.mjs`
- `https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_RELEASE/remote/webdriver-bidi/modules/root/browsingContext.sys.mjs`

No new protocol session or permission command is created. BiDi
reports completion without CDP's received-byte counters; both engines still
require the actual saved file's exact length and SHA256 before and after
browser exit. The owned final file is physically removed only after that
verification. Both engines close their dedicated download observation before
browser shutdown, and the runner requires the cleanup receipt.

All three engines must satisfy the original36seconds of continuously decoded
320x180 VP8 at at least9fps, advancing received bytes and owned capture pixels,
three Opus intervals with at least43200decoded samples/second and45packets/second,
at least four steady signed renewals, exact input release and file transfer,
all common UI cases, physical owner cleanup, browser exit and removal of the
attempt's private directories. There is no Firefox-specific waiver or smaller
matrix. Unsupported runtime behavior causes the Firefox job to fail, while its
sanitized partial evidence is retained. Independent contract tests exercise
wrong product/version, response identity/bounds/failure, download correlation,
listener cleanup and the same media thresholds. Those contract tests alone do
not qualify a real browser run.

The separate optional CDP page WebRTC packet/queue impairment mode has no
equivalent supported Firefox interface in this pinned Puppeteer adapter. A
Firefox invocation with `--exercise-network-damage=true` still fails explicitly;
that scenario remains unverified for Firefox. This is not an omission from
the three-engine steady Web/native matrix, which never enabled that mode for
Chrome or Edge. Physical Windows/GPU capture, clipboard platform integration,
external networks, real device permission dialogs, installed products and
target qualification retain their independent acceptance requirements.

All download/extraction, dependency preparation, syntax checks, contract tests,
builds and browser execution run on GitHub-hosted Actions. Local work for this
change was source review/editing, upstream source/metadata reads and Git only.
