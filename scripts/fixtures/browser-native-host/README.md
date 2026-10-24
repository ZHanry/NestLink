# Native host and production browser development check

This standalone first-party fixture runs the real management router, SDK,
AppCore browser-host loop and VP8 encoder against the production Web site. Its
capture provider generates a changing owned image (320×180 at 10 fps by
default, or 1920×1080 at 30 fps). Optional audio generates 48 kHz stereo PCM
and uses the real Opus encoder. It never opens the user's
desktop, microphone, clipboard, filesystem roots or installed database.

The process binds only loopback, creates an owned temporary SQLite deployment
and random test account, and approves one View/direct request for its own installation
(with Audio when explicitly selected).
Separate HTTP host and HTTPS browser entry points share that temporary database;
each signs its actual management origin. A pinned upstream Caddy process terminates
the browser's HTTPS, with secure cookies enabled in the real browser router.
The readiness file contains a short-lived test account and public trust
configuration. It stays in the private runner directory and is never uploaded.

The `Web production build` GitHub Actions workflow runs this check in its
`Production Web to native host` job. It downloads `nestlink-web-dist` from the
same workflow run, builds the reviewed native codec supplier and this optimized
fixture on GitHub, then runs the production browser probe for 36 seconds with
audio and owned input/files enabled. Product builds and packaging stay on
GitHub; this runner refuses to execute outside a GitHub Linux runner.

The fixture's invocation interface is:

```text
nestlink-browser-native-host-fixture <production-static-site> <new-evidence-directory> <loopback-https-origin> [smoke|1080p30] [duration-seconds] [audio] [owned-data] [multi-display]
```

`scripts/refactor-browser-native-run.py` owns the temporary processes and calls
`scripts/refactor-browser-native-check.cjs` with `--ready`, `--report`,
`--tools`, `--executable`, `--tls` and `--engine chrome|firefox`. The tools directory must
be the reviewed puppeteer-core 25.14.0 package. The GitHub job uses Chrome and
the SHA-256-pinned Caddy v2.11.7 Linux amd64 executable. It generates a one-day
127.0.0.1 certificate and fresh browser profile. Chrome receives only the exact
leaf SPKI for that process; broad certificate-error bypass is disabled and no
installed profile or system trust store is changed. The runner independently
verifies the TLS certificate, IP SAN and same-run production index before browsing.
The probe logs in through the actual UI, requests the native host,
checks real decoded RTP frames over the requested duration (36–1800 seconds)
and signed management renewals,
then checks peer closure. No browser grants or media clocks are replaced.
The host prepares and approves its owned screen before the controller's initial
permit issuance, matching the product's automatic browser inbox. It signs host
readiness, then waits for a real controller-issued permit; capture still waits
for mutual proof. `host-start-gate.json` records the pre-lease gate; `management-stages.jsonl`
contains only fixed operation labels, methods, elapsed times and HTTP statuses.
The browser also samples the decoded owned pixels and peer/ICE/signaling states.
Every interval checks actual receiver frame and byte counters, VP8 identity,
geometry, media time and a minimum decoded rate of 90% of the requested fps.
The report records the requested rate, threshold and measured rate separately;
passing this development threshold does not declare the full G1 gate passed.
Progress samples are flushed to a create-new JSONL file even when a later
interval fails. Receiver NACK/PLI/FIR and decode/drop counters are observed;
this does not inject loss or prove feedback/congestion recovery.

With `audio`, the probe requests Audio through the actual permission checkbox.
It checks an Opus receiver's advancing decoded-sample and packet counters, and
records missing browser statistics as a failure. The video element's volume is
set to zero before playback so the synthetic tone does not play on the user's
speakers. This verifies decoding, not audible completion or device latency.
Use an optimized fixture for frame-rate measurements; debug pixel conversion
and memory wiping are not a release-performance baseline.

Creating `stop.request` in the evidence directory cancels the host. Its original
bounded lifetime (requested duration plus 84 seconds, 120 by default) also
bounds an abandoned run. `host-result.json` records
capture activation/reset and Core cleanup. `database-cleanup.json` confirms the
owned temporary database was removed. The runner closes its Caddy process and
removes the ephemeral leaf key and browser profile. A browser report alone is incomplete
without a successful native cleanup result. Optional audio also requires its
original capture owner to reset. This local synthetic-capture test
does not establish installed-platform, cross-network, system audio/input, TURN, signing
or physical-device acceptance.
If the host fails early, management remains available until the browser creates
`stop.request` or the original lifetime expires so its real revoke and temporary
device cleanup can finish without secondary connection failures masking the cause.

New fixture registry identities, versions and checksums must match the reviewed
root Cargo.lock. Its separate lock retains three existing registry differences:
zbus_names 4.3.5 (root 4.3.4), zvariant 5.15.1 and zvariant_derive 5.15.1 (root
5.15.0). Their checksums and versions are unchanged by the DTLS security update;
see `docs/refactor/dtls-dependency-review-2026-10-24.md` from the repository root.
Both locked graphs undergo dependency audit. These baseline differences do not
exempt advisories. Keep the separate lockfile and preserve failed attempts
alongside successful evidence.

Each first-party path dependency also declares the exact inherited product
version. The dependency policy rejects an implicit wildcard even for an owned
path. Adding these manifest constraints leaves the reviewed lock bytes intact;
GitHub must confirm that the graph still resolves with `--locked`.

## Explicit owned input and files mode

`owned-data` also approves Input, FileRead and FileWrite for the one temporary
installation. It opens a recording `InputDevice` and fresh private file roots
through the production platform-files adapters. It never selects a desktop input
adapter or an ambient user directory. These providers remain behind the ordinary
signed permit, endpoint proof, permission-scoped claims and real SCTP transports.
Without this CLI flag or `multi-display`, the fixture provides no input service.
Files are available only with `owned-data`.

The GitHub evidence artifact is `nestlink-browser-native-evidence`. Its
`runner-result.json` can pass only when the browser probe, native media/input/file
receipts, temporary database removal, browser shutdown and private directory
removal all pass. It includes sanitized JSON/JSONL and screenshots from an explicit
allowlist. Account readiness, private keys, browser profiles, databases, raw
process logs and test payloads are excluded. A failed run keeps its sanitized
failure evidence and fails the job. `negotiation-events.jsonl` retains at most
200 fixed native event categories and elapsed times; only exact public peer-state
messages can retain a detail string. It never copies arbitrary native log text.
These results do not replace original
HL-to-external-Edge, Windows hardware or physical input acceptance.

The browser probe requires a matching `--owned-data true`, a harness-owned
`--upload-fixture <TLS-attempt-directory>/selected-upload.bin`, and an empty
`--download-directory <TLS-attempt-directory>/received`. It uses an isolated
browser context and the public CDP/BiDi download configuration. The selected
upload must match the bounded native descriptor before any browser starts.

The probe requests the three permissions through the production Web checkboxes.
It sends trusted pointer, physical-key and Unicode-text browser input to the
owned recorder, checks focus-loss release, and leaves a final key held so actual
disconnect must release it. Unicode text here does not claim OS IME coverage.
Focus-loss with Shift held and ordinary text entry use separate trusted clicks,
so the latter establishes the textarea insertion caret after selection changes.
It separately approves each file direction in the real local data panel; default
denial, direction separation and revocation on panel close are checked.

The download spans multiple protocol payloads. The probe browses the selected
native root, receives the source through SCTP into real OPFS, checks every byte
and SHA-256, presses Save and checks the actual browser-saved file, then deletes
the staging artifact through the UI. Chromium additionally requires the real
CDP download-completed event and matching byte counters before the owned saved
file is retained for final cleanup. After the browser exits, the probe rechecks
the saved file's exact path, size and SHA-256 before removing it. Final runner
cleanup requires the download directory to be empty. It chooses the owned upload using the real
file input and sends it through SCTP. After shutdown the native fixture rereads
the final file and verifies every byte and SHA-256, with no leftover temporary
files. Payloads and native roots cannot be nominated through a Web request.

`input-records.jsonl` contains the bounded actual recording-device actions.
`data-result.json` requires exact files, no held buttons, device reset/drop,
finished file workers without cleanup timeout/error, their owner dropped and the
temporary sandbox removed. The probe additionally requires the real browser
storage lock to be released and staging directories physically removed.
Combine these receipts with native database cleanup and runner profile/key/
download-directory cleanup; an isolated browser success is insufficient.
This verifies local production data paths with test-owned devices. It does not
establish physical OS input, a signed installation, cross-network behavior,
ARM64 devices or the complete G1 acceptance gate.

## Explicit owned multiple-display mode

`multi-display` requires `smoke` and cannot be combined with `audio` or
`owned-data`. It approves only View and Input. The test-owned catalog contains
source 3 at `(0,0)` with 320×180 red pixels, and source 8 at `(-256,-32)`
with 256×144 blue pixels. No OS screen or input adapter is opened.

The normal AppCore offer/approval channel receives an exact explicit approval
for these synthetic candidates. The local initial source is 8; the production
browser must perform its first acknowledged selection to source 3. The capture
provider exposes only the approved subset and recomputes its catalog hash.
Its recorder rejects a source change while keys or buttons remain held.

Use the Chrome-only driver in `artifacts/browser-multidisplay-20261016/`.
It checks the real binary NLDB/NLDF control messages, decoded source colors and
geometry, increasing epochs, ReleaseAll, negative input coordinates, and a
Chinese/English/Chinese language change within one peer and session. Native
`multidisplay-input.jsonl` and `multidisplay-result.json` prove the actual
recording adapter's selection, input release and final reset/drop. Combine
them with the host, database and runner cleanup receipts. These remain local
synthetic regression evidence, separate from physical-monitor acceptance.
