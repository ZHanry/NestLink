# Retained local diagnostic export

Status: partial W29 implementation, hosted validation pending.

Reuse the existing protocol request hash, Core safe projections, bounded browser
host timeline and platform-security private metadata API. Do not add another
telemetry service or export a full IPC Snapshot. Two approaches were considered:
copying existing private diagnostic files directly and explicitly re-projecting
known typed fields. Choose the latter: private files can be edited by the owner
and future versions may add fields unsuitable for sharing.

`nestlink-daemon diagnostics --state-dir <absolute-private-directory> --output
<new-absolute-private-file>` works without management login or a running daemon.
It reads bounded native, browser-host and private-service observations. Missing,
unreadable, malformed and unsupported input is explicit. Output is create-new,
owner-private, size limited, read back, and accompanied by its byte length and
SHA-256. No source is overwritten. JSON parse errors, path details and raw labels
are not copied into the report. Unknown native metrics remain null. Browser
timelines deserialize through the existing fixed model; arbitrary nested fields
are discarded. Native and browser request hashes can be correlated; independent
local service operation hashes are clearly distinguished. Reading atomic files
separately does not imply a synchronized live snapshot or a shared time anchor.

The production private-service `serve` command now observes directory selection,
listener startup, local stop cause and the original owner's awaited cleanup.
Selection failure and startup failure retain a fixed `operation_failed` event.
Physical counters are copied from joined SDK receipts. No Debug error, target,
alias, port, credential, identity key or application bytes are persisted. A
selected relay count describes user configuration; it is never presented as an
observed path. Listener readiness is local readiness, not a successful backend
connection. Cleanup timeouts retain the same owner and a pending observation.
History is capped at 128 complete records and 64 KiB, with oldest records removed
first. Diagnostic write failure emits one fixed warning and grants no authority.
A visible metadata commit with unconfirmed durability is reported as unavailable,
not a confirmed durable write.

The implementation is intentionally partial W29. Per-flow service grant/path
correlation, full native first-frame/candidate/recovery events, server-side
correlation and target-device evidence remain mandatory. Existing browser UI
export remains separate; this command joins retained local sources. AC49/AC50
cannot be marked passed solely from these source changes.

Privacy injection, unknown values, malformed source handling, create-new input
protection, record bounds and failed-selection retention have hosted tests in
the complete Core workflow. All formatting, compilation, lint and test execution
are performed only by GitHub-hosted Actions.
