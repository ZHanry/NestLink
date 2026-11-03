# ADR 0080: Retain signed direct authority across a new business generation

Date: 2026-11-03. Status: implemented source; exact-source hosted validation pending.
Scope: an already proved signed-space native direct session after successful
TransportLost or NetworkChanged cleanup. This does not qualify W14, W15, AC22,
AC23 or target-device recovery performance.

## Decision and existing components

The original signed direct entry already used NativeEndpoint, native ICE, the
existing Scheduler, mutual TLS/business proof and ChannelRuntime. AppCore kept
its VerifiedRemoteDirect for authenticated currentness polling but discarded
the recovery source after transport loss. The existing legacy reconnection
exchange can safely advance the business generation, but its receipt alone
does not preserve a separate signed-space path or its revocation ancestry.

Retain that exact direct admission only after the original business, input,
media and physical endpoint owners have completed cleanup. Reuse the existing
two-device reconnection exchange, generation/lease CAS, durable receipt and
business proof. Both generations must have identical business claims apart
from the existing successor fields. The replacement remains direct-only and
uses the original local space pin and both exact membership credentials.
Queued input, video, audio, clipboard writes, file operations and arbitrary TCP
requests are never replayed into the replacement. Display selection and actual
media/input bindings must be rebuilt for the new generation.

No wire object or existing device-signature transcript changes. The unchanged
two-device signatures authenticate the business transition; they do not newly
sign a network parent. The network server therefore independently verifies and
durably retains that parent before issuing any new path authority.

## Durable authority lineage

Distinct domain-separated request IDs are derived from the complete original
canonical path, connectivity and ordered membership claims fingerprint, plus
the exact already signed reconnection choice and a path/connectivity selector.
These IDs locate a candidate; possession of an ID does not authorize issuance.

In the same immediate transaction as path issuance, Store obtains the current
business permit and exact reconnection receipt, rechecks the strict successor,
both current device keys/signatures and the original expiry, and queries the
space/session/previous-business-digest index. The query reads at most 65 parent
IDs; more than 64 candidates fails closed. Each matching parent is independently
verified against the exact previous Permit digest in its signed connectivity
grant, current membership, current policy/authority, expiry and revocation.
Both derived request IDs must identify the same unique parent. The member IDs,
policy epoch and path expiration cannot change.

Schema 51 stores child-to-parent identity, full previous/next Permit claims,
the unchanged dual-signed submission, complete parent fingerprint, original
expiry and depth. Foreign keys retain both path rows. Every current direct GET
iteratively revalidates all ancestors, with cycle rejection and a maximum
depth of 16. Each transition rechecks signatures, exact successor claims,
signed parent business digest, fingerprint, both derived IDs and unchanged
scope. Historical Permit claims are accepted only for this private ancestry
validation; normal business admission still requires the actual current permit.
Withdrawal, member/key changes, policy/authority changes or expiry at any
ancestor invalidate the leaf and its committed readback.

This avoids trusting a client-side precheck followed by a fresh same-scope
grant, which would lose a parent withdrawal racing with business commit.
Another valid path with the same members cannot satisfy the withdrawn parent's
derived IDs. SDK recovery likewise starts only from its retained exact parent.

## Deadlines, retries and ownership

The original native bind already narrows its authorization deadline to the
PathGrant deadline. Its business session stores a non-renewable lifetime cap,
and LeaseControl extracts the same stopped-session monotonic budget. AppCore
refuses a budget beyond the retained direct admission. All successor deadlines
take the minimum of that original cap, the prior admission and the existing
reconnection budget. The product's initial path has at most 30 seconds, further
limited by business and membership expiry; no poll or recovery restarts it.

Only the controller sends one immutable path POST. A lost response or conflict
causes authenticated GET of that same derived ID. Failure never allocates
another ID. Because the existing server intentionally shares a 403 for missing
and withdrawn paths, the host can wait at most one second for initial issuance,
always inside the original deadline. Other hard errors remain terminal.

Readmission and media publication complete before a new UDP endpoint opens.
During the pending proof, authenticated child GETs check currentness every
200 milliseconds; failure cancels the same establishment future and awaits its
cleanup. A successful monitor read cannot replace authority. Final establishment
still checks the pinned admission's exact response fingerprint. The resulting
NativeConnection::Direct keeps the original production currentness poller and
resource owner. A later eligible stop can recover again, subject to the same
expiry and the server's 16-transition bound. Original route-set recovery retains
its separate existing single-successor limit.

## Schema compatibility and required evidence

Schema 51 is additive. Older schema-50 Store entry points must reject its
user_version before business admission or database/configuration mutation.
Never lower user_version or discard lineage to make an older server accept the
database. Existing explicit backup/migration/admission/rollback procedures stay
in force; the retained 0.7 package experiment remains unchanged.

The appended hosted compatibility producer builds the unchanged pinned
schema-50 Store source c5893625ebbe3b50406810bd7eb34c60cbbea849, links a small
probe to its actual Cargo-produced library, and runs its real open_existing and
open against a private schema-51 database containing a real dual-signed child.
Both entries must return the exact unsupported-schema refusal. All fixture
file hashes, ownership, permissions and directory entries must remain equal.
The current Store then reopens it and enforces root withdrawal. Raw databases,
credentials and device material stay outside the uploaded artifact.

New Store cases cover fixed scope, immutable committed readback, same-scope
substitution, deep root withdrawal, bounded lookup/depth and disk reopening.
Actual AppCore/HTTP cases cover fresh VP8/input after recovery, one committed
POST with a discarded HTTP body, withdrawal after that commit, and withdrawal
before the real handler executes. They retain the original input/video tests.
The one stream test dependency reuses the existing locked futures-util package;
Actions must derive its new app-core dependency edge without external drift.

No new test, compiler, formatter, lint, syntax check or compatibility producer
has run locally. New-source hosted results and target-device/mixed-installation
evidence remain required. Prior failures and timing gates remain unchanged.
Operator steps are in [SIGNED-DIRECT-RECOVERY.md](../../network-rewrite/SIGNED-DIRECT-RECOVERY.md).
