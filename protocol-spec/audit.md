# Audit metadata and retention

The control service exposes audit metadata to currently authenticated
administrators. Login alone, resource ownership and a supplied `is_admin` flag
grant no audit access. Storage checks the live database role, account/session
state, access expiry and deployment security epoch. All routes use `/api/v3`.

`GET /audit?security_epoch=<epoch>&after_sequence=0&limit=100` returns at most
100 entries in ascending sequence order. Epoch is required; the other values
default to zero and 100. Limits of zero or above 100, cursors outside SQLite's
positive integer range, future cursors and cursors from a previous restore
epoch are rejected. One SQLite read transaction observes entries and cursor
metadata consistently, including when another process appends records.

Each entry contains sequence, event, resource ID, the event's security epoch,
creation time and typed actor metadata. It carries no password, token, hash verifier, TOTP material,
signature, session payload, screen content or file data. Existing events and
their necessary resource IDs remain the source of these records. New implemented
domain events use the actor categories and coverage defined below.

## Actor attribution and implemented events

`AuditActor` is a tagged shared Rust/API enum:

| `kind` | Metadata and basis |
| --- | --- |
| `legacy` | Pre-schema-9 record with unknown actor; never inferred from a resource ID |
| `local_operator` | Local bootstrap, offline restore or local storage maintenance/configuration action |
| `unauthenticated` | Completed failed login; a supplied name or known account does not establish an actor |
| `management` | Authenticated account UUID and management session UUID |
| `device` | Account, management session and installation UUID after the domain operation verifies the device signature |
| `device_credential` | Account and installation UUID after the device-specific credential refresh verifies its old token hash |

New records cannot use `legacy`. The business transaction checks management
session/account/security-epoch and device/account associations before allocating
an audit sequence. Logout and password-change events retain the identity after
revocation in that transaction. This metadata association check supplements the
domain authorization checks; it does not establish authorization or perform
signature verification itself. Administrators cannot submit an actor through
the HTTP API. HTTP policy and device-revocation handlers use the authenticated
principal variants; the local storage entry points remain explicitly local.
Administrator mutation transactions also recheck the current database role and
session identity instead of granting authority from a supplied `is_admin` flag.

Implemented event coverage:

| Domain | Events |
| --- | --- |
| Accounts/security | Administrator bootstrap; member creation/disable; completed login success/failure; login refresh/logout; TOTP enrollment/confirmation; recovery-code rotation/consumption; password change |
| Devices | Signed installation registration; owner/local device revocation; purpose-bound device credential rotation |
| Remote authorization | Pending request creation; host-signed approval/rejection; first permit issuance; explicit trusted access; owner revocation |
| Reusable access | Host-signed trust grant/replace and owner removal; host-signed password configuration/replace and owner removal; signed password attempt reservation and completed success/failure |
| Policy/nodes/operations | Global and scoped path policy changes (scope retained in resource ID); node registration/revocation; audit-retention change; combined WSS relay quota configuration; offline restore epoch rotation |

Unknown-name failed logins retain only resource `login`, without supplied name,
IP, password or factor. A known-account failed login may identify the related
account as its resource, but its actor remains `unauthenticated`. Recovery use
is recorded only when consumption commits with its authenticated operation;
code contents and TOTP material never enter the event. A fixed-password attempt
is recorded in the durable pre-CPU reservation transaction, so cancellation
does not remove either its budget or its audit evidence. Its verified controller
installation is retained even if the password subsequently fails.

Identical request/initial-permit/device-revocation retries and already-revoked
remote requests do not append duplicate transition events. Automatic lease
renewals, signal payload updates, node heartbeats, ordinary reads and retention
ticks do not create an audit record for each poll or packet. Transient challenges
are not authorization grants. This avoids retaining traffic payloads as audit
history. Relay/edge/TURN allocation, public-service and quota events must be added
with those domains; their product implementations are still open.

The page includes the current epoch, `next_sequence`, `high_watermark`,
`pruned_through`, `history_pruned` and `more`. `next_sequence` is the last returned
entry, or the high watermark for an empty page. A client can poll from that
cursor without repeating entries. If `history_pruned` is true, some history
after its previous cursor has been removed; the client must show that fact.
`pruned_through` conservatively records the greatest sequence ever removed,
including when wall-clock timestamps do not follow sequence order. Security
epoch binds cursors because restoring an earlier backup can roll back a counter.

## Retention configuration

`GET /audit/retention` returns configuration revision, retention seconds and
maintenance/cursor metadata. `PUT /audit/retention` accepts
`AuditRetentionUpdate { expected_revision, retention_seconds }`. The initial
revision is 1 and the default retention is 2,592,000 seconds (30 days). Allowed
retention is 3,600–31,536,000 seconds. A successful update advances the revision
and appends `audit_retention_changed` in the same transaction; stale or failed
updates append nothing and change nothing. Updating retention takes effect at
the next maintenance tick rather than running an unbounded delete in the HTTP
request.

The `control` process owns maintenance alongside the HTTP listener. It runs
one transaction at startup and every 60 seconds, skipping missed ticks. Each
transaction selects at most 500 expired rows using `(created_at, sequence)` and
deletes only those rows. It updates the prune cursor and last cleanup time
atomically. Queue exhaustion skips a tick; database/integrity/clock failure is
reported to the service supervisor, which stops accepting traffic and allows
up to five seconds for graceful shutdown. Maintenance ends with the listener.
Loopback fixtures start the same service future explicitly. No live `VACUUM`
or claim of secure erasure of historical database pages or backup files is made.

The last cleanup clock persists, so a backward clock cannot purge a newer time
range accidentally. Cleanup reserves no new audit entries: an idle service
does not create an event per maintenance tick. It also does not modify any
login, device, password/trust authority, business session or lease.

## Sequence and migration

Schema 8 seeds a persistent audit high watermark from the greatest existing
sequence. New events allocate from it within their business transaction. It
does not fall when the newest row or the entire audit table is deleted. Thus
SQLite row-ID reuse cannot hide new events behind an older client cursor.
Counter exhaustion rejects and rolls back the entire business transaction.

Schema 5/6/7 migration retains existing records and cursor order without granting
new trust/password authority. Snapshots and database reopening preserve
retention, prune and counter state. Offline restore creates a new security
epoch and an audit event; previous-epoch cursors are rejected.

Schema 9 adds a bounded valid-JSON actor column. Existing records become `legacy`
without changing their sequence, event, resource, epoch or time. Snapshot and
SQLite reopen preserve actor metadata. New enum variants reject unknown fields;
an unsupported or corrupted actor fails the query rather than silently becoming
a claimed identity. Metadata has no foreign-key cascade into account/device
tables: retained audit identities survive business revocation.

## Development scope

Storage fixtures verify live role/session enforcement, forged administrator
flags, expiry/logout/restore, ordered bounded pages, stale/invalid configuration,
fixed-size expiration batches and their boundary, persistent prune/counter
state through SQLite reopening, sequence allocation after an empty table,
clock rollback and transaction rollback on counter exhaustion. A real HTTP SDK
fixture checks denied member access, generated query parameters, pagination,
retention revisions and the running maintenance future. Additional fixtures
check unauthenticated failures, verified host attribution, cancelled password
attempts through reopen, recovery consumption, actor association rollback,
live administrator role, retry deduplication and schema-9 legacy attribution.
Installed UI, events for outstanding domains, long-running load/capacity and formal product
acceptance remain open.
