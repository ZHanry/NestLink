# Explicit fixed-password authorization

Fixed-password access is opt-in host authority, separate from account login,
device ownership, manual approval and persistent controller trust. All routes
below use `/api/v3`. HTTP credentials use the configured TLS management origin;
development loopback HTTP is an explicit SDK option. Neither the password nor
the device ID replaces either endpoint's installation-key proof or OS consent.

## Configure or withdraw

The host owner obtains the existing 60-second `/devices/challenge` and signs
`RemotePasswordChoice { settings, password }` with the registered host key.
`settings` contains the expected revision, permissions, paths and an explicit
expiry up to 30 days away. Password length is 12–1024 UTF-8 bytes. The
`ConfigureRemotePassword=7` device-action transcript binds deployment/security
epoch, account, host device, challenge ID/nonce/deadline and SHA-256 of the
canonical choice JSON. The enrollment and password purposes cannot substitute
for one another. A challenge is consumed once across both operations.

`PUT /devices/{id}/remote-password` verifies ownership, host capability and the
signature before scheduling Argon2id. Hashing runs outside the database mutex,
under the existing two-worker CPU budget. Before committing, the transaction
rechecks the original login generation, access expiry, security epoch, host key,
challenge, configuration revision and time. Only the salted encoded verifier is
stored. Password-bearing request objects and canonical signature buffers wipe
their owned plaintext buffers on drop; errors, events and audit rows never
include plaintext or a verifier. This does not promise erasure of TLS/HTTP
library buffers or a malicious endpoint's memory.

The initial expected revision is zero. Each set or withdrawal increments it;
withdrawal retains the row as a tombstone with no verifier. `GET
/devices/{id}/remote-password` is host-owner-only and returns revision, scope,
expiry and active state without the verifier. `DELETE` takes
`RemotePasswordRevocation { expected_revision }`. A delayed hash, signature or
delete cannot overwrite newer configuration. Changes atomically revoke all
associated password sessions and leases; manual approvals and explicit trusted
access remain independently authorized. Revocation events identify each live
affected session, and relay authorization independently detects the change.

## Explicit use

The signed-in controller first creates a normal pending `RemoteRequest` with
its own registered controller installation. Creating a request grants no
authority. `GET /remote/{id}/password` exposes the configured scope/revision only
to the requesting login while that request is pending. The controller explicitly
chooses password access and signs `RemotePasswordAttempt { expected_revision,
password }`. The `UseRemotePassword=8` transcript binds the entire current
`RemoteView` and attempt JSON, the original request nonce/deadline, deployment,
security epoch, account and controller device.

`POST /remote/{id}/password` checks that proof, the original requesting login,
the active host configuration and all requested permissions. Paths intersect
the request's current policy result with the configured password paths. It
reserves rate budget transactionally, then verifies Argon2 outside the database
lock. Completion rechecks all original state, including both installed keys,
login generation, pending request/policy, password revision, verifier and time.
Concurrent successful hashes can approve a request only once. There is no
implicit fallback or conversion into permanent controller trust.

The approved `RemoteView.password_revision` identifies this authorization.
Initial/current permits, signaling, relay and renewal recheck that exact
revision, both pinned keys, deployment epoch and current device/account state.
Permit expiry is capped at configuration expiry. Wrong-password traffic cannot
revoke an already-authorized session; explicit withdrawal/rotation, account or
device removal, policy invalidation and restore do revoke it. Restore clears all
password verifiers before listeners start, so a rollback cannot re-enable an
old password configuration.

## Persistent attempt budgets

Before each Argon2 verification, SQLite commits a reservation in both a host-wide
5-attempt/60-second window and a controller-account-wide 30-attempt/60-second
window. All admitted attempts count, including successful, canceled and
concurrent work. An HTTP timeout or worker cancellation cannot refund attempts.
The host budget spans accounts; the account budget spans devices and logins.
Rotating or disabling/re-enabling configuration retains the windows. SQLite
reopening and snapshots retain them. Clock rollback before a recorded window
fails closed. Rejections do not push the window forward, so exhausted windows
recover after their fixed deadline. Only existing host/account records receive
rate rows; arbitrary device IDs and unauthenticated bearer strings allocate none.

The HTTP boundary additionally permits 30 attempts/configurations per minute per
authenticated login session. Refresh preserves that key. Existing request and
body budgets apply; at most 32 live password sessions may involve a controller
account or target host. These fixed development budgets are not the complete
configurable quota/audit product.

## Development verification and remaining work

Tests cover key/purpose/payload/owner separation, scope/path narrowing, wrong
passwords, capped lease renewal, tombstones, concurrent completion, canceled
hash reservations, SQLite close/reopen, snapshot persistence, cross-account and
cross-host budgets, login/refresh, clock rollback, changed keys, policy, logout,
restore, and schema 5/6 migration with no inherited password authority. Real
HTTP SDK tests use password authorization before WSS inner mutual TLS, native
proof, byte transfer and renewal, then verify both connections close on password
withdrawal and separately on replacement.

The desktop and Android apps now provide host configuration, rotation,
withdrawal, current-scope review and one-request password authorization. Both
use the registered installation identity and app-core actions; neither creates
persistent controller trust. The UI binds authorization to the displayed
revision and hides cached scope while it is being refreshed or after a load
failure.

The Web app does not expose fixed-password configuration or use. Its current
session identity is temporary and does not provide the registered persistent
controller signing key required by this protocol. Host configuration also
requires a registered host capability and the installation key. Web support
therefore depends on a supported persistent enrollment and secure-key flow;
the temporary identity must not be presented as an equivalent authorization
path. Local daemon product integration, complete configurable quotas/audit and
fixed-artifact cross-network brute-force acceptance remain open.
