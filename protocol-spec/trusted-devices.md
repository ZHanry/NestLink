# Explicit trusted-device access

Trust is a host-key-signed authorization for one controller installation. Login,
account ownership and a known device ID never register trust. Local approval
continues through `/remote` and `/remote/{id}/approval`; it never silently selects
trusted access. OS capture/input consent remains independently required.

## Registration

The host uses an already approved, current signed permit and explicitly submits
`TrustChoice { expected_revision, expires_at_unix_ms }` to
`POST /remote/{id}/trust`. All paths below use `/api/v3`.

`DeviceAction::TrustRemote=6` has the existing purpose-separated device-action
signature domain. The transcript contains the deployment/security epoch, host
account/device, source session, SHA-256 of the entire prost-encoded permit as
challenge, SHA-256 of serde JSON `TrustChoice` as payload, and the permit expiry.
Only the registered host key may sign it. Both endpoint key fingerprints,
approved permissions and allowed paths therefore come from that exact permit;
there is no separately supplied larger permission set. Renewal changes the
permit digest, so the host must sign the current permit after a race.

The grant expiry must be in the future and at most 30 days from registration.
Initial expected revision is 0. Grants and revocations both advance the stored
revision; mismatches fail. Revoked records remain as tombstones, preventing
delayed signatures from creating an old grant again. A new explicit signature
at the current revision may register new trust. Existing sessions using the old
revision remain revoked. Changes and revocations are audited.

## Use and withdrawal

`POST /remote/trusted` accepts the same `RemoteRequest` model and explicitly
requires an active matching grant. It checks current login, account/device
state, both key fingerprints, deployment epoch, expiry and capabilities. The
requested permissions must be a subset of the grant; effective paths intersect
the grant with all current policy scopes. The approved request stores the grant
revision, also returned as `RemoteView.trust_revision`. Reusing a request ID
across manual/trusted modes conflicts. The session still needs both endpoint
proofs and all native permission/lease checks before business I/O.

Initial permit, current-permit retrieval, signaling/relay authorization and
renewal recheck the original trust revision. Signed session expiry is the lesser
of 15 seconds and trust expiry. Both renewal signatures use the actual previous
permit expiry, including a shortened final lease. Grant expiry, changed keys,
account disable, device removal or a new restore epoch cannot extend old trust.

`GET /devices/{id}/trust` is restricted to the host owner and returns pinned
fingerprints, scope, revision, expiry and current active state. `DELETE
/devices/{id}/trust/{controller}` takes `TrustRevocation { expected_revision }`.
It advances a tombstone and revokes associated trusted requests/sessions/leases
in one SQLite transaction. Explicit manual approvals remain separate records.
Both replacement and withdrawal emit individual revocation events for live
affected requests; the WSS relay's
existing independent authorization checks also close actual relay I/O.

Development budgets are 256 records per host including tombstones, 32 live
trusted requests across the controller account or target host, and 30 HTTP
trusted-create attempts per authenticated login session per minute. Invalid
bearer strings allocate no rate records; token refresh retains the same bucket.
These supplement current queues,
lease deadlines and relay quotas; they are not a complete configurable quota
product. Database schema 6 migrates v15 schema 5 with an empty trust table and
nullable request revision. It never interprets old approvals as persistent trust.

## Verified development scope

Storage tests cover host/account separation, signature purpose/key/payload,
permission/path narrowing, current policy, expiry and shortened renewal,
revision replay and stale revocation, regrant without session resurrection,
device removal, restored epoch, changed public keys, current login and capacity.
An HTTP/SDK test establishes a new trusted session over WSS with inner mutual
TLS, performs native proof, transfers bytes, renews and removes trust; the server
closes both actual relay sides without local stop notifications. Replacement of
the grant during a live relay is separately tested and stops the old revision.
The separate
manual-revocation scenario is retained. A schema-5 fixture migrates and retains
existing account data without creating trust.

Desktop/Android/Web trust UI, local daemon consent and installed-product
acceptance remain open. This increment does not implement fixed-password remote
access or replace its separate authorization/brute-force requirements.
