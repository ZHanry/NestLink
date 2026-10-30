# W18 space product slice

This slice connects account-visible space management to the production Web,
typed SDK, HTTP authentication middleware and SQLite transactions. It is source
for Actions execution. No local compilation, formatter, lint, automated test or
dependency resolution was run while authoring it. It does not complete W18's
service/protocol/port/operation ACL requirements or installed-product acceptance.

Every signed MembershipGrant remains a membership credential. Creating a space,
becoming its owner, accepting an invitation and attaching a device never create
a SessionPermit, ServiceLease, local-target approval or NetworkAccessGrant.

## Identity and persistence

Migration 029 adds named spaces, account memberships, invitation hashes and an
index into the existing retained audit history. It reuses the existing network
authority, device memberships, device public keys and policy epochs. Existing
administrator-provisioned authorities remain independent of the new product
space lifecycle; migration does not invent owners or import old credentials.

An account must have a current management session and an active account
membership to view or manage a product space. Member and guest views contain
only their own membership and space devices. Unknown space IDs and unauthorized
space IDs both fail closed. An archived space remains visible to its members,
but rejects mutations, invitations and network admission.

Every mutation uses an immediate SQLite transaction, the current authority
revision and a monotonic account/device epoch where applicable. Role changes,
membership/device removal and archive advance the existing whole-space policy
epoch. Device admission intersects the current account role and current device
membership; changing a device through the older deployment-admin API cannot
revive a removed account's space rights. Rejoining through a new invitation does
not automatically reactivate previously removed devices.

Deployment account disable refuses an account that still owns a current,
unarchived product space. It commits `account_disable_blocked_space_owner` audit
metadata and returns a conflict, allowing the owner to explicitly transfer or
archive the space first. Disabling another member prevents that account from
acting or delegating; the space owner can still remove its durable membership
and revoke its attached devices afterward.

| Action | Owner | Admin | Member / guest |
| --- | --- | --- | --- |
| Read space | All members/devices | All members/devices | Own membership/devices |
| Invite roles | Admin/member/guest | Member/guest | Denied |
| Change/remove account | Admin/member/guest | Member/guest | Denied |
| Transfer ownership | Existing active member; old owner becomes admin atomically | Denied | Denied |
| Join/remove device | Own or member devices | Own or member/guest devices | Own devices |
| Issue short membership credential | Active member devices | Active member devices | Own active devices |
| Archive / read retained audit | Both | Audit only | Denied |

An invitation contains a random 256-bit secret, scoped space, role, optional
target account, maximum one-day deadline and issuer account membership epoch.
Only its domain-separated hash is stored. Consumption checks the issuer's
current role and epoch and atomically marks the invitation used. Replayed,
expired, revoked, wrong-account, wrong-space and obsolete-issuer invitations
fail. Invitations cannot grant ownership. Secrets are absent from list and audit
responses and cannot be retrieved again after issuance.

## Production entrypoints

The Web entry is **Account and security → Network spaces**, available to every
signed-in account. It provides create/list/read, registered-device join/removal,
role delegation/ownership transfer, one-use invite copying/acceptance/revocation,
archive and the latest 100 retained audit entries. Invitation links place the
secret in a URL fragment and open the acceptance panel after sign-in or session
restoration. Opening the panel captures a received link in memory
and removes its fragment from browser history. Closing the panel or changing
sessions clears the visible secret and prevents late replies from repopulating
the next panel. Failed requests discard writable revisions while retaining the
user's draft for an explicit reread.

`nestlink_protocol::spaces` supplies the shared typed contracts and JSON schemas;
`Sdk` exposes matching operations on native and WASM clients. HTTP paths use the
existing `/api/v3` base:

| Path | Methods |
| --- | --- |
| `/network/spaces` | GET list, POST create |
| `/network/spaces/{space}` | GET authorized detail |
| `/network/spaces/{space}/archive` | POST with expected revision |
| `/network/spaces/{space}/people/{account}` | PUT role/transfer, DELETE removal |
| `/network/spaces/{space}/devices` | POST join with current device epoch |
| `/network/spaces/{space}/devices/{installation}` | DELETE with current epoch |
| `/network/spaces/{space}/invitations` | POST scoped invitation |
| `/network/spaces/{space}/invitations/{invitation}` | DELETE revoke |
| `/network/spaces/{space}/invitations/{invitation}/accept` | POST one-use acceptance |
| `/network/spaces/{space}/audit` | GET latest retained space events |

The existing `/network/spaces/{space}/members/{installation}/grants` issuance
endpoint and `/network/spaces/{space}/grants/{grant}` exact-credential readback
now share product-space account/device delegation in their transaction.
Readback recovers the committed bytes after a lost response, never signs a new
credential, and rejects current removal, archive, expiry or epoch changes.
For older independently provisioned authorities it still requires a deployment
administrator. Its output is still exactly a signed MembershipGrant.

## Actions verification

The source adds nine SQLite integration tests in storage's `spaces` test target
and one SDK integration test in SDK's `spaces` target. They cover targeted and
concurrent single consumption, wrong account/space, expiry/revocation, loss of
issuer authority, role escalation, atomic ownership transfer, registered device
ownership, old credential rejection, stale revisions, removal/rejoin behavior,
archive and restart. The SDK test uses an actual HTTP listener and production
security middleware, including ordinary-account creation of a private space.
Additional regressions cover audited owner-disable refusal, explicit transfer
or archive before disable, removal of disabled members, ordinary-account exact
credential recovery, role demotion, and legacy administrator-only readback.

`scripts/lib/refactor-browser-spaces.cjs` runs compiled production controls
against the existing ephemeral real native/server fixture. It creates the
recipient through UI, signs the recipient into a separate browser context,
accepts/replays an invitation, exercises all four roles, joins/removes a real
registered fixture device, rejects stale changes, revokes membership, reads
actual audit and archives. Existing fixture middleware delays actual GET
responses for unmount races; no response bodies or DOM controls are mocked.
The native runner requires every space-case boolean and the exact helper digest.
Its receipt tests reject partial or missing coverage and helper-source drift.

Required Actions work includes `cargo test --locked -p nestlink-storage --test
spaces`, `cargo test --locked -p nestlink-sdk --test spaces`, the Web WASM check,
and the real browser/native runner. OpenAPI and formatting are generated only in
Actions (`cargo xtask contract --write` and the repository formatting workflow).
Authored tests and receipts are not a claim that these runs already passed.

Detailed per-member/device service ACLs still need an executing intersection
with the signed service access path, including protocol, port, operation and
expiry. The existing service owner/local approval boundaries continue to apply;
this slice does not store unused allow rules or label them effective.
