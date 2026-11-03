# Approved business pair preparation

An ordinary product-space member can prepare only the two current device
memberships of a separately approved live remote request. This does not expose
the space device directory, change the local authority pin, create a business
Permit, or issue a PathGrant, ConnectivityGrant or relay allocation.

`POST /network/spaces/{space}/remote/{request}/preparation` takes exactly
`expected_space_revision`, `expected_policy_epoch`, `connection_generation` and
canonical base64url `permit_sha256`. `GET` at the same path takes those same
fields as a query. Both operations authenticate the current login, require its
account to participate in the remote request and remain an active account
member of the selected product space, then intersect `current_resource_permit`
with both active device memberships and the exact current authority. Global
administration grants no exception to participant scope. Legacy administrator
policy and device/member directory endpoints keep their existing gates.

The response binds request, connection generation, Permit digest, policy
metadata and two signed membership envelopes. Each envelope contains its exact
installation ID, key, role and membership epoch. Keys and roles come only from
the current Store snapshot; the caller cannot choose an arbitrary peer, role,
grant ID or expiry. The original membership issuer, canonical signatures,
stored digest, cross-purpose ID namespace and current-grant quota are reused.
Both inserts and their existing audit entries commit in one transaction.

Two domain-separated grant IDs are derived only from space, request,
connection generation and exact Permit digest. Revisions and epochs remain
exact preconditions, never allocation entropy. A changed revision cannot mint
a replacement after either original credential is revoked or its membership
epoch changes. An incomplete or colliding pair fails closed. Repeated POST
and GET return the original signed bytes and original expiry, with no duplicate
issuance audit. GET never signs. The lifetime is at most 60 seconds, capped by
the original live Permit and both device expirations; preparation has no renewal.
No schema migration or new dependency is needed.

The native SDK accepts a previously approved `PinnedNetworkSpace`, local
`DeviceIdentity`, `VerifiedPermit` and exact selected space revision/epoch.
It performs one fixed POST, then only the same GET after a transport failure,
timeout, lost body or exact `409/ReplayRejected` Store conflict. Authentication,
authorization, invalid data, other HTTP errors and mismatched response bindings
remain terminal and keep their original typed error. The original five-second
setup deadline bounds both. Independent
signature verification checks the local pin and compares both membership key
digests with the business Permit; the local endpoint key must also match the
original installation identity. The resulting `VerifiedRemotePreparation`
retains signed credentials privately without Clone, Debug or Serialize.
Its accessors expose only the policy and fixed IDs, roles, epochs and expiry.
`check_current` re-reads the exact pair under the original login, origin, local
identity, business digest, response fingerprint and monotonic deadline.

AppCore owns the one-use local review and configuration compare-and-swap.
Preparation never overwrites the authority pin, LAN consent, PCP consent or
saved network settings. The original path issuer and currentness poller must
still independently intersect network authorization and business authorization
before native input, media or files can use a connection.

Hosted Actions tests cover ordinary cross-account participants, unchanged peer
directory restrictions, unapproved requests, unrelated global admins, changed
Permit/generation/revision/epoch, wrong signing keys, immutable duplicate and
lost-response readback, revocation without replacement IDs, membership role or
account removal, device revocation and archived spaces. A real HTTP handler
commits the pair before a response body I/O error; the SDK must recover through
one fixed GET with exactly one issuance POST and no lifetime extension. The
same hosted test also rejects an unapproved authority pin and a nonparticipant
local installation. Additional real HTTP cases retain a visible POST 403 even
when GET could read a previously valid pair, exercise the actual Store rejection
of a changed posted business digest, reject a mismatched successful response,
and distinguish the exact Store conflict from `409/InvalidMessage`. A revoked
PathGrant occupying the second derived ID must reject preparation and roll back
the first sibling and its audit. Compilation, testing and formatting are
Actions-only.
