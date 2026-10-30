# Persist exact node prefix publication authority

Status: source implementation; hosted validation pending.

Reuse the existing RouteExportClaims, canonical prefix checks, Ed25519 authority
signature and publisher proof verification. Managed node grants cannot be put in
the existing membership grant table: its kind and installation foreign key are
specifically scoped to memberships. Migration 035 therefore adds the smallest
separate durable export and publisher-reference tables, preserving original
claims/signatures, issuer-bound digest, registered node key and permanent IDs.

Space owners/admins, or deployment admins for legacy spaces, may issue and revoke
exports through revision/epoch checked transactions. The node identity comes from
its registered current record, never request-supplied claims. Grants have at most
15 minutes of original lifetime, 32 explicit non-default prefixes, 4,096 current
and 65,536 historical records per space. Readback returns the original bytes and
does not renew a grant. Used IDs cannot be recycled.

Publisher requests reference stored export IDs. Store resolves their exact
current signed proofs, derives the permitted prefix union and caps the publisher
by every referenced original grant deadline. Every production publisher consumer
uses those proofs, including publication, head recovery, query, neighbor checks
and management readback. Revocation atomically updates the authority revision,
revokes dependent publishers, journals withdrawals and preserves sequence fences.
Current policy snapshots also reject exports whose node identity, control lease
or policy is no longer current.

Nine new Store source regressions and a real HTTP scenario cover original-byte
recovery, prefix ACL, unstored proof rejection, withdrawal and replay fences,
permissions, CAS, issuer/epoch, bounds, permanent IDs, node revocation, clock
rollback and migration. Existing downgrade fixtures now remove every later table
before exercising their original migration and identity assertions. HTTP routes,
manifest, schema registry and SDK wrappers use the same production methods.

The node reporter still publishes no prefixes. A local explicit export owner,
observed prefix reachability, OS/LAN forwarding, NetworkAccess enforcement and
W23 remain unimplemented. RouteExport alone confers no raw-IP or business right.
