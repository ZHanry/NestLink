# ADR 0007: durable network authority rotation and revocation

Status: implementation slice; exact-source Actions and target evidence pending.
Date: 2026-10-30, Asia/Shanghai. Scope: W04 and the current W05/W07 route owners.

## Existing authority and the required lifecycle

The existing SQLite authority, membership epochs, signed network credentials,
current-policy verifier and deployment administrator authentication remain the
owners of network admission. The old configuration operation could replace a
public key and advance the policy epoch, but production HTTP issuance always
signed with the deployment's fixed network key. It could not issue usable
credentials after a managed rotation. There was also no retained key history
preventing an administrator with a fresh revision from reinstalling a retired
key. Existing per-grant and per-member revocations remain in place.

We compared accepting or storing replacement private keys with deriving managed
space keys from the existing network signing root. We choose a small adapter over
the existing HKDF-SHA256 and Ed25519 components. Generation zero preserves the
exact preexisting key. Later generations bind the space UUID and a monotonic
generation to a separate, length-delimited derivation domain. Seed copies and
derived seeds use the existing zeroizing owner. SQLite stores the generation and
public key, and no HTTP operation accepts a private key. Business SessionPermit
and installation signing keys keep their existing independent authority.

Generation zero is a compatibility boundary: existing deployments can upgrade
without replacing every client pin. Starting at generation one, different spaces
derive different keys. Rotating the root secret itself remains an operational
root-provisioning event; this API rotates space authority under the configured
root. An externally configured public key cannot be managed unless the configured
root actually reproduces its current key. Production issuance resolves the stored
generation and checks its exact public key before the original issuance
transaction independently rechecks current policy.

## Durable transitions and client trust

Migration 030 adds a signing generation, permanent authority-revocation bit and a
public-key history. Existing authority rows seed one generation-zero history row
using their current policy epoch and last observed time. Retiring a key and
activating its replacement happen in the same immediate transaction as the
policy/revision update and audit event. A failed audit insert rolls the entire
transition back. The history is retained permanently; configuring an old key with
a current revision does not reset it. Managed generations can only change through
the rotation operation.

We compared allowing an unrevocation operation with treating authority revocation
as terminal. Revocation is terminal. The same space UUID cannot be reenabled by
configure, rotate, policy advance or process restart. A new authority requires a
new space UUID. All lifecycle changes authenticate the live deployment admin
session inside the storage transaction and compare both expected revision and
policy epoch. Reads recheck restore fencing, deployment security epoch and the
original monotonic observed time. A revoked authority remains readable to the
deployment admin so a lost final response can be recovered; this read grants no
credential issuance or transport admission. Repeating a terminal revoke with the
current revision and epoch is idempotent.

The management API provides authority read, rotate, permanent revoke and explicit
policy-epoch advance, with typed SDK methods and generated management schemas.
Policy advance invalidates the entire old credential generation while retaining
the same signing key. Space owners/admins are product delegates and do not gain
deployment authority management through these routes.

We compared accepting the new public key from an authenticated management response
as automatic trust with keeping operator-pinned network keys independent. Local
pins remain independent: returned keys never mutate PinnedNetworkSpace. Operators
must distribute and verify the new key through their trusted deployment procedure
before new clients can use rotated credentials. Failure to update a pin rejects
new credentials. This operation does not claim recovery from a compromised root
without a trusted distribution channel.

## Revocation reaches the original live resources

The original node resource snapshot and its existing update loop remain the
propagation mechanism. An obsolete path epoch or expired/revoked stored path is
omitted before checking old signatures. An explicitly revoked membership grant
can return the existing PolicyRevoked proof error; that exact result now also
omits its route instead of failing the entire node resource poll and retaining
unrelated old resources until freshness expires. Other proof and internal errors
still fail the poll. This avoids introducing a second revocation scheduler.

Existing node entry/pair gates and SDK current-route observation then close the
original routes, pending setups and client socket owners. New credential
generation never transfers an old grant identifier, relay allocation or physical
resource receipt. Revocation is not proof of physical closure, so the mature
reservation's original capacity hold and expiry remain intact.

## Verification sources and evidence boundary

New storage test sources use real SQLite transactions, restart, populated
schema-29 migration, compare-and-swap conflicts, wrong-root rejection,
permanent-revoke readback, retired-key rollback attempts and an injected audit
insert failure. They exercise exact generation-zero compatibility, space-separated
later generations and current-generation signing after restart. HTTP test sources
check anonymous/member denial, current-key credential signatures, stale revision,
explicit policy advance, no reactivation and permanent key history.

SDK integration test sources use the existing real HTTP server, SQLite store,
signed node resource polls, actual node listener, two Quinn clients and business
proof. They send FileRead data before rotate, policy advance, authority revoke or
single membership-grant revoke, then require the current node snapshot to omit
the old route, both channel runtimes to report Revoked, original UDP sockets to
rebind and the original held reservation to remain charged. An unpaired real node
setup is also interrupted by rotation and must release its original UDP socket
without opening business connections. The rotation test checks the original
client pin remains unchanged.

These are source additions awaiting GitHub-hosted Actions under R02; no local
build, formatter or automated execution has been used. A source test alone is not
passing evidence. Exact source SHA/run results, generated OpenAPI/formatter
patches and any target-environment gaps must be recorded by the integration owner
before this slice is marked verified.
