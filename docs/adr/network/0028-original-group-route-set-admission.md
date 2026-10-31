# ADR 0028: Atomic one-hop candidates under an original PathGrant

Status: implemented, awaiting GitHub-hosted Actions verification. This is an
admission/readback slice of W13. It does not complete W13, W14 or AC20–AC22.

## Problem and alternatives

Existing production direct, one-hop relay and ordered two-hop chain issuers
each create one immutable PathGrant. The verified transport group includes the
issuer and the complete original signed PathClaims. Two independently issued
grants cannot become one group merely because their business peers are equal.
The single-route and chain tables also intentionally permit one route per path.

We compared two implementations:

1. Extend issuance with one original PathGrant and two independent one-hop
   reservations, retaining the existing node admission, resource snapshots,
   quota view and eventual sole connectivity Scheduler.
2. Keep separate single-route grants and reconstruct an application session
   after cleanup, with bilateral successor proof and newly issued network
   grants. This is useful safe recovery, but is not an original-group standby
   and cannot preserve the original business connection by assertion.

We chose the first option for this slice. The second remains the safe fallback
if a later authenticated carrier replacement cannot preserve a connection.
Changing DNS addresses alone is insufficient: the existing node Pair has one
slot per original endpoint role; close is terminal and its seen fence persists.

## Original authority and atomic capacity

Migration 037 adds distinct route-set and member-reservation tables. It leaves
the original single-route and chain unique constraints and API semantics in
place. A set contains exactly two distinct registered node identities. Its one
PathPolicy permits the sorted relay identities with max_hops=1 and disallows
direct traffic. Each member has its own original allocation ID and TransitGrant
whose route is exactly canonical-first-peer -> that relay -> canonical-second.

One participating device signature binds the business digest, account, space,
set ID, all path/member/node/grant IDs, policy epoch and expiry. The signature
domain is separate from single-route allocation and ordered-chain consent.
The issuer checks current consent, login, memberships, business policy, node
runtime, registered endpoints, lease and quota. It reserves both members in one
immediate SQLite transaction. The first member enters all_relay_capacity before
the second calls the unchanged reserve_capacity admission. A second admission,
signing or audit failure rolls back all original grants and both promises.

Each route occupies one existing allocation, both account endpoint slots and
two node slots in the existing cumulative quota. The set does not mint legacy
allocation tickets or borrow TURN capacity. Its byte budgets statically split
the original bytes_per_allocation: member zero receives ceil(total/2), member
one floor(total/2). Their sum is the original total; both must be positive. No
retry, read, node change or refresh transfers bytes or replenishes a meter.
The current per-route rate and node runtime meters remain the existing owners.

The path expires no later than the original common business, memberships and
both live node leases, with a maximum 30-second issuance interval. No readback
re-signs the path or transit objects. Set revoke marks the original path and
both members terminal, while retaining both original capacity promises until
their fixed expiry plus the existing hold margin. Restore fencing also covers
the new reservation facts. The original node role/Pair/seen logic is unchanged.

## Authority is separate from candidate availability

Every readback first verifies the original group, business, membership, policy,
quota, signature and reservation facts. Each member retains the original node
key, runtime/generation, endpoint revision and endpoint JSON. Its available
field is then independently derived from the current management transaction.
A stopped/revoked/replaced node, changed endpoint or unavailable original lease
withdraws that member; it does not erase another member's original authority.
The returned endpoints remain the original mapping even while unavailable.
Availability is an observation of current node authority, not a reachability
measurement or a guarantee that the next network attempt will succeed.

Node resource snapshots delegate only their own available member, using the
existing version-one signed resource and exact-query verifier. Thus a failed A
does not suppress healthy B's original TransitGrant or role admission. A group
business/policy/membership revocation still withdraws every member. No socket
input can create a node resource or supply the authority pin.

The SDK constructs VerifiedRemoteRouteSet only through authenticated same-origin
management readback and the operator-pinned authority. It verifies both original
transits against the one original path and business proof. Its immutable
fingerprint covers the complete original credential and node mapping but
normalizes the mutable available flags. Refresh returns fresh member states,
checks that immutable fingerprint, and caps the previous fixed deadline.
Candidate admission metadata requires the same login, deployment, business,
local/peer identities, a live original deadline, an observation younger than
five seconds and available=true. Same-address members retain different route
binding digests and relay pins. A metadata handle owns no socket or permission
to bypass the node's original mutual proof.

## Scope and evidence

Production entry points are POST remote/{request}/route-sets and GET/DELETE
route-sets/{set}, plus typed SDK reserve/readback/revoke APIs. Tests cover real
Store transactions and snapshot restoration, held revocation, cumulative node,
global and account admission, complete-consent mutations and audit rollback.
HTTP cases cover authentication, exact readback, node-specific withdrawal and
quota rollback. SDK cases cover signed-group mutations and typed candidate
gates, plus actual management HTTP, two real NodeControl owners, stopping A,
retaining B's original group, B's actual mutual node admission, role replay,
whole-set withdrawal and physical socket cleanup.

All checks execute in GitHub-hosted Actions under R02. Test source is not a
passed result; exact-source run/job/artifact evidence belongs in the progress
journal after successful execution.

This slice creates no continuous Scheduler instance, probe loop, selected-route
business adapter, migration epoch, switch proposal/ACK or in-place replacement.
Those next steps must reuse the existing connectivity Scheduler and original
transport owner, preserve direct_only isolation, and prove the actual business
forwarding and cleanup. The private W14 Quinn experiment remains separate
evidence and does not establish those production behaviors.
