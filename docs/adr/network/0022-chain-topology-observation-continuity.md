# Keep transit lifetimes independent from continuous topology observations

Status: source implementation; hosted validation pending.

The durable topology journal replaces a head for every authenticated report.
Binding an entire reservation to the first advertisement digest caused a healthy
edge refresh to revoke the route. Capping TransitGrant by a one-second observation
also reduced every reservation to that reporting interval. A topology observation
describes present reachability; the separately signed business/path/transit grants
retain their original authority and lifetime.

Keeping the original digest throughout readback was considered and rejected
because ordinary refreshes necessarily change it. Simply accepting any fresh
head was also rejected: a down/up, expiry/up or replacement publisher between two
resource polls could revive a route whose authority had already ended. Reissuing
transits on each observation would change their signed bytes and capacity promise
and would incorrectly turn reachability reports into business renewal authority.

Reuse the current canonical report and advertisement verifiers, durable node
sequence owner, immediate SQLite transaction and existing quota/capacity owner.
At creation the two device-signed advertisement digests must still exactly match
the current fresh heads. Both heads must report the same ordered relay edge up,
with the registered keys, current incarnations and mirrored endpoint revisions.
Transit lifetime remains bounded by 30 seconds, both original node control
leases, current business and membership authority. Observation TTL does not set
that lifetime; current control leases may impose a shorter bound.

Migration 036 adds one binding per existing ordered hop. The immutable publisher
digest and original report sequence complement the hop's existing frozen node
key, incarnation and endpoint revision. Mutable latest-sequence and
observed-until fences record the last uninterrupted accepted observation. They
never modify the original path, transit signature, transit expiry or capacity
deadline. Existing schema-35 chains cannot prove historical continuity from a
digest alone; migration closes both hops and revokes their paths while retaining
both original capacity holds. New issuance obtains a fresh binding.

Every authenticated accepted report checks affected open chains before replacing
the durable head. Only the original publisher/incarnation and mirrored endpoint
revisions, a strictly greater sequence and continued up edge received before the
previous observation deadline advance the fence. A down or missing edge, an
expiry gap or changed authority closes both ordered hops and revokes the path in
that same transaction. Central withdrawal does the same, including publisher
replacement, revocation and query-detected expiry. Later up reports cannot clear
those flags. This covers transitions even when no business/resource poll observed
the interruption and survives reopening SQLite.

Readback reauthenticates both current fresh heads against the original bindings,
sequence floors, bilateral up edge and current nodes, alongside the original
policy/business/quota checks. It returns the exact original signed transits and
original request digests. A failed topology read permanently retires the chain.
The HTTP read owns one transaction and commits that retirement before returning
Forbidden; resource snapshots use their existing outer transaction and omit the
retired chain. Actor authorization precedes topology retirement, so an unrelated
reader cannot close somebody else's route. Internal database errors still roll
back rather than committing a partial transition.

Store regressions cover one-second observations with longer node-bounded grants,
refresh beyond the first observation deadline, original-byte recovery across a
Store reopen, exact initial digest rejection, down/up without an intermediate
poll, expiry/up with and without an expired read, publisher replacement and
schema-35 migration without refund or resigning. A journal-insert fault verifies
that the new report and both-hop retirement roll back together. These are control-plane source
regressions. They do not qualify real four-node QUIC traffic, migration under
loss, OS/LAN routing or the W23 raw-IP data plane.
