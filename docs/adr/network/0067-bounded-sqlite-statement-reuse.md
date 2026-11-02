# ADR 0067: Reuse compiled SQLite statements for live policy snapshots

Status: implemented; awaiting exact-source GitHub-hosted validation.

Each private application handshake still performs independent current-authority
readbacks before and after proof. A readback obtains the full bounded network
snapshot, including current members and every existing revocation collector.
These queries previously compiled the same SQL again on every readback, even
for empty subnet, packet-access and WireGuard tables. The packet-access query
alone contains many policy joins and correlated checks.

Use the existing rusqlite connection's bounded `prepare_cached` facility for
the snapshot authority, membership, grant and path queries and its existing
revocation collectors. This reuses compiled SQL, not result rows, grants,
signatures or authorization decisions. Each execution still binds the original
space, epoch, clock and history limit and reads the current transaction. No SQL
predicate, ordering, bound, signature check or error propagation changes. The
existing connection cache capacity is retained; cache eviction only recompiles
the same statement. No new cache, dependency, worker or schema is introduced.

A cached policy response would hide current revocations and is rejected.
Omitting unrelated revocation collectors or their global history bounds would
change admission behavior and is also rejected. This change retains the full
snapshot and every collector, including empty ones.

The capacity workflow additionally executes the existing real storage
regressions for external device revocation, expiry and key corruption;
persisted grant revocation and restart; and clock rollback and restored-space
fencing. It also retains the new exact-byte/tamper/expiry/ACL currentness
regression and the original HTTP, negotiation and multiplex suites before
executing the original load. Build time and test execution budgets remain
separate. All automated validation runs on GitHub-hosted Actions.

The earlier debug, release pair-window and independent origin-window failures
remain failures. Reusing compiled statements does not itself demonstrate a
capacity, latency, physical-node or soak qualification. Original signed leases,
three-second handshakes, admission limits, 1000-live assertion, three waves,
exact bytes, durable accounting and physical cleanup remain unchanged.
