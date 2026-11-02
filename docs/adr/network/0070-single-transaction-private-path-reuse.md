# ADR 0070: Reuse the decoded path in one current-authority readback

Status: implemented; awaiting exact-source GitHub-hosted validation.

The original release pair-window workload at source 9df4140, run 41454242981,
still failed with 403 PermissionRequired near its original signed authority
expiry. It retained 100 enrolled installations, 20 pairs, 1000 simultaneous
flows, three waves and the original lease, handshake, quota and hold assertions.
This failure remains distinct from build timeouts and other load observations.

ADR 0066 already reused one verified immutable business lease in each serialized
Store readback. ADR 0069 already avoided verifying that same service and usage
signature again through the delegation. Neither change removed three reads and
JSON decodes of the same stored network path in the combined currentness call:
the selected Direct/Relay check, complete network-path validation, and relay
currentness wrapper each separately queried `network_json`.

Retain the first decoded `PrivateServiceNetworkPath` alongside the verified
business lease only for the rest of this invocation. The selected-path query
still occurs after the original consumer login and effective path-policy reads,
and before the original exact ACL and authority-epoch reads. The combined API
uses that same typed path for full network signature/snapshot verification and
the relay-currentness helper. The immediate SQLite transaction is unchanged,
so a second read cannot observe a valid intervening management mutation.

Standalone business-lease and network-path APIs keep their original wrappers.
The standalone relay-currentness wrapper still independently reads and decodes
the database before calling the same full helper. A missing path retains the
standalone business-lease direct fallback, while the combined network-authority
API still rejects it after reading the current snapshot. Malformed paths,
signature tampering and reservation mismatches continue to fail. Every later
request queries and verifies the current database again.

No live check is removed: login/account/device state, target approval, current
membership and keys, exact ACL, effective selected path, policy epoch, original
signed deadline, the full network snapshot and signatures, relay nodes, hops,
quotas and two-hop topology continuity all remain. In particular the two-hop
helper retains its existing independent snapshot read. No cross-request cache,
new lease, retry, deadline or resource allowance is introduced. SDK canonical
decoding and usage-claim parsing are unchanged.

The existing combined-currentness regression additionally replaces the stored
path between requests with NULL, malformed JSON, a corrupted path signature and
a different reservation ID. Each complete currentness read must reject it;
the standalone business-lease NULL-path behavior and restored exact lease/path
bytes must remain unchanged. Original business-signature tamper, expiry, ACL
revocation and outstanding cumulative reservation assertions are retained.
Existing HTTP/Quinn, multiplex, live snapshot and two-hop topology regressions
remain required on GitHub-hosted Actions before the unchanged capacity workload.
Source simplification alone establishes no latency or capacity qualification.
