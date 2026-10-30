# ADR 0011: Reuse an identical chain only inside live node snapshots

Date: 2026-10-31 (Asia/Shanghai). W11 implementation follow-up; exact-source
Actions and two-node regression results are required before qualification.

The node polls its signed resource snapshot every 250 milliseconds. The previous
implementation verified the complete immutable network/business chain on every
poll, including the same permit and five network signatures, while holding the
node state mutex on its Tokio control task. Two independent nodes and several
endpoint owners repeat this work. Existing lab failures include node TLS client
pin refusal and inner endpoint-proof timeouts; this observation does not prove
that repeated verification caused either failure.

Keep the mature Ed25519 and grant verifiers for every new or changed chain.
Reuse a previous verified binding only when all of these conditions hold:

- The new exact-query node-policy signature has already been verified and the
  complete snapshot still passes its sequence, runtime, policy, quota and time
  validation. Observation has the unchanged one-second authority ceiling.
- The previous snapshot is still live. Snapshot expiry, omission or stop removes
  its entries; there is no separate credential cache or new resource budget.
- The allocation issuer and quota revision are identical.
- The SHA-256 of the complete resource protobuf is identical. It covers the
  authority key, every network credential, the permit and allocation claims.
- The complete allocation claims match and both the original monotonic deadline
  and signed route expiry remain in the future.

The fresh snapshot must explicitly include each route. Reuse grants no new
time: the original grant deadline remains unchanged for an unchanged sequence,
and paired connection/byte counters retain their existing owners. A changed
chain is verified normally and still faces the existing no-retarget/replay
checks. TLS possession and the fresh admission challenge are never cached.

Alternatives considered were a process-wide signature cache and moving the
whole mutex-held operation to an unbounded blocking task. Both introduce
additional lifetime, capacity and cancellation ownership. This narrow reuse
uses only the existing bounded snapshot map and immutable digest comparison.
It does not alter the network protocol, deployment trust, three-second proof
budget, seven-hundred-millisecond poll budget or terminal cleanup behavior.

Regression coverage requires repeated fresh observations to preserve the same
allocation deadline and pair, changed permit/issuer rejection, omission stop,
expiry/stop discarding reuse, and renewed full verification after those stops.
Both real-node integration and complete workspace gates remain required.
