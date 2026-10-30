# ADR 0002: independently versioned grants and the first real slice

Status: first-slice source contract implemented, Actions and production integration pending.
Date: 2026-10-30, Asia/Shanghai. Target: 0.8.0RC / 0.8.0-rc.1.

## Decision and alternatives

We compared adding fields to v15 permits/proofs with introducing explicit
`network-core-v1` objects. We choose additive network objects: v15 proofs bind
their existing path and connection generation, and old peers cannot interpret
new permissions. Both peers must advertise each new capability. Required unknown
capabilities fail; optional unknown capabilities do not grant rights. Failed
new-protocol authentication never triggers an implicit legacy downgrade.

We compared a new network daemon/scheduler with extending the current connectivity
policy and native SDK adapter. We retain the current scheduler and native
QUIC/TLS/WSS runtime. Existing business proof and queue ownership remain mandatory.
The first change preserves typed handshake errors through this real production
chain, so identity/protocol/permission failures terminate the candidate race while
ordinary reachability errors keep their fallback budget.

## First-slice wire representation

`protocol::network` uses bounded, versioned serde structs. Canonical claims are
UTF-8 JSON generated in declared struct field order, without insignificant
whitespace, with integer timestamps/epochs, numeric byte arrays and canonical
UUID/IP encodings. Decoding rejects unknown fields, duplicate fields and any bytes
that differ from canonical re-encoding. This is a NestLink-specific canonical
profile, not a claim to implement RFC 8785. It contains no floating-point values
or free-form JSON maps. Independently generated Node/OpenSSL reference vectors
must prove compatibility before the contract is frozen.

The Ed25519 signed message is `purpose_domain || u32_be(claims_length) || claims`.
Each of membership, connectivity, path, transit, route-export and network-access
has its own `NestLink/network/v1/…` domain. The authority key derives from the
existing protected deployment seed using HKDF-SHA256 with a new salt/info pair;
it is separate from legacy permit and node-policy keys. A configured pinned
authority, deployment, space and current policy epoch are all required.

PeerId is the existing SHA-256 installation public-key fingerprint. Membership
also binds installation UUID, public key and membership epoch. SpaceId is a
canonical non-nil UUID independent of account/deployment identity. Roles manage
space resources and do not grant remote control or raw IP access.

Connectivity references both verified member digests and the separate business
grant. Path grants bind that connectivity digest, canonical peer pair, purpose,
explicit allowed relay identities and a maximum of two relays. Groups isolate
the exact verified authority and PathGrant, including scope, purpose, policy
epoch and expiry. No `direct_only` connection is pooled with a relay-capable
group. A parsed claim or a single verified signature is not a complete chain.

Transit permits bind group, route, relay, adjacent peers, hop budget and quota.
Route export and raw-IP access are separate types. Prefix metadata reuses the
existing ServiceSourceNetwork validator; only product-specific default-route,
identity, rule and quota restrictions are added. Actual packet parsing,
fragmentation, source ownership and connection tracking remain W22/W23 work.

## Failure, migration and integration boundaries

Single-grant verification checks canonical bytes, pinned issuer, exact space and
epoch, explicit revocation and lifetime. A complete path chain must recheck all
objects at use, bind references/peers/purpose, and prevent a child lifetime from
extending its parents. It establishes network path permission only; v15
SessionPermit/ServiceLease or NetworkAccessGrant still authorize business data.
The authoritative persistent revocation/member snapshot and its anti-rollback
behavior are implementation requirements, not properties of a caller-provided
verification context.

`path-migration-v1` is represented as a separate negotiable capability, but no
production offer advertises it yet. W14 must implement endpoint-signed proposal
ID, session generation, old/new path epochs, verified grant digest, challenge,
deadline, deterministic simultaneous-proposal ordering and idempotent ACK/commit.
Old-path failure requires a newly authenticated control-only carrier. Permission
checks precede business streams, revocation wins over drain, and failed continuity
uses existing safe application recovery. These are not implemented by the new
grant parser or capability helper.

W07 MTU/route authentication, W09 bilateral same-socket ICE, W14 continuity and
RTT/PMTU convergence remain unproved until real Actions L2 experiments. The first
slice adds no runtime dependencies or EasyTier code. Existing lock versions and
later provisional components are documented in components.json.

## Validation and rollback

Actions runs canonical parsing/group/capability negative cases, signed membership
binding, key-domain separation and chain rejection tests. The SDK also runs real
wrong-key QUIC/TLS tests while retaining ordinary network fallback cases. The
format workflow emits patches for review; it does not turn failing source into
passed evidence. These results cannot close AC03's full production negotiation,
AC04's two-endpoint/two-relay experiments, or any target acceptance by themselves.

The source additions do not enable new grants in old production APIs or modify
v15 signed objects. Reverting an unused first-slice module requires no schema or
OS rollback. Once storage/system integration begins, separate persistent
revocation/quota/schema fences and owned-resource cleanup must precede rollout.
