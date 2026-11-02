# ADR 0076: Reuse exact canonical network claims within one Store verification

Status: implemented; awaiting exact-source GitHub-hosted validation.

The efebb7b phase diagnostic, run 41476929737, retains the original failed
capacity workload. The after-all-controls-recorded window contains 1432 CPU
samples, including 266 matching serde names. It includes continued checks and
failure teardown, has no call graph and cannot identify the cost of an individual
Store operation. The separately committed evidence preserves that limitation,
all preceding checks, all 58 payload hashes and the actual carrier failure.

Manual review identifies one exact duplicate independently of that profile.
Store's private network `signed(view)` decodes canonical claims to validate the
envelope schema and grant ID, then discards those claims. Its immediately
following membership or raw-grant verifier decodes the same immutable signed
bytes again. ADR 0072 already introduced a canonical candidate and the unchanged
signature/currentness core for identity's private-service path, but intentionally
left Store's independent member and envelope ordering unchanged.

Expose that existing candidate as an opaque type with private fields, a checked
canonical decode constructor, an immutable claims accessor and a consuming
verify method. No API accepts caller-provided typed claims alongside signed
bytes. The candidate borrows its exact immutable signed object, carries no
authority and cannot become a VerifiedNetworkGrant except through the existing
strict signature, exact-byte transcript, authority-bound digest and current
context verification. The mature canonical parser and cryptographic routines
remain the only implementations.

Store's thin view adapter now checks both original canonical base64 fields,
decodes the exact canonical claims once, checks the same metadata and consumes
that candidate in the same invocation. Consumer and host members still undergo
fresh snapshot active-member lookup before signature/currentness verification,
followed by installation/key/epoch binding and the original role check. A small
private member-verifier callback shares that original sequence. The standalone
raw member API still performs active-member lookup before decoding; Store's
view path still validates envelope metadata before active-member lookup. Every
failure keeps its original StorageError mapping and ordering.

The alternative was to export a fully verifying view helper and move member
lookup after it. That would change which failure wins when membership and a
signature are both invalid. A new independent decoder would also duplicate the
mature existing implementation. The opaque existing candidate and private
callback preserve both boundaries with no such reordering.

Only Store's private network path verification uses the new candidate entry.
Its standalone signed-view wrapper and relay issuance callers retain their
original behavior. The complete currentness transaction, full bounded snapshot,
all revocation collectors, all signatures, usage/business/path/relay binding,
clock checks, poll cadence, immutable leases and workload assertions remain.
No row, authorization decision or time is cached across requests.

Existing hosted regressions gain counterexamples for canonical claims combined
with another original signature, a correctly signed wrong member, and invalid
schema/grant metadata combined with a corrupt signature. Metadata must retain
the original Forbidden result before signature verification. Existing exact
bytes, issuer/digest, live member/role, expiry, revocation and external-state
regressions remain required. No local build, formatter, lint, syntax check or
test ran; only the next exact-source hosted run can validate this source and
assess its effect on the original capacity failure. AC68 remains failed.
