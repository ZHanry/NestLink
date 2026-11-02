# ADR 0069: Check delegation against the original sealed service lease

Status: implemented; awaiting exact-source GitHub-hosted validation.

The complete private network grant verifier previously verified the nested
service lease through its issuer delegation and then verified the exact same
service lease again while verifying the private business envelope. Each service
lease verification also verifies the same nested usage-grant signature. This
repeated immutable cryptographic and canonical decoding work on both sides of
every current-authority readback.

Retain the original complete private-envelope verifier. Its sealed
`VerifiedServiceLease` already records the exact issuer public key. Reuse that
object for a delegation check requiring the same issuer, deployment, security
epoch, policy revision, complete lease-within-delegation interval and both
original current-time intervals. The standalone delegation `verify_lease` API
still verifies its signed input and delegates to the same check. No unverified
claims, caller-supplied issuer or reconstructed lease can satisfy the new API.

No signature is omitted from the accepted chain: the private envelope, service
lease, usage grant, delegation and every network signature still validate.
Only the second verification of the identical service and usage signatures in
one invocation is removed. Each later readback repeats all original verification
and live management checks. There is no cross-request authority cache, new
deadline, retry or changed resource budget.

The new regression requires a positive sealed lease and rejects an otherwise
valid sealed lease from another issuer, changed deployment/security/policy,
lease intervals outside the delegation and expired/not-yet-current time.
The capacity workflow runs it alongside original storage, live snapshot,
HTTP, negotiation and multiplex regressions before the unchanged load.

Run 41449447897 at d7e735d passed all original regressions plus the live snapshot
counterexamples. Its original release pair-window workload reached 751 ready
flows, then received 403 PermissionRequired near original authority expiry.
It remains failed, alongside f3cfb45's 1000 readiness observations followed by
zero live targets after the original two-second hold. No complete wave or
capacity acceptance is established by either result or this source change.
