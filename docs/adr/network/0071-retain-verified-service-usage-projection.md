# ADR 0071: Retain the original verified usage claims inside a sealed lease

Status: implemented; awaiting exact-source GitHub-hosted validation.

The private service network verifier and SDK decoded the same immutable nested
usage grant again after `verify_service_lease` had already verified its signature,
decoded it and validated its claims. Direct currentness paid for these extra
parses on every readback; relay binding helpers repeated the same work as well.

Store the typed claims returned by that original usage verifier as a private
field of `VerifiedServiceLease`, exposed only by an immutable reference. Reuse
this projection for the original reservation ID, request ceiling and relay wire
allowance comparisons. The sealed object cannot be constructed or mutated by
callers. Its signed lease bytes, usage signature, digest, publication binding,
issuer and every existing verification step remain unchanged.

The alternative was a broader rewrite of protocol `ServiceLeaseClaims::validate`
and `publication_binding` to share their parse. That touches validation order and
generic protocol boundaries unnecessarily. This change leaves those checks as
they are and only reuses the exact result already returned by the mature verifier.

This is request-local immutable data reuse, not authority caching. Later HTTP
readbacks still verify the complete grant and every original live management,
current-time, network, private envelope and delegation check. No lease, rate,
quota, retry, handshake bound or original load assertion changes.

The new regression compares the projection with the independent original usage
verifier and exact signed bytes, checks a valid replacement reservation remains
distinct, and rejects a nested altered signature, foreign issuer, mismatched
target or insufficient lifetime even under a freshly signed outer lease.
The capacity workflow runs it before the unchanged original load alongside all
prior currentness, snapshot, HTTP, negotiation and multiplex regressions.

No performance result is inferred from removing these parses. Source 9df4140
run 41454242981 remains failed at 798 flow readiness events, without a complete
1000 simultaneously live flow wave. Original failures remain in the evidence.
