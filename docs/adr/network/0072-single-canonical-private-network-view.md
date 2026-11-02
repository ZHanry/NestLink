# ADR 0072: Decode one private network view canonically once

Status: implemented; awaiting exact-source GitHub-hosted validation.

The identity private-service verifier passed every NetworkGrantView through
remote::signed and then verify_network_grant. Both independently called the
same mature GrantClaims::decode_canonical, including validation, serialization
and exact-byte comparison. A Direct bundle repeated this for four grants, and
relay bundles also repeated it for each transit grant.

Retain one internal decoded candidate that borrows the exact immutable signed
bytes and owns the typed claims returned by that original canonical decoder.
The existing public verify_network_grant API still decodes once before using
the common private verification core. A private view entry decodes both base64
fields, checks canonical base64 equality, decodes the canonical claims once,
then checks the original schema and grant-ID metadata before that same core.
Only the identity private-service closure uses this entry in this change.

The candidate is private and unverified. No public API accepts arbitrary typed
claims alongside signed bytes. The common core retains the original exact
domain, original byte length and original signed bytes, strict Ed25519 check,
authority-bound digest and check_current. Current authority/deployment/space,
policy epoch, revocations and time still fail on every invocation. Membership,
business/path binding, delegation, transit, quota and independent currentness
checks above this entry are unchanged. No cross-request cache is added.

The alternative was to change Store snapshot membership and SDK standalone
decode APIs at the same time. That would broaden live-state ordering and error
mapping scope unnecessarily. Those APIs, remote::signed and all other callers
remain independent with their original behavior. The original network wire,
signed bytes, deadlines, capacity workload and assertions are unchanged.

The new regression compares verified claims, issuer and digest with the public
raw-byte verifier and retains exact standalone bytes. It rejects correctly
signed noncanonical JSON, noncanonical/invalid base64, substituted metadata,
corrupt signatures, a foreign issuer, future/expired grants, changed policy and
revocation after a successful read. Metadata still fails before signature
verification. Independent signature/reference vectors and full private service
and snapshot regressions remain required on GitHub-hosted Actions. No latency
or capacity qualification is inferred from this source simplification.
