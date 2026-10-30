# Keep functional control-plane deadlines with optimized dependency arithmetic

Status: hosted before/after validation pending; no performance qualification.

At eab863b the real registered-node scenarios reached current signed topology,
then repeatedly received reservation Conflict and exhausted the unchanged setup
budget. Rejected POST requests took approximately 350-569ms while the original
production reporting period is 500ms. The same log also records 201ms database
admission failures. It does not isolate how much time belongs to curve
arithmetic, serialization, authentication or database contention.

The exact current advertisement digest remains mandatory at reservation, and
the original request IDs, original grant expiry, 1000ms advertisement TTL,
500ms report period, 700ms probe/HTTP bounds and test deadlines remain unchanged.
Accepting historical heads or extending those periods would alter authorization
or hide the observed failure, so neither is selected.

Two implementation options were considered. A cache of successful Ed25519
verifications could avoid repeated immutable arithmetic while rechecking all
current policy, but adds shared security-sensitive state and a new invalidation
review burden. Compiling the already locked mature arithmetic provider with its
production optimization uses the existing implementation and leaves every
verification and live policy check in place. The latter is selected first.

The workspace dev profile sets opt-level=3 only for curve25519-dalek and
ed25519-dalek. Cargo's test profile inherits dev. Application code retains its
normal dev settings; debug assertions and overflow checks retain their defaults.
Release settings and dependency versions/checksums do not change. GitHub-hosted
Actions perform the builds and all actual verification. No local toolchain is
run, no assertion is removed, and no pass is inferred from the profile edit.

This is a functional laboratory configuration. A passing result would establish
only the unchanged scoped scenarios under this configuration. High-latency,
loaded control planes, actual capacity, production release performance and all
external acceptance still need their own measured evidence. Persistent Conflict
or admission failures require implementation work, not another deadline change.
