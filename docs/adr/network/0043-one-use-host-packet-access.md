# Explicit host packet access and one-use online runtime

Status: source implementation in progress; no TUN or target qualification.

Joining a space and obtaining a PathGrant cannot authorize arbitrary IP access.
The first host-only NetworkAccess API reuses the existing independently signed
NetworkAccess, Connectivity and Path grant domains. Only the destination device's
account can issue a host approval; a space administrator cannot approve another
account's device. Both memberships, current keys, current address epochs, the
direct-path policy and the exact /32 or /128 addresses are checked in one durable
transaction. The maximum lifetime is 60 seconds and is intersected with both
memberships. Reads return the original signed bytes and a fresh two-row scoped
directory, never a renewed credential or a broader directory disclosure.

Two choices were considered for budget ownership: reconstructing a packet policy
from a saved signed graph after process restart, or an online one-use start per
endpoint. Reconstruction resets local cumulative counters and can reuse the same
quota. The selected API atomically claims a previously NULL source or destination
owner in SQLite after rechecking the complete live graph. Each endpoint's account
can claim only that endpoint. Every repeated claim, including the identical public
owner UUID, is denied. A lost successful response consumes the claim and prevents
local OS creation. GET, database reopen, stop and revoke never restore a claim.
A subsequent runtime needs a new grant and a new destination-account approval.
The owner UUID is correlation data and grants no authority.

The ordinary SDK owner pins the management origin and network authority, obtains
an explicit local approval of the access digest, performs the online claim and
refreshes the original graph and current address bindings. Any refresh failure,
observation gap, changed login or terminal condition stops the original owner.
Both endpoint policies count both directions against the original cumulative
byte budget. A second path, codec or TUN must not reconstruct that budget.

Wire parsing reuses etherparse 0.21.0; carrier fragmentation and reassembly reuse
the existing authenticated datagram codec and transport owner. NestLink adds the
peer, source-prefix, independent RouteExport and L3/L4 policy decisions. The first
1280-byte host slice rejects IPv4 options/fragments and every IPv6 extension or
fragment, including atomic fragments. It never implements a permissive fallback
parser or unbounded IP fragment cache. Reverse traffic is bounded by the original
admitted flow; identity and address checks precede OS injection.

The one-use HTTP, concurrency, persistence, expiry and revocation cases and packet
parser/admission cases are source tests awaiting their exact GitHub-hosted run.
Managed TUN provider, least-privilege OS resource owner, production CLI wiring,
dual-stack application traffic, VPN coexistence and target lifecycle evidence
remain required. These contracts alone do not satisfy W22 or AC32/35/36.
