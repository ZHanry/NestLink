# Admit and forward NRD2 through registered production nodes

Status: source implementation; exact-source hosted validation pending.

The existing node listener, dynamic TLS pins, RelaySelector, Hub Pair, original
allocation deadlines, cumulative meters and cleanup owners now carry NRD2.
The production relay command passes its registered NodeIdentity explicitly to
`serve_with_chain_identity`; NRD1 and legacy retain their independent ALPNs.

A second standalone forwarding pool would bypass shared capacity. Accepting
only the remote node's TLS certificate would omit the local original allocation.
NRD2 therefore uses one admission stream on the pinned outer QUIC connection:
the receiver challenges its fixed neighbor, checks current full-chain authority,
and signs a fresh reciprocal challenge for the neighbor's original allocation.
Both node ends independently admit the opposite fixed slot. The return allocation
must match the original complete resource, and an endpoint cannot substitute the
other relay. A final Ready exchange precedes forwarding. Packets received while
pairing remain in Quinn's existing bounded queue and cannot be forwarded before
both local slots and possession checks succeed.

Only the first ordered relay dials the second, from the existing node listener
UDP socket. Current NodeControl descriptors derive the exact neighboring grant
ID and endpoint from the policy-signed resource snapshot. At most three attempts
share the original absolute deadline; attempts never create credentials, refresh
deadlines or recycle a terminal Pair. Pending dial attempts and the original
admission stream are owned by the listener's existing task set.

The SDK authenticates current management readback against the operator-pinned
network authority and original business permit, freezes the complete ordered
view, selects only its fixed first/last node and proves the same SessionPermit
through the existing business owner. Current management reads supply node UUID
and endpoint mapping; every handoff and subsequent observation compares the
entire original view. The original login, devices, origin and absolute deadline
remain bound. Cancellation, mismatch, omission, expiry or revocation stops the
original owner and physical sockets.

New source regressions cover NodeControl descriptors, live and terminal Pair
lookup, unchanged original deadlines, and two registered-node SDK OS FileRead
scenarios for both canonical business endpoint orders. Those integration cases
explicitly seed signed topology fixtures. They are not evidence for continuous
production adjacency discovery, bootstrap or refresh. Those paths and complete
W12/AC18/AC19 qualification remain mandatory. No release readiness is claimed.
