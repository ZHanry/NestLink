# Private service relay authority and original carrier ownership

Status: implemented, awaiting exact-source hosted validation.

The private service's signed lease, fixed local target approval, consumer ACL,
space memberships and cumulative application budget remain distinct from a
remote-control SessionPermit. A space member or a relay node cannot turn a
service grant into a remote-control, arbitrary-port or public-ingress grant.

## Selection and authorization

The existing private-access API accepts an explicit Direct choice, or one/two
registered relay nodes ordered from the canonical first peer. Relay selection
includes the exact request ID, consumer, service/exposure revisions, application
budget and, for two hops, both current topology heads. The consumer installation
signs the complete request with the private-service route domain. An exact retry
retains its immutable request and graph; a failed transaction reserves nothing.

Issuance uses one immediate SQLite transaction for the existing service usage
grant, all network grants and all relay hop reservations. Membership,
connectivity, path and transit are verified independently. Both-hop neighbor
incarnations and continuous topology observations use the existing remote-chain
capture/update/withdraw algorithms. A stopped and restarted neighbor cannot
resurrect the old private route.

The original delegated service signer additionally signs the relay metadata:
node IDs, keys, registered endpoints/revisions, complete ordered TransitGrants,
route ID and topology digests, bound to the original business digest. This closes
the gap that Transit peer fingerprints alone do not authenticate a node URI.
The SDK also applies the machine's own dialing scope to the complete DNS answer.
Public unicast is the default; private prefixes require local selection, and
loopback requires both local selection and registered node permission.

## Shared capacity and separate meters

Schema 42 adds private-service relay hops to the original all_relay_capacity
view. Existing node/account/global concurrency and quota admission include them.
The original four service ledgers reserve the plaintext allowance once, including
in Both mode. Each relay has a separate finite encrypted-wire allowance:

`min(original relay bytes_per_allocation, checked(2 * plaintext_ceiling + 65536))`.

Overflow refuses issuance. The 64 KiB is a bounded setup/framing allowance; it
does not enlarge the service's application allowance or promise unlimited setup
retries. The network signer authenticates the wire limit, the node applies the
original allocation meter, and the host still charges only admitted application
bytes. Revocation does not refund an unsealed application promise.

Node resource snapshots carry the complete private-service bundle in its own
field. Remote business_permit, relay_bundle_json and chain_bundle_json fields
must be empty. The independently rooted service delegation and network chain
are verified before reusing the existing node candidate, pair, slot, meter and
close owners. No legacy allocation-ticket verifier accepts this private bundle.
Original relay-close receipts can seal the immutable private allocation even
after ACL or topology withdrawal; they release transport slots without altering
the separate service ledger's terminal accounting.

## Actual endpoint and command paths

The authenticated host inbox returns paginated current relay grants for the
original service/runtime. The host scans with fixed page/time bounds, verifies
every complete bundle and starts at most one worker for each original grant.
Omission from a page does not grant renewal or independently assert revocation.
Each worker retains its own currentness checks and original absolute deadline.

Both endpoints reuse NRD1/NRD2, the existing dynamic-node TLS admission, mutual
possession proofs and RoutedEstablishment. Pre-admission TLS access_denied may
wait for the original resource publication under the fixed deadline; no Hello
or possession proof is retried. The verified private purpose chooses SERVICE_ALPN
for the inner installation-pinned connection. The existing service Hello,
nonce/open/ready proof and LocalTargetOwner/PrivateServicePublication forward
the actual approved stream or datagrams and retain usage reporting.

PrivateServiceConnection retains either its original direct physical owner or
the RoutedTransport, revocation source and management observer. Cleanup joins
the original observer, virtual socket/pollers and physical node adjacency. An
ordinary connection close is not a physical release receipt. Stop and expiry
also signal every original host worker before listener cleanup.

The daemon's explicit host command performs local target approval and exposure
configuration, retains the original protected login owner and installation's
cumulative usage directory, and grants no consumer ACL automatically. SOCKS and
native-stream consumers can explicitly choose one/two relay nodes and local
dialing scope. Direct remains the default, with no automatic path fallback.

## Evidence and remaining scope

The hosted suites include a real Store issue/retry/tamper/shared-capacity/inbox/
node-snapshot/terminal-close scenario, and six actual registered-node SDK cases:
single/two-hop TCP, original consumer signout, fixed approval expiry, and
single/two-hop UDP including empty datagrams. These are source additions until
the corresponding Actions logs prove their execution. No target acceptance or
release qualification is claimed by this ADR.

Raw local TCP/UDP mapping still requires an independently verified OS access
gate. Public four-protocol ingress, continuous path migration, external NAT,
mobile WireGuard, TUN, HA and device soak qualification retain their own work
packages and evidence requirements.
