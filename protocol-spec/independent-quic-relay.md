# Independent native QUIC datagram relay

`nestlink-server relay --config <node.toml> --listen 127.0.0.1:28746
--quic-listen 0.0.0.0:28743` starts independent WSS and QUIC listeners with one
authenticated node-control owner. The WSS loopback default is 28746 so it does
not occupy the planned TURN/TLS 28745 listener. Caddy handles the separate node
WSS origin; it does not proxy native QUIC UDP. Ports need actual bind/firewall
validation. Ending either listener stops shared authority and the other listener.
No node service opens the control database.

## Two encryption layers

Outer QUIC uses TLS 1.3 and separate `nestlink/relay-datagram/1` ALPN, no 0-RTT or
resumed authentication. The node certificate uses its protected node Ed25519 key.
The endpoint pins `node_key_sha256` from the original control-signed allocation
and verifies TLS transcript signatures. A DNS answer or peer candidate cannot
replace that key. The listener accepts TLS before business admission; a TLS
connection alone grants no forwarding.

The node initiates one bidirectional control stream. Each message is a four-byte
big-endian length followed by at most 16 KiB of UTF-8 JSON:

1. Node sends `NodeRelayChallenge` with a fresh random 32-byte nonce.
2. Endpoint sends `NodeRelayHello` with its public key, original signed allocation
   and device signature. It binds the complete allocation, endpoint,
   QUIC-datagram transport and socket challenge.
3. The node verifies current resource/node/runtime/epoch/policy, device and
   account/session facts, grant, key and unique role. A new grant can wait at
   most 700 ms for the next snapshot. Preparation occupies no allocation role.
   The shared [carrier selector](relay-selection.md) commits only when both
   roles join the same allocation on this transport, before `RelayReady`.
4. Controller opens inner QUIC through virtual UDP; host accepts it. Inner TLS
   pins both endpoint keys from the permit. Native session proof and channel
   negotiation remain mandatory before authorized business use. The node has
   no inner key or media decoder.

The control stream stays open for the carrier lifetime. Unexpected payload/EOF,
extra streams and pre-admission datagrams fail closed. No account bearer or
cookie is sent. Shared guards from [node-resources.md](node-resources.md) enforce
current authority and both-direction rate/lifetime bytes; allocation grants and
global node leases cannot replace them.

## Datagram contract and virtual UDP

Inner UDP packets are at most 1200 bytes. Inner MTU discovery and migration are
disabled on this carrier; a new system network generation requires new candidates
and authorization. Each packet has one or two outer unreliable QUIC datagrams,
with at most 1000 payload bytes per fragment:

| Bytes | Value |
| --- | --- |
| 0 | Fragment version, exactly 1 |
| 1 | Zero-based fragment index |
| 2–3 | Complete inner packet length, big-endian, 1–1200 |
| 4–11 | Nonzero increasing packet ID per direction, big-endian |
| 12 onward | Exact fragment payload |

Fragment count follows from length. Non-final fragments have 1000 payload bytes;
final payload is the remainder. The node validates this envelope and forwards
each fragment only to the paired role. It does not reassemble or read the
encrypted inner packet. There is no arbitrary UDP destination field.

Endpoint reassembly retains at most 32 incomplete packets, expires at 100 ms
from the original first fragment and remembers the current high ID plus at
most 64 preceding IDs (65 IDs total).
Duplicates do not renew arrival time. Conflicting metadata/content terminates
the carrier; expired, evicted or completed IDs cannot be revived. Complete
packets enter a 32-packet nonblocking queue; dequeue also checks that original
100-ms age. A full queue drops a packet. Inner QUIC handles loss where reliability
is appropriate; no reliable application queue retransmits UDP.

The abstract socket reports synthetic loopback peer addresses only to inner
Quinn. It opens no loopback network socket. It rejects other destinations,
source addresses, GSO multi-packet transmits and packets over the MTU. ECN
metadata is not carried. Product path display must use the selected candidate
and node allocation, not synthetic inner addresses.

Outer Quinn datagram buffers hold at most 32 maximum fragments per direction.
Send-space checks avoid silently evicting older admitted packets. The node drops
a newly congested fragment without counting it; other guard/quota failures close
the pair. Counters count admitted encrypted fragment bytes including the
12-byte envelope, not delivery or outer UDP/TLS wire overhead. Flood loops
explicitly yield after at most 32 packets. The virtual write poller retries after
a five-ms timer when buffer space is full.

## Route, race and lifecycle

`Sdk::node_quic_route` takes an explicitly approved local `quic://host:port` URI,
resolves at most 32 addresses once within three seconds and binds the full
permit digest and verified allocation. It rejects credential-bearing URIs,
paths/query/fragment, invalid ports, unspecified/multicast addresses and
unapproved loopback. Connecting another literal or permit is refused.

`NativeEndpoint::dial_native_with_relays` admits direct candidates under the
existing address policy and relay candidates only through `NativeRelayRoute`
values from verified combined/WSS/QUIC routes. Attempts share the bounded
scheduler, permit paths and local network lifecycle. A `relay_only` permit
does not create or dial a direct peer UDP endpoint. A loopback fixture makes the
approved outer QUIC address unreachable and verifies that both endpoints select
approved WSS and prove the business session. Signed address discovery is specified
in [node-discovery.md](node-discovery.md).

Each allocation has unique committed endpoint roles shared across allowed
alternative transports. Pending candidates consume no role or business meter.
WSS and QUIC share a selector; the first transport with both proven roles
commits the pair and discards other candidates. This supports crossed arrivals,
one-sided UDP failure and multiple fixed addresses of the same carrier. Closing
an admitted role retires the allocation ID; retries after an admitted carrier
failure need a fresh allocation. Retry coordination after commit remains open. Local cleanup cannot release a control-side signed capacity
promise. Reliable signed close receipts remain open.

Both listeners share 256 active/pending sockets/tasks, at most 128 pending
allocations and 256 candidates, 1024 IP rate records and 120 incoming attempts
per IP per minute, including Retry attempts. Protocol hubs each bound 128 pairs. Unvalidated
addresses receive QUIC Retry before a handshake task is allocated. Handshake
and hello have three-second budgets, pairing five seconds and control writes
500 ms. Client setup also has the original allocation's remaining monotonic
budget. Extra streams are constrained and rejected.

Each layer's closure immediately closes the other through an owned watcher.
Its explicit carrier owner is retained by the business runtime; discarding a
candidate, cancellation, failed proof or dropping that runtime closes both
layers and aborts the watcher. A lost outer socket closes the abstract receive
channel and explicitly closes the inner connection. Guard stop/deadlines, remote/quota revocation,
HTTP resource loss and listener stop close idle sockets.

## Development evidence boundary

Real loopback fixtures use actual outer and inner QUIC sockets, native proof,
256 KiB synthetic video-channel bytes and a reverse frame. They cover remote
and quota revocation, lifetime exhaustion, HTTP resource loss, listener
cancellation, network generation, pending/established candidate cleanup,
same-pair renewal past the original grant deadline, wrong node key, wrong
transport, challenge replay and pre-authentication datagrams. Reassembly
fixtures cover reordering, duplicates, expiry, malformed data and a 5000-packet
flood.

Shared-selection fixtures include both directions of one-sided UDP failure,
crossed role/transport arrival orders with either carrier winning, two approved
loopback literals, duplicate candidates, pending cancellation/timeout/revocation
and continued forwarding after loser cleanup. Preparation tests use actual
signed tickets and endpoint proofs, then change current issuer/authority or
expire the fixed monotonic ticket before commit. These do not prove DNS routing
across multiple nodes or retry after an admitted carrier fails.

The network-stop fixture exposed an outer carrier remaining open after inner
business stop. A later parallel byte-exhaustion test found that node closure
could leave the client waiting for a frame while the abstract socket driver
handled congestion. The owned bidirectional close watcher fixes both lifetime
defects without increasing the two-second deadline; failed and passing logs
are preserved. These checks do not validate cross-host
NAT/MTU/loss/congestion/migration, actual media, 72-hour/capacity load, installed
products or G5/A01–A21. TURN, edge/tunnels, browser media, UI/platform integration,
signatures and full product acceptance remain open.
