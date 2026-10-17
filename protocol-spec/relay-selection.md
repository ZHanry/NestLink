# Pairing native relay carrier candidates

WSS and QUIC of one registered node share a `RelaySelector` and its authenticated
`NodeControl`. The CLI uses `serve_with_selector` for both listeners. A standalone
single-protocol `serve` creates its own selector; a caller combining listeners
must explicitly share the same selector. Neither listener opens control SQLite.

Each socket proves the original allocation, fixed endpoint key, allowed transport
and fresh socket challenge before registering a candidate. Preparation grants
no forwarding, allocation role, business connection count or admitted bytes.
Candidates are grouped by allocation identity and match only opposite roles on
the same transport. Multiple candidates of the same role and carrier are allowed
within the total budget, including attempts at different approved literals.

The first matching transport consumes both candidates and rechecks each one's
current node gate, snapshot, stable grant binding, delegated issuer and original
monotonic ticket deadline. Only successful reservations are handed to the chosen
sockets through owned one-shot channels. The protocol hub then sends ready after
both live guards register. If commit or handoff partly fails, dropping the guards
stops the committed roles; forwarding never follows from preparation alone.
Successful commitment retires other candidates for that allocation.

Each pending registration has a random cleanup token. Cancellation, socket EOF,
unexpected early data, validity failure or the original five-second pairing
deadline removes only that registration. Dropping an uncommitted loser cannot
close the winning pair or mark an unused UUID closed. Closing a committed guard
still closes both roles and permanently retires that UUID for the node runtime.
Retry after committed carrier failure requires a fresh grant; coordinated retry
remains separate unfinished work. Signed endpoint discovery is specified in
[node-discovery.md](node-discovery.md).

Both listeners share at most 256 active/pending sockets, 128 pending allocation
identities, 256 candidates, 1024 IP rate records and 120 attempts per IP per
minute. QUIC Retry attempts consume the same IP budget. The data services retain
their bounded queues, finite protocol hubs and handshake/write deadlines. Pending
state neither refunds control-side signed capacity promises nor reports business
bytes. Reliable close receipts remain unfinished.

Development tests use real sockets with both directions of a one-sided UDP
blackhole, crossed arrival orders, either carrier winning, two explicitly approved
loopback literals, duplicate socket candidates, pending cancellation/timeout/
revocation and continued data after loser cleanup. Signed-proof unit tests recheck
issuer changes, global stop and fixed monotonic expiry despite newer authority.
These tests are not company/mobile network, installed-product, DNS/multi-node,
sustained-load or formal capacity acceptance.
