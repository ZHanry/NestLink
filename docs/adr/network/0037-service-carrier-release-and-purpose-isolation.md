# Service carrier release and purpose isolation

Status: source implementation; exact-source hosted validation pending.

## Problem and alternatives

The public service runtime used the existing pinned QUIC carrier and the mature
generic `ServiceFlowPermit` forwarding owner. Its cleanup monitor considered a
joined worker and `Endpoint::wait_idle` sufficient to report `Stopped`, while
the runtime and monitor still retained Quinn connection/endpoint references.
Those references can retain the UDP socket and writable pollers. A service
restart or upgrade therefore could observe a completed logical cleanup while
the original physical port was still owned.

Polling whether the port can be rebound is unsuitable as a production release
proof: an unrelated new owner can acquire the same port. The selected approach
transfers the carrier's original one-use socket/poller completion receipt to
the existing cleanup monitor. It does not create a second forwarding engine,
lease, usage meter or transport scheduler.

## Decision

`Connected::take_socket_release` transfers that original receipt exactly once.
`LocalServiceRuntime::wait_stopped` first stops authority and releases its last
connection clone. The cleanup monitor retains the original worker and report,
joins that worker, closes and drops its endpoint, then awaits the physical
receipt before returning `Stopped`. Timeouts and abandoned waits keep the same
physical release task. A failed worker cannot certify joined children; a lost
receipt cannot certify release. Drop retains the same work in the existing
runtime reaper.

Service JSON framing now accepts Tokio `AsyncRead` / `AsyncWrite`, preserving
the existing length limit and wire bytes. `BiStream` remains the concrete QUIC
adapter. This permits the existing service proof and generic authorized stream
forwarder to be reused without embedding concrete Quinn stream types in the
proof codec. It does not introduce a reliable UDP fallback or authorize a new
carrier.

The same routed QUIC establishment owner also chooses the inner ALPN from the
verified `RouteAuthorization` purpose. RemoteControl retains its existing ALPN;
PrivateService uses the existing service ALPN. Both retain exact mutual TLS
endpoint pins, disabled early data, the original route deadline, opaque NRD1 /
NRD2 forwarding, bounded queues and original socket receipts. The negotiated
ALPN is checked after TLS. There is no public arbitrary-ALPN override. Signed
private one/two-relay verification remains independent of a SessionPermit and
cannot expand the original shared service byte ceiling.

## Validation and limits

Source regressions exercise real tracked UDP endpoints with an extra endpoint
holder, a joined worker, cancellation of a pending wait, final release and actual
port rebinding. Existing slow-worker and ordinary-thread Drop cases retain their
assertions and now use the tracked carrier. Generic framing tests cover request
FIN followed by a response, invalid lengths without a body, and truncated input.
All execution must be on GitHub-hosted Actions under R02.

W16 remains in progress. A generic proof codec and purpose-aware routed carrier
do not by themselves establish production private relay authority distribution,
service publication over every alternate transport, four-protocol public edge
qualification or external ingress acceptance. None of AC25/AC26 is marked
passed from this source change. Public HTTPS backend trust, source ACL, target
approval, short leases, half-close and durable usage owners are retained.
