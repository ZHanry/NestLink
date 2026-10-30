# Observe the original proved business connection without replacing its owner

Status: source implementation; exact-source Actions pending. W13 remains in
progress; route selection, standby switching and product display remain open.

The existing Scheduler ends its first successful race. Keeping a new score type
beside it would not create ongoing production observations. A second transport
owner would also overwrite ChannelRuntime's existing carrier cleanup owner.

Two approaches were considered. A new standalone connection manager could
sample every path but would duplicate admission, endpoint and lifecycle owners.
An optional sampler held by the original ChannelRuntime can observe its actual
proved Quinn connection and join before that original connection and carrier
are released. The latter is selected. Quinn supplies transport measurements;
NestLink supplies only the bounded observation policy and business binding.

NativeConnection enables sampling after successful mutual business proof.
NativeSession and NativeSessionControl expose a read-only handle. The NRD1 and
NRD2 business adapters use the same source, binding it to the original verified
PathGrant ID, transport group, purpose, route binding, business permit digest
and business generation. Native candidates retain their original network
generation. Missing legacy network grants and routed candidate data remain
explicitly absent. Observations confer no admission or migration authority.

Every 500ms, the sampler reads only its original inner Quinn connection. The
first poll establishes a baseline. RTT is refreshed only when a later poll sees
a new received ACK; an initial RTT estimate is not a measured result. The change
between consecutive smoothed RTTs is labeled as such, not as one-way jitter.
The packet window reports sent packets and newly declared lost packets. Losses
can be declared for older packets, so these counters are not divided into a
fabricated window loss probability.

Completed local business payload writes and complete audio DATAGRAM enqueue
events provide an offered business TX window. Proof, renewal, framing and
retransmission are excluded. This is neither delivered goodput nor available
bandwidth. Available rate and cost remain unknown. Idle polls do not renew
measurement timestamps; values expire after three seconds. Read-time freshness
also handles an executor that has stopped emitting samples.

The read-only handle retains measurements and a terminal watch receiver, not
the connection, lease capability or task owner. It observes the synchronous
business stop directly, so stop cannot return while the handle still claims
live metrics merely because the sampler has not been scheduled. Cleanup stops
and joins the sampler before releasing the existing connection/endpoint/carrier.
Cancellation retains the original absolute cleanup deadline and receipts.

New regressions cover initial estimates, idle/expired feedback, deferred losses,
counter/clock resets, actual Quinn payload writes, immediate terminal visibility
without yielding, preservation of the original carrier owner and socket release.
Existing real NRD1, NRD2 and native ICE business tests also check original
bindings and retain the read-only handle across cleanup. These are scoped
laboratory checks, not full W13/AC20/AC21 or target qualification.
