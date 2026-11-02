# Capacity validation profiles and retained failures

The original hosted capacity scenario offers 100 enrolled installations, 20
active service pairs, 50 real TCP target flows per pair and three reconnect
waves. It requires all 1000 targets to remain simultaneously active for the
original two-second observation, exact application bytes, durable accounting,
original finite authority, and physical cleanup. These assertions are unchanged.

Run 41431119457 at 8c6ecfd passed all seven native HTTP admission regressions,
the explicit legacy/multiplex negotiation test and six original multiplex owner
regressions. All 20 multiplex control owners became ready. The first pair's
first application stream then failed at its original immutable lease expiry;
there are no ready application-flow samples. The run remains failed. Its
receipt, samples, logs and their verified hashes are retained in
`evidence/capacity-attempts-20261102.json` with every earlier failed attempt.

The workflow now accepts an explicit `debug` or `release` build profile, keeps
`debug` as the default, and records that selection in its receipt and artifact
name. An additional production-profile observation uses the existing release
optimization settings and locked components. It does not extend a lease or
handshake deadline, alter the offered load, disable a currentness readback,
change a rate/quota/database gate, retry a mutation or refresh business authority.
It retains the same assertions. Both its success and failure must be recorded
separately from the debug result. No application source optimization or actual
capacity success is inferred merely by selecting that profile.

An optimized result is useful because the release packages are optimized too;
it cannot qualify debug performance or replace either prior failure. A failing
optimized run requires further implementation and diagnosis. This single
hosted-process experiment also cannot qualify 100 independent physical nodes,
loaded external management/relay machines, all bounded queues or a 24-hour soak.
