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

The first explicit release-profile attempt, run 41434724934 at c010515,
successfully compiled the capacity executable in 406.53 seconds. The following
HTTP regression command spent its entire original 180-second execution budget
compiling a second release test harness; no HTTP test or offered load executed.
It remains a failed build/execution orchestration attempt, separate from the
original failed debug load. The workflow now compiles all three original test
harnesses together under its existing 1200-second build budget, records their
individual hashes, then executes those binaries under the unchanged 180/300/660
second execution budgets. It also verifies the exact executed test counts and
records a command before starting it so a timeout cannot omit that command from
the provenance. Application deadlines, gates and assertions are unchanged.

Run 41437445247 at b97182d executed the explicit release-profile workload after
all three original harnesses built. The seven HTTP, one negotiation and six
multiplex owner regressions passed. All twenty control owners were ready, and
61 actual application flows reached readiness. Wave zero, pair eight, flow two
then hit the original three-second handshake deadline while awaiting management
currentness. There is no wave_live sample or completed thousand-target wave.
Its official archive and all eleven receipt files were hash-verified. This
original pair-window execution remains failed.

The original pair-window scenario permits eight pending application opens per
pair, or 160 across the shared management origin. A separate test and explicit
workflow schedule, origin-window, observe a ramp with eight pending opens across
that origin. It retains each original per-pair limit. This scheduling observation
is recorded separately; it does not replace the original scenario or qualify its
burst opening behavior. Both scenarios retain every admitted backend until all
1000 actual TCP targets have passed the same simultaneous-load assertion and
two-second hold, for all three waves. Original immutable signed leases, each
three-second handshake, HTTP/rate/quota gates, exact byte accounting and physical
cleanup remain unchanged. No successful outcome is inferred before execution.

Run 41441918578 at 8a35c4e observed the separate origin-window ramp in
release profile. The original seven HTTP, one negotiation and six multiplex
regressions passed; twenty control owners and 598 actual application flows
were ready. The next handshake rejected invalid signed authority near original
lease expiry. No thousand-live sample or completed wave exists. The official
archive and eleven receipt files were verified; the failure remains recorded.
ADR 0066 removes redundant work within one production readback without caching
authority or changing any original deadline or currentness requirement. Its
new source and original workloads still require hosted validation.
