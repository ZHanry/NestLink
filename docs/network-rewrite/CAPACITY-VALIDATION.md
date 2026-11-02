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

Run 41447173194 at f3cfb45 executed the original release pair-window scenario
with ADR 0066. Its exact-byte/tamper/expiry/ACL regression, original seven HTTP,
one negotiation and six multiplex regressions passed. All twenty controls and
1000 application flows reported readiness. The original assertion after the
two-second full-load hold then observed zero actual live targets instead of
1000 as the original authority expired. No wave_live sample or completed wave
exists. The official ZIP and all receipt files were verified. This result is
failed; a thousand readiness events do not establish a surviving full-load wave.

ADR 0067 additionally reuses rusqlite's existing bounded compiled statements
for each full current policy snapshot and all original revocation collectors.
Only SQL compilation is reused; rows, signatures and authorization decisions
are read or verified again. The next exact-source original pair-window run is
41449447897 at d7e735d. It also executes the existing external-change, persisted
revocation/restart and clock-rollback/restore storage regressions. All prior
failures and every original deadline, bound and load assertion remain in force.

The optional flat perf diagnostic at e226eec, run 41470546001, retained the
original release pair-window load and failed at wave zero, pair zero, flow 39
with HTTP 403 PermissionRequired after 800 readiness records (40 per pair).
There is no completed thousand-live hold or successful wave. All six sampler
lifecycle tests and the preceding original regressions passed. Perf recorded
1474 samples with zero lost samples; its flat report spans the entire target
lifetime, including 244.900 seconds of wall-clock setup. It has no call graph
or per-phase attribution, so its crypto, JSON and SQLite symbols cannot identify
the cost of currentness or opening alone. The official ZIP digest and all 50
receipt payload hashes were verified; `evidence/perf-e226eec.json` preserves the
original receipt, failure, exact counts, limitations and mature perf references.
This diagnostic does not qualify AC68 or replace any previous failed attempt.

The explicit perf-phases run 41476929737 at efebb7b passed all 14 sampler
regressions, the original preceding checks and its three clock-verified flat
reports, but the original load failed with carrier connection lost at wave zero,
pair zero, flow 35 after 640 ready flows (32 per pair). The prior 403 failure
remains failed. The setup, control-record interval and after-all-controls-recorded
windows contain 55, 63 and 1432 samples respectively, totaling all 1550 captured
samples with zero lost samples. The final window includes 313 curve25519, 266
serde and 278 sqlite3-prefixed samples; it has no call graph or per-query/queue
timings and is not a pure opening phase. Setup wall time includes the original
244 seconds of rate-limit waits. `evidence/perf-efebb7b.json` records the official
ZIP digest, all 58 verified payloads, exact producer inventory, independently
checked realtime boundaries and original failure. No thousand-live hold,
completed wave, AC68 or soak qualification follows from diagnostic success.

The perf-phases run 41483686808 at 4ec2c3c completed the original release
pair-window workload in 275.065 seconds under its unchanged 660-second budget.
All 14 sampler regressions, all 22 executed Rust tests and both strict Clippy
commands passed. The exact sample inventory contains 3000 unique wave/pair/flow
tuples: three waves, twenty pairs and fifty flows per pair. Each wave has twenty
original leases and multiplex controls, 1000 simultaneously active real TCP
targets, the original two-second hold and a subsequent drain. The original
resource-scope readback asserts each pair's cumulative 1600/3200/4800 bytes,
zero outstanding bytes and zero active grants. These are passed Rust assertions;
the event file does not contain separate numeric receipts for every quota scope.
All owned UDP and TCP listener addresses were rebound after shutdown. Final
process FD count is 27, so physical owner cleanup does not imply zero process
descriptors or allocations.

The official ZIP digest and all 60 receipt payloads were independently verified.
All 29 producers returned zero, with complete output and test inventories.
The 277 clock anchors have a maximum 16284 ns uncertainty and zero observed
offset span. Independently recomputed windows match their original perf --time
arguments; their 29, 32 and 3269 samples total all 3330 captured samples, with
zero lost samples. The final 30.1028-second window includes every successful
wave, hold, drain and cleanup; it is not a pure opening phase. Its symbol-name
groups include curve25519 732, serde 528 and sqlite3-prefixed 554 samples.

This runner used an AMD EPYC 9V45 with four online CPUs; the prior efebb7b run
used an EPYC 7763 with four online CPUs and failed during a roughly 9.0547-second
final window. Different hardware, outcomes and exposure prevent causal speedup
claims or direct sample-percentage comparisons. Setup still includes the original
244 seconds of rate-limit waits, and attachment can miss early target work.
`evidence/perf-4ec2c3c.json` records the complete verified inventories and limits.
The diagnostic receipt retains original_workload_passed=true and
diagnostic_passed=true, but passed=false and ac68_passed=false. An exact-source
sampling=none qualification remains separate. Every historical failure remains
recorded, and this short hosted process does not qualify AC68 or cross-day soak.

The separate ordinary qualification, run 41486568717, checked out the identical
4ec2c3c source and workflow with sampling=none, confirmed by the official job
log. The original multiplexed release pair-window scenario passed in 275.131
seconds under the original 660-second budget, with receipt.passed=true. All
fifteen original commands returned zero, all 22 executed Rust tests passed and
both strict Clippy checks passed. The official 95025-byte ZIP digest matches
the independently downloaded archive; all 31 payloads, the exact producer/test
inventory and the separate official job log were verified.

Its event inventory again contains exactly 3000 wave/pair/flow tuples, sixty
original leases and controls, three thousand-live samples, three original
two-second full-load holds and three drains. The same-source exact-byte, EOF,
per-pair resource accounting and physical UDP/TCP listener-rebinding assertions
all completed. Wave open_seconds values are 8.4763, 8.6141 and 8.4610, including
each hold. Setup retains the original 244 seconds of rate-limit waits. Final
process FD26 and RSS252228 kB are recorded without a zero-resource claim.
`evidence/capacity-none-4ec2c3c.json` retains the full evidence inventory.

This qualifies the original single-process release pair-window scenario at
that exact source. It does not qualify earlier debug failures, independent
grants, other schedules, 100 physical nodes, loaded external management/relay
machines, all queue bounds, cross-day soak or the complete AC68 group. The
ordinary receipt has no ac68_passed field. The diagnostic receipt remains
diagnostic-only, and every historical failure remains recorded separately.
