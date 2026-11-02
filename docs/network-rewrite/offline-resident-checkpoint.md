# Original offline resident checkpoint

Updated 2026-11-02. This is a scoped W27 implementation/verification log, not a
whole-release, physical-device, public-NAT or advanced-media acceptance claim.
The main task owns pushes, workflow dispatch, progress/task state and release.
All compile, formatter, lint and test execution remains on hosted Actions.
The original Luanti 25-second check and its failure status remain unchanged.

## Completed receipts

- Source `85c8da8d5ec1f7af4e393e31e299cc83bc36c53d`, focused run
  [41443851500](https://github.com/ZHanry/NestLink/actions/runs/41443851500):
  AppCore2, daemon remote2/private2/entry1, desktop2 and all three strict
  clippy commands passed on Linux and Windows. Original resident Linux1/4,
  Windows2/4. All40 downloaded files independently hashed; all32 producer
  payload byte/SHA entries match. See `evidence/native-offline-resident-85c8da8.json`.
- Source `78a7cb4f79f00e930a3fbb56409f17517129a171`, focused run
  [41451102046](https://github.com/ZHanry/NestLink/actions/runs/41451102046):
  those same scoped commands plus the dedicated download-consent regression
  passed on both systems. Original resident Linux0/4, Windows2/4. All42
  downloaded files independently hashed; all34 producer payload entries
  match. The complete original Windows TLS data/rebuild test passed: real
  VP8 pixels before and after rebuild, two completed262144-byte files with
  exact original bytes, same runtime/newer generation, unchanged bundle,
  second connection attempt/cumulative quota, stale-generation rejection,
  authenticated IPC Exit and original cleanup/socket checks. This establishes
  that exact TLS laboratory case only. See
  `evidence/native-offline-resident-78a7cb4.json` for all original results and
  independently downloaded payload hashes.
- Source `f570243c12e0390e963e373988fd76f5ec44b465`, focused run
  [41455823431](https://github.com/ZHanry/NestLink/actions/runs/41455823431):
  all scoped commands, download-consent regression and strict clippy passed on
  both systems. Original resident Linux0/4, Windows3/4. All42 downloaded files
  independently hashed; all34 producer payload entries match. Linux delivered
  actual original green pixels and completed files on both carriers; TLS also
  rebuilt and completed its second file before the original immediate budget
  assertion failed. Windows management, pending-listener and entire TLS cases
  passed. Both original QUIC rebuild cases still failed with stopped authority.
  See `evidence/native-offline-resident-f570243.json`.
- Source `1dd4efd03b201d31744a716b4f99d73fd0d9c657`, original focused run
  [41461596961](https://github.com/ZHanry/NestLink/actions/runs/41461596961):
  Linux job125331747406 and Windows job125331747712 completed. All scoped
  commands and strict clippy passed on both OS. Original resident Linux1/4,
  Windows3/4. The entire original TLS real-data/rebuild/immediate-budget/IPC
  Exit and cleanup case passed on both systems; the Linux original immediate
  cumulative-quota failure is now repaired. Both original QUIC rebuilds still
  failed with the same confirmed late capture termination. Windows management8
  and pending4 passed. Linux management cases0..2 completed, then independent
  case3 setup returned management response Invalid; the exact SDK operation is
  not yet located. Linux pending0/1 completed, then independent case2 public-PKI
  system-DNS readiness failed within its original60 seconds. All42 downloaded
  files independently hashed; all34 producer inventory entries match. See
  `evidence/native-offline-resident-1dd4efd.json`; the earlier Windows-only
  evidence is preserved.
- Source `91509d13f8aa52fff19f31e2fb77c5c702da0dc1`, original focused run
  [41466485538](https://github.com/ZHanry/NestLink/actions/runs/41466485538):
  Linux job125348643070 passed; Windows job125348642149 failed. All scoped
  AppCore/daemon/desktop tests, download-consent and new real signed/proved
  capture-terminal regressions, and all three strict clippy commands passed
  on both OS. Original resident Linux4/4, Windows2/4. The complete original
  QUIC actual-pixels/two-files/rebuild/EOF case now passed on both systems,
  confirming the observed late-capture repair case. Linux all management8,
  pending4 and full TLS passed. Windows management8 passed; pending case1
  independent setup returned Invalid, and TLS rebuilt-pixel IPC timed out
  while both real sessions remained Connected with live finite budgets.
  All44 downloaded files independently hashed; all36 producer inventory
  byte/SHA entries match. See `evidence/native-offline-resident-91509d1.json`.

## Confirmed changes and remaining failures

1. `d7e735d` fixed the actual original download ACK race by retaining the same
   LocalDownloadConsent owner in the async approval guard. Source78's dedicated
   regression passed on both systems; the original Windows TLS case completed
   both files and QUIC completed its first file. Local/session checks remain
   active, and no ACL, sharing-mode or failed-task bypass was used.
2. `66821f4` registered the real Xvfb display through original libpam/login.
   Source78 really created UID1001 sessions with PAM_XDISPLAY `:0`, removing
   the former empty Display error. Actual capture then exposed the missing
   Xauthority file. Sourcef570 private xauth/Xvfb repair now allowed the original
   Linux green-pixel checks and real completed files, including TLS rebuild.
3. Both sourcef570 QUIC cases completed initial pixels/file then failed rebuild
   because the original owner was already stopped with roughly75 seconds left.
   Correction: the earlier claim that the final offline Core lifecycle stays
   Running was wrong. `native_offline.rs` explicitly sets Lifecycle::Stopped
   after route cleanup and publishes the final receipt. The transient cleanup
   window is distinct from that final state. f570's completed-carrier guard
   did not cure QUIC; the actual authority-stop path remains unconfirmed.
   Bounded fixed-category original supervisor/authority diagnostics are next.
   No rollback tolerance, authority/deadline/quota renewal or attempt refund
   is justified by the current evidence.
   Source1dd on both OS now identifies the actual extra termination:
   `PlatformChanged previous_state=Stopped(TransportLost)`. The original
   products supervisor observed the final Stopped/successful-cleanup receipt
   and `stop_owner=false`. There was no expiry/rollback category in this failure.
   During original transport cleanup, the host Core can still have its prior
   connected snapshot. The old capture worker observes terminal authorization,
   then its exact-route failure notification unconditionally stops that already
   stopped lease with PlatformChanged, terminating the original offline owner.
   This observed call path supersedes the former supervisor hypothesis.
   Source915's existing original atomic stop_if_running repair is now verified
   by the complete original QUIC resident case on both OS and its new real
   signed/proved-lease regression. No late PlatformChanged revocation appears
   in these exact original QUIC rebuilds. This establishes this repair, not
   full resident completion on Windows or whole-release acceptance.
4. Windows management-fence source78 reached the fourth independent fixture,
   then protected login recovery failed before ready. SessionStore previously
   folded every restoration failure into None. New diagnostics preserve the
   original behavior and expose fixed stages, I/O kind/OS number or the SDK's
   fixed diagnostic category/HTTP status. They emit no key, plaintext login,
   token, URL or raw transport error. On sourcef570 all eight original Windows
   management cases passed, so the earlier failure did not recur. Linux case6
   failed the actual Secret Service key-store setup within its original10 sec;
   nonsecret original service metadata is needed before changing behavior.
5. Linux source78 management-fence eventually failed a new independent public
   HTTPS tunnel's actual system-DNS readiness inside its original60 seconds.
   No tunnel is shared across cases and no resolver, certificate, HTTP or
   time-bound fallback is introduced. Linux pending-listener executed its
   first three subcases then returned a bare Invalid; added case/setup/
   controller/HTTPS-cleanup context must locate the exact operation before
   changing it. Windows's four original pending-listener subcases passed.
   On sourcef570 Linux pending case0 passed, and case1 failed its independent
   original public-PKI system-DNS readiness. The bare Invalid did not recur.
   On source1dd management cases0..2 completed and case3's independent
   Fixture::new returned management response Invalid. This run contains no
   Secret Service timeout or associated metadata; it neither establishes that
   previous keyring cause nor proves it resolved. A diagnostic-only follow-up
   adds fixed original SDK-operation stage, SDK category/HTTP status and I/O
   kind to Fixture::new failures using inspect_err. It returns the same error
   and leaves operations, assertions, authority and all time bounds intact.
   No raw error, endpoint, account, token, key or secret is printed. Pending
   cases0/1 completed, and independent case2 then failed its original60-second
   public-PKI system-DNS readiness. No retry, shared tunnel or DNS fallback is
   introduced.
   On source915 Linux all original management/pending cases passed. Windows
   management8 passed, pending case0 completed and case1 independent setup
   returned Invalid. Source4031432's diagnostic-only fixed-operation stages
   are newer than915 and await the next exact-source run. No root-cause claim
   is made for the earlier intermittent setup failures.
6. Source915 Windows TLS initial pixels/first completed file passed, both
   original carriers cleaned up and rebuilt into Connected sessions, and the
   same finite meter still had about72 seconds left with stopped=false. The
   original rebuilt-pixel IPC then timed out: actual dxgi capture remained
   live and the controller decoded VP8 frames, but the first rebuilt frames
   were dropped at queue-admission about40..65ms late. No original second
   file or IPC Exit success is claimed. This differs from the confirmed old
   authority-stop defect and requires read-only original PTS/clock/playout
   diagnosis before a repair. The original frame, IPC and test time bounds
   remain unchanged.

## Repairs and exact-source verification

Direct CoreHandle snapshots and NativeOfflineSession views now read the same
original cumulative authority meter, rather than returning the last250 ms
notification sample. The periodic watch cadence remains unchanged. This reuses
the original SDK/session status read; it creates no accounting implementation,
authority or refreshed deadline. Compared with delaying the original test or
polling faster, a direct meter read gives every authenticated IPC/UI caller the
current cumulative facts. If that read fails, the view reports stopped/zero
remaining authority. The original resident assertion and its timing are intact;
the existing real AppCore integration also asserts immediate snapshot budgets
after actual completed files before and after rebuild. Source1dd now confirms
those AppCore assertions on both OS and the complete original Linux TLS
resident immediate-budget case, with both real files and cleanup passing.

Diagnostic-only changes identify the first products actor, its fixed result,
the original lifecycle/status/reason/cleanup/failure and whether the supervisor
stops the owner. Original admission/process/session termination records static
source location and fixed rollback/wall-expiry/monotonic-expiry categories only.
Original rollback, expiry, quota, process-stop and revocation checks are intact.
These diagnostics identified the exact late-capture path on both source1dd
original QUIC failures; the repair below still requires its own actual run.

The source1dd diagnostic on both OS identifies the path described above. The
new capture-failure notification delegates to existing
`LeaseControl::stop_if_running(PlatformChanged)` after retiring the exact bound
route. An active capture failure still stops immediately. A stopped producer's
terminal-authorization observation cannot change recovery eligibility or revoke
the retained original offline meter. A fresh explicit platform change, actual
cleanup failure, process stop, revocation or expiry retains its original path.
Compared with ignoring PlatformChanged generally or checking a cached Core
snapshot, this reuses the original atomic lease-state boundary and preserves
real live failures. No Session/authority check or original resident assertion,
deadline, HTTPS owner or byte quota is changed by this repair.

The focused coordinator adds one AppCore library regression that calls this
same private production notification on real signed, bilaterally proved
LeaseControl owners. After TransportLost, it requires the historical reason
and actual reconnection eligibility to remain; the old unconditional stop
retains that historical reason but makes recovery_forbidden true, so the
eligibility assertion detects the defect. A new explicit PlatformChanged must
still forbid recovery, and the same notification on a running proved lease
must produce PlatformChanged and forbid recovery. The original full offline
resident suite still establishes actual independent-owner/pixel/file/rebuild
behavior; this library regression alone cannot do so. Source915 now passed
this regression on both OS, plus the complete original QUIC resident case on
both systems; Windows's independent setup and TLS-pixel failures remain gates.

After the original Secret Service store gate fails, a bounded read-only probe
records original helper states, store attempts/exit status and login-collection
Locked metadata. It never reads a secret or prints raw command output. The
cancelled original secret-tool is now killed through its existing Child owner;
the gate remains10 seconds, and metadata cannot convert failure to success.

The original f570 Linux job log reports gnome-keyring46.1-2ubuntu0.2 and
libsecret0.21.4-1build3. Additional mature-component source reading pinned GNOME
46.1 tag to commit `4e173494bf15795a1ebab6e2bbd9377fac456240`:
`pam/gkr-pam-module.c::pam_sm_close_session` is explicitly a no-op, so repeated
PAM close cannot be asserted as the direct keyring-kill cause.
`daemon/gkd-main.c` can exit after its configured XDG_SESSION_ID enters closing,
but this has not been observed for the failing fixture. The read establishes
neither a root cause nor an adopted implementation; no upstream code is copied.
Source links:
<https://github.com/GNOME/gnome-keyring/blob/4e173494bf15795a1ebab6e2bbd9377fac456240/pam/gkr-pam-module.c>
and
<https://github.com/GNOME/gnome-keyring/blob/4e173494bf15795a1ebab6e2bbd9377fac456240/daemon/gkd-main.c>.

## Next exact-source hosted work

Source1dd includes production budget readback/diagnostic commit `c0bb7ac`
and original Session::stop reason/previous-state diagnostic `54ba6cf`. The
complete run41461596961 is now downloaded and verified as above. The new source
`91509d13f8aa52fff19f31e2fb77c5c702da0dc1` contains the confirmed late-capture
repair and real lease regression. The main task pushed it and dispatched the
complete original focused matrix as
[41466485538](https://github.com/ZHanry/NestLink/actions/runs/41466485538).
Both original jobs are now downloaded and independently verified with results
above. The main task owns newer diagnostic-only source4031432, subsequent
formatter review and same-source full workflow dispatch. Source4031432 is
newer than these receipts and has no runtime success claim from source915.
Require all four original resident tests to execute and pass before marking
resident completion. Follow the real protected-login stage and pending-case
operation, plus Windows's original TLS rebuilt-video PTS/playout path, and
repair only confirmed failures. Preserve every failed receipt,
all original assertions and deadlines, independent HTTPS owners and strict
clippy. The same-source full workflow and physical-target gates remain
separate; this log does not change their status.

## Source9f original follow-up and mature conversion implementation

Run [41473579543](https://github.com/ZHanry/NestLink/actions/runs/41473579543),
exact source `9f00b068a67e5db9d1ed5285e7bda90afe004600`, completed both
original jobs with failure. The complete focused evidence is retained in
[native-offline-resident-9f00b06.json](evidence/native-offline-resident-9f00b06.json).
All44 downloaded files were independently byte-counted and SHA256-hashed;
all36 producer inventory entries match. Downloaded source-before/after files
are byte-identical, clean at the exact source/Cargo.lock. Both receipts retain
matching original frozen HTTPS executable hashes. GitHub artifact digests are
reported separately; no independently hashed ZIP is claimed.

Both OS passed all original focused AppCore/daemon/desktop cases, including
the actual signed/proved late-capture regression and download-consent case,
plus all three strict clippy commands. Original Linux resident is3/4 in226.83s:
management8 and the complete QUIC/TLS real-pixel/two262144-byte-files/rebuild/
EOF or IPC Exit paths pass. The pending case0 EOF setup failed before SDK
calls in its independent public-PKI HTTPS startup: temporary fixture DNS was
not ready before the original deadline. That failure remains recorded.

Original Windows resident is3/4 in314.01s: management8, all four pending
EOF/Stop/logout/identity cases and complete QUIC real data/rebuild/EOF pass.
TLS now failed at initial original pixels, before its first file or rebuild.
The original host actually selected DXGI, both sessions remained Connected/
Running, attempts remained1, and the original budget had roughly75 seconds
left. Observed ingress-to-output was114072us first and83–85ms later. Queue
admission dropped frames41–54ms late; another frame entered at38966us late
and exceeded the same40ms threshold at presentation-poll43089us. These are
whole-pipeline measurements; they do not isolate libvpx decode cost.

The new fixed SDK operation-stage diagnostic emitted on neither platform:
Linux failed before SDK setup, while Windows's pending setup cases passed.
The earlier source915 management-response-invalid result remains unresolved
historical evidence. This run does not identify its SDK operation or repair it.
No original time bound, assertion or independent HTTPS owner was changed.

Implementation commit `7de4463463d115643e75ce59a92c0382a58d137f` reuses the
already pinned libvpx archive's mature bundled libyuv1711, with its explicit
upstream commit, original BSD/README notices, fixed17-file static source
closure, native compiler/Release/CRT checks, installed-file receipt and both
SPDX metadata producers. The production bridge converts original libvpx
planes directly into the original bounded wiping BGRA owner, removing the
intermediate packed-I420 copy and scalar Rust decode conversion. The encoder
is unchanged. The BT.601 limited semantics and opaque BGRA bytes remain,
with the supplier's documented different integer approximation. All original
color/PSNR and resident assertions remain; new actual converter/stride/guard
vectors supplement them. First3 debug decode calls report only fixed Rust
geometry/allocation/whole-FFI/total durations. See
[ADR0073](../adr/network/0073-reuse-bundled-libyuv-vp8-conversion.md).

Source9f predates that implementation and cannot qualify it. Require newer
exact-source native builds, original VP8 quality cases, sanitizer, notice/
receipt tests, strict lint and the complete original resident matrix. No
local build/format/lint/test/Python execution or packaging was performed.
Keep the60ms immutable validated-ingress anchor,40ms late threshold, original
PTS/clocks/deadlines and cumulative authority meter unchanged. Resident
completion still requires all four original cases to execute and pass on
both OS; physical devices and public-NAT acceptance remain separate.
