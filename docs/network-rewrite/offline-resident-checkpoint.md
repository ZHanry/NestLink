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

## Sourcee202 actual mature conversion and remaining Linux store failure

Run [41478056075](https://github.com/ZHanry/NestLink/actions/runs/41478056075),
exact source `e2026fb523db32c45a14ec66f01a4a22a964d38e`, completed with
Windows success and Linux failure. Full receipts, both original native supplier
records, fixed Rust stage observations and every downloaded file digest are in
[native-offline-resident-e2026fb.json](evidence/native-offline-resident-e2026fb.json).
All44 downloaded files were independently byte-counted/SHA256-hashed; all36
producer entries match. Both downloaded source-before/after files are identical
and clean. Static archive hashes inside the native receipts are retained as
producer inventory; those archive binaries are not part of this focused
download and are not claimed independently hashed. GitHub ZIP digests also
remain explicitly GitHub-reported metadata.

Both original native x64 suppliers actually built and verified the fixed17
unmodified bundled libyuv source units, Release optimization and Windows dynamic
CRT, with source-tree/installed-file checks. Original Rust consumers linked and
ran. All focused AppCore/daemon/desktop cases, the signed/proved capture-terminal
and download-consent regressions, and all three strict clippy commands passed
on both OS. Full Rust quality/sanitizer/notice and ARM64 qualification are
separate runs owned by the main task.

Original Windows resident is now4/4 in314.78s: management8, pending4, complete
QUIC/TLS initial and rebuilt real pixels, two262144-byte completed files per
carrier, and EOF/IPC Exit all pass. Actual QUIC initial/rebuilt decode totals
were28307/27889us, with whole FFI22748/21953us. TLS was32666/30407us, with
FFI24752/23629us; later observed FFI was1619–3105us. First FFI still includes
lazy libvpx context work. These are debug-context observations, not a pure
libvpx benchmark. The original60ms immutable anchor,40ms late threshold,
frame/IPC deadlines, PTS/clocks, profile and cumulative budget were unchanged.

Original Linux is3/4 in236.56s. Management8, pending4 and complete TLS pixels/
two files/rebuild/IPC Exit passed. TLS initial first decode total5802us included
allocation4775us and FFI1026us; rebuilt first5053us included4179/873us. Later
observed FFI was534–741us; the retained allocation spike12419us was not removed.
QUIC failed before starting that case's real native session, at the new fixed
`source_protected_login` stage: the unchanged ten-second Secret Service gate
made187 attempts, last exit2. All three helpers were sleeping/alive and the
original login collection reported Locked=false. That original failure remains.

Read-only pinned libsecret0.21.4 source distinguishes parser/usage exit2 from
an actual Secret Service store failure1. Both original production and fixture
store/lookup argv lacked `--` before opaque URL-safe base64 attributes, which
can begin with a hyphen. Commit `d6c19c4a3d9a856521976f98b337415989681361`
adds the standard literal-attribute boundary through one tiny shared argv
helper, preserving the binding format, OS service, login/key/cipher, original
ten-second gate and all four original cases. A separate real CLI/Secret Service
regression requires both retired calls to exit2 and the repaired production
argv to actually store/read a leading-hyphen attribute. See
[ADR0074](../adr/network/0074-literal-secret-service-cli-attributes.md).
Sourcee202 did not log its exact binding prefix, so the value is not reconstructed
or claimed proven; the new regression and full original matrix still need
their own exact-source execution. Earlier unrelated SDK Invalid and independent
fixture DNS failures remain historical evidence. No local project execution
or new hosted dispatch occurred in this evidence work.

## Source4ec real literal-attribute regression and original matrix failures

Run [41483674367](https://github.com/ZHanry/NestLink/actions/runs/41483674367),
exact source `4ec2c3c0addea9d708629d58b2932ec035bd5569`, completed with both
original jobs failed. All scoped AppCore/daemon/desktop cases, the actual
capture-terminal and download-consent regressions, and the original three
strict clippy commands passed on both OS. The same-archive fixed17-file libyuv
suppliers built and verified on both x64 targets, and original Rust consumers
linked and ran. Exact commands, original names/results, native receipts, fixed
Rust timing records and every downloaded file digest are in
[native-offline-resident-4ec2c3c.json](evidence/native-offline-resident-4ec2c3c.json).
All46 downloaded files were independently byte-counted and SHA256-hashed;
all38 producer inventory entries match, and both source-before/after files
are byte-identical and clean. Native archive hashes remain producer inventory,
and ZIP digests remain explicitly GitHub-reported metadata.

Linux's separate real Secret Service leading-hyphen regression passed1/1 in
0.11s. It actually required the retired store and lookup argv to return2, then
required the original private D-Bus/gnome-keyring to retain and return the same
secret through repaired production argv under the original ten-second gate.
No raw attribute or secret is recorded. Its added strict command failed
`clippy::duplicate_mod` because the new integration loaded `secret_tool.rs`
directly and through support. Newer commit
`2285fd1f01887efb130433e81f21c941c8b01bb2` uses support's single production
module instead, without a lint suppression or runtime change. These source4ec
receipts cannot qualify that newer fix. See
[ADR0074](../adr/network/0074-literal-secret-service-cli-attributes.md).

Original Linux resident is3/4 in254.56s. Management8 and complete QUIC/TLS
initial/rebuilt real pixels, two262144-byte completed files per carrier and
EOF/IPC Exit passed. Pending case0 EOF and case1 Stop ran; case2/logout setup
failed before SDK calls at the unchanged temporary public-PKI HTTPS DNS
deadline. The case3 identity path did not complete after that failure. QUIC
first initial/rebuilt decode totals were4872/6274us (allocation4041/5409us,
whole FFI824/864us); TLS was7534/4481us (6541/3795us,991/685us). Later full-case
FFI observations were492–770us. These debug context costs remain distinct
from a pure codec benchmark.

Original Windows resident is0/4 in97.54s. Management case0 actually ran with
DXGI and completed its stopped endpoints. Management case1, pending case0
and both full data cases then reported original socket Os10013 PermissionDenied.
The recorded errors do not identify the failing bind stage, excluded port
range or OS cause. No Windows full-case pixel/file/rebuild success is claimed
on this source. Earlier sourcee202's4/4 success remains separate historical
evidence and does not replace this result.

The original four names/counts/assertions, immutable60ms ingress anchor,
40ms late threshold, PTS/capture clocks, frame/IPC deadlines, cumulative
offline budget, ordinary OS tokens and independent public-PKI owner remain
unchanged. Require newer exact-source strict lint and all four original cases
on both OS. No local build, formatter, lint, test, Python execution or
packaging occurred; this evidence work did not dispatch another workflow.

## Source4a complete original resident matrix and real CLI strict regression

Run [41488486927](https://github.com/ZHanry/NestLink/actions/runs/41488486927),
exact source `4a4496b77cf5923a1b39c85c757b7cc6a7f3dc00`, completed with both
original hosted jobs successful. Original resident is4/4 on Linux in245.79s
and4/4 on Windows in289.20s. Each ran all management8 cases, all pending
EOF/Stop/logout/identity cases, QUIC/TLS initial/rebuilt real pixels, both
262144-byte completed files per carrier and original EOF/IPC Exit. All scoped
AppCore/daemon/desktop tests, actual capture-terminal/download-consent
regressions and the original three strict-clippy commands also passed on
each OS. No case was filtered, ignored, renamed or replaced.

The separate Linux real Secret Service leading-hyphen regression passed1/1
in0.23s, including both retired actual parser exit2 assertions and repaired
retained-data equality through the original private D-Bus/gnome-keyring.
Its additional strict-clippy command passed, exercising the single-module
reuse repair. The original10-second store gate, production3-second helper
timeout, token hash/base64 binding, actual key/cipher/lookup and OS service
remain. No attribute or secret value is retained in the evidence.

Complete exact commands/results, both native supplier receipts, case-labelled
fixed Rust timing observations and independently hashed downloads are in
[native-offline-resident-4a4496b.json](evidence/native-offline-resident-4a4496b.json).
All46 extracted artifact files and two independently downloaded complete
GitHub job logs were byte-counted/SHA256-hashed; all38 producer inventory
entries match. Both source-before/after facts are identical and clean.
Native archive hashes remain explicitly producer inventory; GitHub ZIP
digests remain GitHub-reported metadata. Both x64 suppliers built/verified
the fixed17-file libyuv closure, including native Release/Windows dynamic CRT,
and original Rust consumers linked and ran.

Linux full QUIC first initial/rebuilt Rust decode totals were4942/5621us
(allocation4125/4820us, whole FFI815/799us); TLS was4802/5196us
(3900/4510us,900/684us). Later full-case FFI was463–723us. Windows QUIC was
37048/44347us (9446/10123us,27596/34223us); TLS was38794/43055us
(10886/15823us,27903/27230us). Later recorded FFI was1323/1352us. These are
original debug-context observations including lazy native setup, not pure
libvpx or throughput benchmarks. All fixed observations remain in evidence,
including separate management-case records with their original case identity.

No failure-only socket stage emitted on either OS. The source4ec Windows
Os10013 bind stage and OS cause remain unproven, and no socket algorithm,
retry or error was changed. Source comparison from4ec changes original
resident paths only by fixed failure diagnostics and module visibility;
the original independent HTTPS owner and all assertions/deadlines remain.
Earlier DNS, SDK setup, protected-store and Windows socket failures stay
preserved as historical results. This run does not reconstruct their random
inputs or infer an unobserved cause.

The60ms immutable validated-ingress anchor,40ms late threshold, PTS/capture
clocks, frame/IPC deadlines, cumulative offline authority budget and ordinary
OS identities remain unchanged. This completes the focused both-OS resident
matrix and Linux real CLI regression on this exact source. Full Rust-core,
VP8 quality/sanitizer/notice, ARM64, original25-second Luanti, actual AMF
hardware, physical-target and public-NAT/advanced-media acceptance require
their own evidence. No local build/formatter/lint/test/Python execution or
packaging occurred, and this evidence work did not dispatch another workflow.

## Source745 complete full-workspace failure and independent skipped gates

Full Rust run [41479911345](https://github.com/ZHanry/NestLink/actions/runs/41479911345),
exact source `745c05a8016c1d33c193706171714fa8b72c30cf`, completed with a
failed Linux core job and a Windows core job cancelled by its own original
60-minute job limit. Matrix fail-fast was false. GitHub's Windows annotation
explicitly reports the maximum execution time of 1h0m0s; the cancellation was
not caused by the Linux failure. Its workspace step began at 17:06:05Z after
approximately 47m50s of earlier work and was interrupted at 17:18:18Z. The
normal-token wrapper received KeyboardInterrupt. There is no completed
Windows workspace exit status.

The same source and jobs first passed the early serial original resident
suite on both OS: Linux 4/4 in 250.52s and Windows 4/4 in 290.35s. Later,
Linux's original default-parallel workspace resident suite returned 1/4 in
101.49s. TLS completed. QUIC produced its initial real pixels, then its initial
actual file task disappeared; original host stderr reported PlatformChanged
and controller stderr Revoked while both processes were still running and
approximately 76 seconds of finite authority remained, with attempts=1.
Management completed cases 0/1 before case 2 setup hit the unchanged independent
public-PKI HTTPS DNS deadline. Pending completed case 0 EOF and case 1 Stop
before case 2/logout setup hit that same DNS deadline; case 3 did not complete.
The logs establish the common platform terminal boundary, not the exact first
OS fact, historical random input or cross-session cause. They do not establish
a decoder or late-threshold failure.

Linux continued through all remaining workspace binaries and doc-tests under
the original --no-fail-fast command, then returned 101 for exactly one failed
target, `-p nestlink-daemon --test offline_remote_resident`. All 183 harness
records have actual final summaries, totalling 2066 passed, 3 failed and 48
ignored. Cargo's stderr can print the next Running/Doc-tests header before
the previous stdout summary; evidence queues those headers and associates
cases/summaries with the harness actually started by its lowercase running
N tests line. Windows completed 22 harness records totalling 258 passed and
2 ignored. Its 23rd, original resident, printed actual ok results for QUIC,
TLS and pending, while management remained running when the job timed out.
No final four-case result or failed management assertion is inferred.

Linux's original media-codec unit suite passed 45/45 in 0.63s, including all
eight VP8 cases for color/BT.601, mature I420/BGRA conversion, odd geometry and
PSNR, worker movement, references/live bitrate, PTS and corrupt/truncated
frames. The separate Rust prefix_validation integration passed 3/3 in 0.01s
for linked components, tampered library and wrong target/source/features or
untracked bytes. The Opus native bridge ASan/UBSan unit case also passed.
That Opus result does not execute the separate VP8 boundary sanitizer.
Both OS built and verified the original native supplier and passed workspace
type-checking. The later original VP8 sanitizer, Python native-supplier/notice
regressions and cargo xtask check were skipped after the Linux workspace
failure or Windows job timeout. Windows workspace did not reach the VP8 or
Rust prefix targets. No complete notice inventory is qualified by this run.

Complete metadata, original case names/results and gate statuses are in
[full-rust-core-745c05a.json](evidence/full-rust-core-745c05a.json). Seventeen
downloaded files, including both complete core logs, were independently
byte-counted and SHA256-hashed. Both independently downloaded early lifecycle
ZIP hashes match GitHub's official artifact digests; all eight extracted files
are hashed separately. Other seven jobs' successful conclusions are recorded
as GitHub metadata, without claiming their logs were independently audited.

The newer original-platform owner changes in 5bb8bf5 and 0a1b789, including
actual child exit/reap before Drop releases ownership, postdate this run and
still require their own hosted qualification. See
[ADR0077](../adr/network/0077-original-resident-platform-owner.md). The four
original resident names/counts/assertions, all deadlines, 60ms immutable
ingress anchor, 40ms late threshold, PTS/capture clocks, ordinary OS tokens,
independent public-PKI owner and cumulative authority budget remain unchanged.
The original 25-second Luanti gate and historical failure remain separate and
unchanged. No local project build, formatter, lint, test, Python execution or
packaging occurred; this evidence work did not dispatch another workflow.

## Sourcec589 focused success and complete full Rust failures

The focused original resident run
[41562179075](https://github.com/ZHanry/NestLink/actions/runs/41562179075),
exact source `c5893625ebbe3b50406810bd7eb34c60cbbea849`, completed successfully
on both hosted OS. All four original cases passed: Linux in 221.58s and
Windows in 275.24s. This includes all eight management fences, all four
pending terminal cases, and both complete QUIC/TLS initial/rebuilt real
pixel and two 262144-byte file paths with original EOF/IPC Exit and physical
listener cleanup assertions. The separate original platform-owner regression
passed 1/1 in 0.39s on Linux and 0.10s on Windows, with its additional strict
clippy command. Linux's real leading-hyphen Secret Service regression passed
1/1 in 0.12s, including its additional strict command. All original focused
AppCore/daemon/desktop commands and original three strict commands passed.

The complete receipt and every case-labelled fixed decode-stage observation
are in [native-offline-resident-c589362.json](evidence/native-offline-resident-c589362.json).
Both source-before/after facts are clean and byte-identical. All 57 downloaded
files were independently byte-counted and SHA256-hashed: 50 extracted files,
two complete job logs, two ZIPs and three final API metadata files. All 42
producer inventory entries match downloaded bytes. Both ZIP hashes match
GitHub's official digests. Native archive/library hashes are explicitly
producer receipt inventory; those library binaries were not in the downloaded
focused artifact. Both original native suppliers built and verified the fixed
17-file bundled libyuv closure and the original Rust consumers linked and ran.

The same-source full Rust run
[41562145692](https://github.com/ZHanry/NestLink/actions/runs/41562145692)
completed with failure. All 13 jobs completed; seven peripheral jobs succeeded
and both core, both complete-workspace and both boundary-tools jobs failed.
No job timed out or was cancelled. This focused success does not replace any
full-workflow failure.

Early core execution returned Linux 3/4 in 128.13s: pending and both complete
carriers passed, while management failed before its first case diagnostic with
only `Error: Elapsed(())`. The exact original startup await/OS cause was not
logged. Windows returned 0/4 in 51.84s, each error at the original peer helper's
second operation: UDP bind of the TCP-selected numeric port, with
`PermissionDenied` / `Os10013`. The logs prove the operation; an excluded-range,
security or live-port-owner explanation is not established. No original
timeout or failure was swallowed or retried.

Both complete workspaces ran all 185 harnesses through their final doc-tests
under the original `--workspace --locked --no-fail-fast` command. Linux totals
2072 passed, 5 failed and 48 ignored; Windows totals 2074 passed, 5 failed and
16 ignored. Every declared case count matches the actual case lines and final
summary. Cargo stderr headings can arrive before the previous stdout summary
or after the next lowercase `running N tests` line. Evidence associates these
two independently ordered streams by original Cargo harness order, excluding
native supplier bootstrap messages, and retains all raw line references.

Four failures on each OS are the original resident cases: the fresh independent
workspace job lacked the original frozen public-PKI HTTPS fixture tool, so
each failed setup before resident business assertions. Linux returned 0/4 in
5.15s; Windows 0/4 in 1.84s. The separate older owner regression still passed
1/1 in 0.36s and 0.11s respectively. The remaining Linux failure is
`member_removal_and_session_logout_close_both_transports` in SDK `space_dns`
(10/11 in 13.30s), with `AddrInUse` / `Os98`; the specific bind/cleanup cause
is not logged. Windows SDK `space_dns` passed 11/11 in 12.91s. The remaining
Windows failure is AppCore
`proved_file_access_tracks_dynamic_roots_and_keeps_failed_tasks_session_scoped`
(native_session 5/6 in 16.70s): the original assertion at line 540 expected
Succeeded and received StartNativeSession Failed/Transport/DirectUnavailable.
Linux AppCore native_session passed 6/6 in 7.97s. No unobserved port, timeout,
media or owner cause is inferred from that Windows operation failure.

Both workspaces actually reached and passed the original eight VP8 Rust cases.
Media-codec totals were Linux 46/46 in 0.52s and Windows 70/70 in 6.92s;
prefix_validation passed 3/3 and 2/2 respectively, both in 0.01s. The separate
Linux boundary-tools job also actually passed the original first-party VP8
ASan/UBSan corpus (96 real frames, 3072 mutated packets and every encoded-prefix
truncation) and the original 100000-case PipeWire PCM sanitizer. Upstream static
libvpx/libyuv were not sanitizer-instrumented. The original Python discovery
ran 292 tests on each OS and failed with 35 notice setup errors, all reporting
the missing `cargo fetch --locked` prerequisite. Later UI-token and xtask
steps were skipped. See the independently committed
[boundary-tools evidence](evidence/boundary-tools-c589362.json) for the precise
execution, error and skip distinction.

[full-rust-core-c589362.json](evidence/full-rust-core-c589362.json) retains all
13 final job records, both complete core/workspace step inventories, all 370
workspace harness/case records and exact original errors. All 21 downloaded
files, including six complete job logs and eight early artifact files, were
independently byte-counted and SHA256-hashed; both early ZIP hashes match their
official GitHub digests. The seven peripheral successes are GitHub metadata,
without claiming their complete logs were independently audited.

The newer constructor adoption and six-stage cancellation/error regression
in `62a0668`, workspace HTTPS prerequisite in `dd8c39d`, and carrier-specific
standard port-zero selection in `00f5e7a` postdate both sourcec589 runs. They
remain pending their own exact-source hosted qualification; the newer owner
fix is scoped to constructor and original long-lived children. See
[ADR0077](../adr/network/0077-original-resident-platform-owner.md) and
[ADR0079](../adr/network/0079-original-resident-carrier-port.md). The four
original resident names/counts/assertions, immutable 60ms ingress anchor,
40ms late threshold, PTS/capture clocks, ordinary OS tokens, independent
public-PKI owner, cumulative authority and all original deadlines remain.
The original 25-second Luanti check and its failed history remain unchanged.
No local project build, formatter, lint, test, Python execution or packaging
occurred; this evidence work did not push or dispatch.

## Source f24 original Linux results and separate collector failure

Focused run [41577568244](https://github.com/ZHanry/NestLink/actions/runs/41577568244),
source `f24b79f0c8baa00ad398636868c513624b0707cc`, has a failed Linux job.
The actual original resident command returned zero with four passed, zero failed
and zero ignored in 211.84s. The original platform owner and actual leading-hyphen
Secret Service command also returned zero, with one pass each in 2.75s and 0.10s.
All scoped AppCore/daemon/desktop tests and all five original strict lint commands
returned zero. This does not turn the failed workflow into successful evidence.

The collector merged child stderr with libtest stdout. Actual Xvfb/xkbcomp stderr
was inserted after each `test name ... ` prefix, so the strict one-line parser
retained empty case lists for those three commands and marked `passed: false`.
The original receipt, actual final summaries and official archive/payload hash
verification are retained in
[native-offline-resident-f24b79f-linux.json](evidence/native-offline-resident-f24b79f-linux.json).
Windows and the complete Rust workspace remain separate pending outcomes here.

New source collects stdout and stderr into separate original byte streams,
retains and hashes both, and applies the same exact case/name/count/summary/exit
checks to harness stdout. It does not parse a successful summary as proof of
missing cases. New real subprocess regressions cover a grandchild writing
stderr between the harness prefix and result, nonzero exit and timeout, plus
strict rejection of the original merged log, missing/wrong/duplicate/failed or
ignored cases. They execute only through hosted Actions and require their own
new-source result. No original assertion, deadline, ingress clock, offline budget
or Luanti 25-second check is changed.
