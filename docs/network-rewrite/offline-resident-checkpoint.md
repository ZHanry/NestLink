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

## New source, awaiting hosted verification

Direct CoreHandle snapshots and NativeOfflineSession views now read the same
original cumulative authority meter, rather than returning the last250 ms
notification sample. The periodic watch cadence remains unchanged. This reuses
the original SDK/session status read; it creates no accounting implementation,
authority or refreshed deadline. Compared with delaying the original test or
polling faster, a direct meter read gives every authenticated IPC/UI caller the
current cumulative facts. If that read fails, the view reports stopped/zero
remaining authority. The original resident assertion and its timing are intact;
the existing real AppCore integration also asserts immediate snapshot budgets
after actual completed files before and after rebuild.

Diagnostic-only changes identify the first products actor, its fixed result,
the original lifecycle/status/reason/cleanup/failure and whether the supervisor
stops the owner. Original admission/process/session termination records static
source location and fixed rollback/wall-expiry/monotonic-expiry categories only.
Original rollback, expiry, quota, process-stop and revocation checks are intact.
No QUIC authority repair is claimed until the next actual run identifies it.

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

The f570 focused matrix completed with the original failures above. The next
source `1dd4efd03b201d31744a716b4f99d73fd0d9c657` includes the production budget
readback/diagnostic commit `c0bb7ac` and the additional original Session::stop
reason/previous-state diagnostic `54ba6cf`. The main task pushed it and started
the complete original focused matrix as
[41461596961](https://github.com/ZHanry/NestLink/actions/runs/41461596961).
Linux job125331747406 and Windows job125331747712 are pending here. The main
task separately owns the source1dd hosted formatter run41461476335. No newer
source compilation, runtime or formatting success is claimed until receipts
are downloaded and checked.
Require all four original resident tests to execute and pass before marking
resident completion. Follow the real protected-login stage and pending-case
operation, and repair only confirmed failures. Preserve every failed receipt,
all original assertions and deadlines, independent HTTPS owners and strict
clippy. The same-source full workflow and physical-target gates remain
separate; this log does not change their status.
