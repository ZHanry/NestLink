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

## Confirmed changes and remaining failures

1. `d7e735d` fixed the actual original download ACK race by retaining the same
   LocalDownloadConsent owner in the async approval guard. Source78's dedicated
   regression passed on both systems; the original Windows TLS case completed
   both files and QUIC completed its first file. Local/session checks remain
   active, and no ACL, sharing-mode or failed-task bypass was used.
2. `66821f4` registered the real Xvfb display through original libpam/login.
   Source78 really created UID1001 sessions with PAM_XDISPLAY `:0`, removing
   the former empty Display error. Actual capture then exposed the missing
   Xauthority file; the new private xauth/Xvfb repair in ADR0068 is unverified.
3. Windows QUIC failed after its completed first file because LocalProducts
   treated an actor's normal return after the original carrier's observation
   channel closed as a product failure. The retained offline Core's final
   lifecycle remains Running; the former supervisor therefore revoked the
   original finite owner before the resident's explicit product join. The
   repair recognizes only the original Stopped/successful-cleanup/no-failure
   receipt with NetworkChanged or TransportLost. Errors, incomplete cleanup,
   platform changes, revocation and expiry still terminate the owner. No
   authority, deadline, byte quota or attempt is renewed. The original full
   QUIC/rebuild test must verify this repair on newer source.
4. Windows management-fence source78 reached the fourth independent fixture,
   then protected login recovery failed before ready. SessionStore previously
   folded every restoration failure into None. New diagnostics preserve the
   original behavior and expose fixed stages, I/O kind/OS number or the SDK's
   fixed diagnostic category/HTTP status. They emit no key, plaintext login,
   token, URL or raw transport error. The actual failure cause remains pending.
5. Linux source78 management-fence eventually failed a new independent public
   HTTPS tunnel's actual system-DNS readiness inside its original60 seconds.
   No tunnel is shared across cases and no resolver, certificate, HTTP or
   time-bound fallback is introduced. Linux pending-listener executed its
   first three subcases then returned a bare Invalid; added case/setup/
   controller/HTTPS-cleanup context must locate the exact operation before
   changing it. Windows's four original pending-listener subcases passed.

## Next exact-source hosted work

The main task pushed `f570243c12e0390e963e373988fd76f5ec44b465` and started
the original focused Linux/Windows matrix as
[41455823431](https://github.com/ZHanry/NestLink/actions/runs/41455823431),
with hosted formatting separately dispatched. Both are pending here.
Require all four original resident tests to execute and pass before marking
resident completion. Follow the real protected-login stage and pending-case
operation, and repair only confirmed failures. Preserve every failed receipt,
all original assertions and deadlines, independent HTTPS owners and strict
clippy. The same-source full workflow and physical-target gates remain
separate; this log does not change their status.
