# 0077 — Own the real hosted resident platform before starting a case

Date: 2026-11-03. Status: implemented; exact-source hosted execution pending.
Scope: original resident test fixture scheduling, with an additional independent
real-platform lifecycle regression. Production authorization and capture are
unchanged.

Full Rust run41479911345, source745c05a, passed the early serial original
resident suite4/4 on both OS. Later in the same Linux job, the default parallel
workspace invocation ran the same four cases simultaneously and returned1/4.
Management case2 and pending case2 hit the original independent public-PKI DNS
deadline. QUIC produced its initial real pixels, then lost the actual file task
after the host stopped with PlatformChanged and the controller with Revoked,
while the original cumulative budget still had approximately76 seconds. TLS
passed. The preserved log identifies the terminal boundary, not the exact
platform check that first failed. No particular X11/logind/Secret Service fact
or historical random input is reconstructed.

Each Platform already owns a separate temporary directory, Xauthority, Xvfb
display, private D-Bus, XDG data/runtime directories and random systemd/PAM
session. It does not mutate process-global environment. Production logind
monitoring selects the actual GUI PID's session and subscribes to its exact
object path. These facts do not support weakening the production checks or
asserting that a particular other session's signal caused the failure.

The fixtures still run under one real hosted desktop UID, the original system
logind service and finite native capture scheduling resources. The focused
runner already schedules the original suite with test-threads=1. Use Tokio's
existing semaphore to put this same ownership boundary in Platform itself,
so the complete workspace's default test parallelism cannot overlap these
real platform lifecycles. There is one process-local permit. Acquisition occurs
before creating OS owners or starting any original fixture/case deadline.
The permit remains in Platform through its original awaited child shutdown.
Drop also starts termination and synchronously polls each original Child's
try_wait until actual exit/reap before releasing the permit. A signal alone
does not establish cleanup. This uses no asynchronous task that a shutting-down
test runtime could cancel. An unknown kill/reap result closes the semaphore,
retains its permit and fails the current case; queued cases fail closed rather
than overlapping an unreaped owner. There is no new original cleanup deadline,
retry of a case or replacement OS owner. This is resource scheduling, not proof
of the old PlatformChanged cause or permission to continue after a real
platform failure.

The additional independent integration target creates the original real
Platform, verifies a second owner remains queued, cancels that waiter, and
then obtains owners after explicit shutdown and Drop. Linux also checks the
actual retained child PIDs have left /proc after each cleanup; it uses the
original private D-Bus, gnome-keyring and Xvfb. Windows retains the original
ordinary-token fixture. It is a separate one-test target and strict command,
so the four original resident names/counts/assertions remain unchanged.

Every original timeout/deadline, immutable60ms ingress anchor,40ms late
threshold, PTS/capture clock, original authority/cumulative budget and OS
authentication boundary remains. Waiting for the lab owner precedes them.
No local build/formatter/lint/test/Python execution occurred. Require exact
hosted original resident execution under workspace parallel scheduling,
the independent owner lifecycle regression and strict lint before qualifying
this scheduling change. Original DNS and platform failures remain failures
in [source745 evidence](../../network-rewrite/evidence/full-rust-core-745c05a.json).
