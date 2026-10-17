# Native text clipboard product integration

Native clipboard actions are explicit one-shot operations on an already connected native
session. The UI offers two commands: **Copy remote clipboard to this device** and **Send
this device's clipboard to the remote device**. Session startup, clipboard status
observation, remote copy notifications, reconnect, and retry never read or write clipboard
text.

## Authorization matrix

Each action needs both the matching remote permit and separate local consent at both endpoints:

| Explicit action | Remote permit | Host local consent | Controller local consent |
| --- | --- | --- | --- |
| Copy remote to local | `ClipboardRead` | Read | Write |
| Send local to remote | `ClipboardWrite` | Write | Read |

The Core route binds the request ID, connection generation, and Core generation. It
rejects any IPC command that does not match all three. Consent has no permissive default.
The platform clipboard adapter and SDK must also recheck the live lease and
direction-specific consent at dispatch, OS access, queue delivery, and completion; a
route-level authorization check alone does not authorize an OS call.

## Text handling

Clipboard text remains one-shot data in the existing zeroizing SDK and platform path. IPC
requests carry the exact session binding plus direction choices or a one-shot action;
replies contain only status or a sanitized result/effect. Text must not enter `Snapshot`,
debug output, logs, operation history, serialization caches, cancellation retries, or
reconnection queues. A lost acknowledgement is not replayed automatically because the OS
effect may already have happened.

## Connected flow

When an accepted native session carries either clipboard permit, Core attaches a
`NativeClipboardRoute` using the exact request ID, connection generation, Core generation,
and proved channel claims. The host immediately starts one switchable RPC owner with no OS
adapter installed, so clipboard requests are denied without local clipboard calls until a
local direction is selected. The controller keeps its claimed transport until it has
opened the platform adapter after that same explicit selection. Later approval installs the
adapter into the existing host owner; it does not reclaim the channels or replace the
owner. Directions can be revoked during that session, but adding a direction requires a
new native session.

The Core route maps the UI's local Read/Write choices to the remote permits for each
endpoint, opens the platform adapter only after a local choice, and supplies live consent
checks to controller SDK operations. A controller remote read rechecks consent after it
consumes and validates the exact reply, before exposing its text to the platform write.
Revocation turns that response into a denial while advancing the channel sequence so the
next authorized request can still use the session.

`crates/app-ipc/src/clipboard.rs` serves status, direction selection, and one-shot action
commands. `apps/desktop/src/clipboard.rs` presents the two local direction choices and
the Copy/Send actions. The IPC carries bindings, directions, actions, and sanitized
effects only; clipboard text stays in the SDK/platform path.

The daemon installs `DesktopClipboardFactory` from `apps/daemon/src/main.rs`. Windows opens
the native Windows adapter after local selection. Linux opens X11 using the configured
desktop process identity and display, or transfers a grant from the existing Wayland
RemoteDesktop portal session. The Wayland grant is matched to the full Core binding and is
not reopened as a separate clipboard session. Core stops and joins the SDK and platform
owners with the native session. Factory open can return an inactive failed owner when
started platform work cannot prove timely cleanup; Core checks it before installation and
retains it after rejecting readiness. If cleanup remains pending or failed, the route
retains the owner for another cleanup pass. The platform monitor publishes completion only
after backend destruction and the original actual worker join; late joins preserve the
original cleanup failure. Unknown Device drops retain that same handle in the finite
32-worker budget, with no background reaper or replacement worker.

## Verification status

The fixture coverage includes
`switchable_host_denies_until_selected_then_revokes_without_stopping_view`, which checks
that the unselected host owner rejects promptly with zero fixture OS reads/writes, then
accepts a device on that same owner after selection and honors revocation. The
`revoked_controller_write_consent_consumes_read_reply_and_keeps_sequence_reusable` test
revokes controller consent while a host read is held behind a fixture gate, then verifies
that the consumed response is denied and the next sequence succeeds. Both fixtures cover
the TLS and QUIC transports. Cleanup retention is exercised by
`switchable_owner_keeps_platform_device_until_cleanup_is_proven`.
Late adapter installation after host retirement is rejected by
`retired_switchable_owner_rejects_late_adapter_install`.

The Windows concentrated regression on 2026-10-15 ran all twelve SDK clipboard tests,
including these consent and retained-owner fixtures, with twelve passes and zero failures.
The retained log is
`artifacts/core-verification/native-files-clipboard-regression-20261015-attempt04.log`.
That batch still had failures in the Core audio/file shutdown and remote audio lifecycle
targets; it is not a passing whole-product receipt. Subsequent WebRTC data integration and
clipboard decode rejection cleanup require their own current-source checks.

The Windows workspace runtime attempt06 still fails its private window-station
fixture before clipboard access. The 2026-10-15 diagnosis verified that the ordinary
test child retains the parent's filtered user token, with no AppContainer, Job UI
restriction or Win32k-disable mitigation. The session's WindowStations directory
denies CREATE_OBJECT. Microsoft's CreateWindowStationW documentation also reserves
explicit names for Administrators. A new NULL-name + CWF_CREATE_ONLY probe returned
error 183 because the automatic-name station already exists, without opening it.
The original fixture remains unchanged and failed; its isolated station/desktop
must be created in a suitable Windows test environment before the real test can
pass. Evidence and a precise execution entry are retained in
`artifacts/windows-private-clipboard-followup-20261015/`; no clipboard, existing ACL
or global setting was accessed or changed by this diagnosis.
