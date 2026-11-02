# 0068 — Register the original hosted X11 resident through real PAM

Date: 2026-11-02. Scope: the Linux original offline-resident fixture. The
replacement fixture is implemented but awaits exact-source hosted execution.

Run 41443851500, source `85c8da8d5ec1f7af4e393e31e299cc83bc36c53d`, exposed
the original host capture error `Failed to parse value ''`. Its original IPC
snapshot stopped with `platform_changed` and successful cleanup. The production
platform-session boundary parses logind's real `Display` and must keep rejecting
a missing display. The same fixture's pending-listener cases passed; they do not
open capture and cannot establish a valid graphical login.

The previous fixture reused systemd-run's `PAMName=login` with a real Xvfb and
`DISPLAY`. That adapter does not populate `PAM_XDISPLAY`. In reviewed systemd
v255 source, `setup_pam` sets `PAM_TTY`, while pam_systemd reads `PAM_XDISPLAY`
to register logind's Display. Supplying DISPLAY as an environment variable does
not fill this PAM item. These are actual upstream interface differences, not a
reason to accept missing facts in NestLink.

The selected adapter calls the runner's mature `libpam.so.0` and original
`login` stack with the actual fixture Xvfb display as `PAM_XDISPLAY`. It opens
and retains the real session, forks the original daemon, drops all child real,
effective and saved UID/GID values to the original runner account, waits for
that exact child, and closes the original PAM session. The child retains the
fixture's actual Secret Service. NestLink still uses the system bus and the
original child's PID to verify the actual UID, active/unlocked state, session
type/class and matching X11 display. No accepted fact, fake bus, screenshot,
clipboard, permit or authority is supplied by this adapter.

Alternatives considered:

- Keep systemd's existing PAMName adapter and add environment values. Rejected
  after the real execution and upstream read: the required item is not an
  environment value, so this cannot fill the real Display property.
- Set TTYPath to the X display, or use sudo/runuser as another launcher. The
  reviewed systemd transient TTYPath API requires a filesystem path; `:N` is
  not a TTY path. The reviewed sudo PAM adapter also supplies PAM_TTY and does
  not expose the required PAM_XDISPLAY selection. Pretending a display is a
  device pathname would not register the actual source.
- Install a complete display manager and graphical login desktop. This is a
  mature alternative for a full target fixture, but adds another graphical
  server/session owner to a bounded Xvfb experiment. The missing operation here
  is one standard libpam item; reuse that OS interface directly.

The adapter remains inside the existing exact systemd service owner, including
the original 180-second service bound and 5-second stop bound. It forwards
termination to the exact child, sets parent-death SIGKILL after dropping child
credentials, and rechecks the parent PID to close that race. Normal completion
waits for the original child before closing PAM. It runs only as a privileged
GitHub-hosted Linux fixture and never changes the product's normal-user checks.
There is no new package build, local execution, product PAM authentication
implementation or replaced OS service.

Reviewed sources, systemd v255 commit
`db11bab38ccf1ed257f310d29070843d4c58ea01`:

- <https://github.com/systemd/systemd/blob/db11bab38ccf1ed257f310d29070843d4c58ea01/src/login/pam_systemd.c>
- <https://github.com/systemd/systemd/blob/db11bab38ccf1ed257f310d29070843d4c58ea01/src/core/exec-invoke.c>
- <https://github.com/systemd/systemd/blob/db11bab38ccf1ed257f310d29070843d4c58ea01/src/core/dbus-execute.c>
- <https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/plugins/sudoers/auth/pam.c>
- <https://github.com/linux-pam/linux-pam/blob/v1.5.3/Copyright>

Reading these sources does not create a clean-room claim. This adapter calls
the existing OS library; it does not copy a login manager or PAM implementation.
The runner's distribution supplies the exact library build. Keep the failed
source85 receipt, and require a new same-source original capture/pixel/file/
rebuild execution before claiming that the new fixture passes.
