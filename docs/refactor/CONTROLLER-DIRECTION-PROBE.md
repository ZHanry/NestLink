# Windows controller direction diagnostics

The Windows GitHub core job builds a separate
`windows-controller-direction-probe.exe` and binds its bytes, source files,
source commit, run and attempt in `controller-probe-build.json`. It never runs
this diagnostic on GitHub. Verify the original artifact ZIP digest, manifest,
exact source and successful complete Windows job before target execution.
Run under an ordinary interactive Windows token with an external process
watchdog; one driver call cannot be preempted by the internal ten-second budget.

The command requires explicit width, height, target FPS, bitrate ceiling and
`cpu-software`, `cpu-hardware` or `gpu`. The diagnostic creates only its own
synthetic fixture/window. It validates actual H264 SPS constraints, coded/display
geometry, decoded output dimensions, FIFO timestamps and known output color.
CPU and GPU use an independent decoder owner. Hardware qualification requires
actual output and the same resource UUID, adapter LUID and driver revision
before and after processing; unavailable metadata stays unknown and fails that
qualification. Unknown or unsupported targets exit with failure.

The bounded fixture supplies up to 24 IDRs; at least 16 decoded/color-verified
outputs are required. GPU also requires actual retired pictures and at least
one DXGI submission. RGB channels differ by more than twice the comparison
tolerance, so an R/B swap fails validation. Every fixture frame has the same
color: FIFO timestamp checks do not prove per-frame pixel/timestamp identity
or rule out an older same-color picture.

Checked flush/end-stream failures prevent a successful receipt. Pending decode
and picture discard counts remain explicit; `eos_complete` and
`performance_qualified` stay false. A single atomic synthetic GPU owner slot
bounds active plus quarantined owners to one. Construction failure and completed
destruction release the slot; timeout retains it. Live GPU owners keep their
existing close path and do not enter this diagnostic quarantine mechanism.

This is a finite functional capability observation. It does not enable signed
format negotiation or production HEVC/4:4:4/ten-bit, establish sustained FPS,
prove physical capture, verify scanout or replace remote-desktop acceptance.
