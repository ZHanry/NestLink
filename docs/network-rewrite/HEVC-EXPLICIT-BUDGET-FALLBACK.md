# Explicit signed HEVC budget fallback

The daemon can accept one explicitly selected lower HEVC budget in addition
to its original exact target:

```powershell
nestlink-daemon --native-gpu-hevc-target 1920x1080@60:8000 --native-gpu-hevc-fallback-target 1920x1080@30:4000 --native-gpu-hevc-encoder amd-amf
```

The Main10 variant uses `--native-gpu-hevc-main10-target` instead of the Main8
target flag. Both remain SDR/4:2:0 modes. The lower target is optional and must
retain the original geometry, profile/depth, color and local encoder selection.
Its frame rate and bitrate cannot exceed the original and at least one must
be lower. It cannot be combined with a CPU target, a software candidate,
another HEVC profile or a second fallback. The existing feedback controller
has a 120fps maximum; explicit adaptive pairs respect that original ceiling.
Single exact targets retain their existing independent ceiling of 144fps.

This selection authorizes two finite candidate budgets, not a change of codec,
backend, pixel depth, color or physical source. Each local Encode or Decode
publication runs the original complete native direction workload for **both**
targets, serially on the original bounded worker. Both must pass all existing
actual SPS/output/color/accounting checks and checked resource cleanup. The
two observations must have the same original adapter, driver and selected
encoder/runtime, including the decode workload's sample producer. A failed
target fails the publication; the provider does not treat a probe failure as
permission to try the other target. The original total 30-second provider
budget, 10-second HEVC direction budget, GPU copy deadline and quarantine
behavior remain unchanged.

The local publication must include exactly the configured targets. The remote
request and host approval still use the existing signed exact format scope.
Only targets present in both peers' valid, actual direction announcements can
enter that scope. Approval rejects any unconfigured intermediate budget,
foreign geometry, profile, depth or canonical version. A scope containing
only one intersecting target runs that one target with no adaptive alternative.
Only a scope containing both exact signed targets can switch between them.

The real HEVC capture producer starts with the highest approved target. It
uses the existing producer cost, enqueue delay and authenticated receiver
feedback controller to choose among the signed targets. It never synthesizes
an intermediate frame rate, bitrate or resolution. Healthy recovery uses the
original approved ceiling rather than treating the reduced target as new
authority. Missing or stale receiver feedback keeps the controller's existing
behavior and cannot create a new upgrade observation.

A change may briefly pause video. While the old owner is still current,
Core verifies its exact registered identity, pauses the format gate and
discards queued video. The single original native owner then completes its
checked shutdown and join before a replacement can be created. The replacement
must produce an actual accepted AU, register its own original receipt, and
complete a fresh exact NLMF format epoch/digest ACK before any AU is delivered.
The receiver prepares its original owner for that exact proposed format through
the existing ACK path. Preparation, cleanup, deadline or ACK failure safely
stops the stream; no retired receipt is restored and no old frame is replayed.
This is bounded explicit fallback, not a claim of seamless switching.

Relevant production paths are `NativeSessionConfig::with_gpu_hevc_fallback_target`,
`NativeMediaProvider::with_hevc_fallback` / `run_probes`,
`CoreHandle::pause_native_video_execution`,
`nestlink_media_session::select_hevc_budget`, and the daemon's original
`native_video_hevc::stream`. No new wire format, signing authority or backend
substitution is introduced.

The added regressions exercise CLI mode conflicts and dispatch, exact fallback
configuration, signed approval/publication bounds, original driver/runtime
pairing, finite budget selection and original-ceiling recovery. The existing
Windows software Core regression additionally exercises the same production
pause/replace/ACK boundary with actual original codec receipts: a decoder
receipt cannot pause an encoder, pausing rejects delivery while the old encoder
is still current, checked join retires it, and a replacement encoder cannot
deliver before its new exact ACK. Those software results cannot attest GPU
HEVC execution. All tests, formatting, compilation and automated checks belong
to GitHub-hosted Actions and have not been run locally.

This source slice does not fix the retained original AMD 1080p SPS rejection,
qualify that device, implement 4:4:4/HDR owners or complete W33. The original
native target failures and all mandatory hardware/full-chain evidence remain.
