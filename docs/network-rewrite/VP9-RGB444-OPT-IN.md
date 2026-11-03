# Explicit software RGB444 mode

The independent v6 mode uses fixed libvpx VP9 profile 1, eight-bit, full-range
sRGB and three full-size color components. It is lossy RGB444. It makes no
HEVC444, GPU444, HDR or sustainable-frame-rate claim. Existing HEVC/hardware
target failures remain recorded failures.

Configure both native peers explicitly, for example:

```text
nestlink-daemon --native-vp9-rgb444-target 1920x1080@60:8000
```

This requests one exact geometry/rate/bitrate. It does not add an adaptive ladder,
implicitly try another codec/backend or shrink a failed workload. Normal host
approval and the deployment's existing media authority rollout gate still apply.
Both original direction probes must finish and publish their independent signed
scope before a request can proceed. Configuration and an unsigned inspection
report alone grant no remote authority.

Inspect one actual direction without granting permission:

```text
nestlink-daemon media-capabilities --mode vp9-rgb444 --chroma 444 --dynamic-range sdr --direction encode --target 1920x1080@60:8000
nestlink-daemon media-capabilities --mode vp9-rgb444 --chroma 444 --dynamic-range sdr --direction decode --target 1920x1080@60:8000
vp9-rgb444-direction-probe encode 1920 1080 60 8000
vp9-rgb444-direction-probe decode 1920 1080 60 8000
```

The selected workload must itself complete 32 outputs with exact PTS/geometry,
adjacent one-pixel RGB samples and checked original-owner close inside ten
seconds. This finite functional work does not establish the requested steady
fps, desktop capture latency, transport performance, color-managed monitor
photometry or physical scanout. A high-resolution/high-rate target may fail;
failure produces no replacement capability.

The production path retains the existing authorized BGRA desktop capture and
normal source/session/layout checks. libyuv splits the RGB bytes into full-size
G/B/R planes for VP9's sRGB storage. Every encoded packet is an independent
visible keyframe. No YUV matrix conversion or chroma subsampling is performed.
The original shared software worker seals each output against exact native
context identity, generation, target digest, PTS and bytes. Its original queue,
command/start/join bounds, cancellation fences and quarantine remain.

The v6 descriptor, format/set hash domains, required capability marker and
approval domain are separate from v2-v5. The ordinary NLMF proposal/ACK route
must confirm this exact signed target before delivery. A native protocol enum
or peer-provided descriptor cannot create an executable receipt.

The original daemon decoder verifies the mature libvpx keyframe/geometry result
and actual decoded I444/eight-bit/sRGB/full-range metadata before returning BGRA.
Its same sealed output goes through the authenticated finite export ledger and
independent `NLVID006` IPC marker to the existing desktop CPU presenter. The
compressed hardware presenter and shared HEVC rings do not accept this mode.
Changing a codec byte or marking this output as hardware is rejected. Odd RGB
dimensions are preserved exactly; there is no 4:2:0 even-edge padding.

Normal newly captured v6 all-intra frames use ordinary frame pacing. The
existing keyframe recovery interval remains for cached `repeated_source`
recovery frames and all previous codecs. This distinction requires an actual
current sealed v6 output matching the selected exact format, PTS and bytes;
registration markers, retired owners, changed packets and other formats cannot
obtain it. The pacing boundary regression is an explicit actual-owner hosted
experiment; no result is claimed before its producer passes.

All compilation, formatting, lint, tests, supplier builds and packaged tools are
produced by GitHub-hosted Actions. Source implementation is not target or release
qualification. Track the exact source and independent producer evidence before
including this mode in a release capability claim.
