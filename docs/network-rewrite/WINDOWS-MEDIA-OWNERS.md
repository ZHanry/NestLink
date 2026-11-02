# Windows media owner evidence and remaining integration

The real desktop GPU receiver now records the original worker's successful DXGI
submission QPC values. Recording is O(1): one lifetime first/last/count and at
most 512 recent timestamps. A duplicate or reversed native timestamp is retained
as an error count. The normal diagnostic report and the actual joined terminal
receipt carry that metadata; a new receiver owner starts its own window.

Use the downloaded Actions product, retain its independent source and executable
hash, collect the real product's GPU diagnostic report after stopping the session,
and run the Actions-built inspection source as an explicit target evidence step:

```text
python network-rewrite-gpu-cadence.py --diagnostics native-gpu-diagnostics.json --product nestlink-desktop.exe --product-sha256 <independent-Actions-hash> --source-revision <40-character-source> --output gpu-submit-measurement.json
```

The tool requires a live observed terminal from the original recorder, completed
worker join and revocation, no failed or pending terminal write, consistent actual
output counts, configured 1920x1080 and the real positive QPC frequency. It reports
the original 60-second, 58fps and p95 25ms thresholds using integer comparisons.
The p95 covers the explicitly bounded recent window; it cannot qualify the whole
session when that window rotated. The supplied executable hash does not prove
which image ran. DXGI submission is not physical scanout. Accordingly the report
keeps AC54 and physical GPU qualification false; target topology, exact running
image/driver/display identity and actual screen presentation evidence remain
required. Synthetic analyzer fixtures are never GPU evidence.

The exact-source `windows-media-owner.yml` workflow runs ordinary-token receiver
diagnostic/presenter regressions, negative analyzer cases and strict desktop
Clippy. It records source, workflow, dependency lock and tool hashes independently
of its runtime logs. Hardware absence cannot be turned into a physical GPU pass.

The HEVC addition reuses the existing bounded Annex-B/SPS parser and original MF
transform, timestamp ledger, bounded tracked textures and checked teardown. An
immutable local Main8 output contract records every general PTL compatibility
and constraint bit, exact uncropped coded/display geometry, explicit BT709
limited color, target rate and bitrate. Unknown color is rejected. Changed PTL
or rejected parameter sets cannot replace accepted parser history.

`MfHevcTextureEncoder` accepts an original worker's real same-device NV12 texture
without requiring a synthetic source. It checks authority and exact native
resource/adapter/driver identity around work, separates input acceptance from
actual output, validates each returned AU against the original contract and
requires actual hardware-output identity before returning bytes. Returned bytes
and scratch storage are zeroized. The owner retains the existing MF pump and
checked close; its caller must own approval, worker stop/join and signed epochs.

Exact HEVC format data now has its own v3 canonical encoding: 69 bytes, including
all twelve general PTL bytes. The original v2/H264 57-byte encoding and digest
domains remain unchanged. A v3 format set cannot mix canonical versions, and the
signed announcement/permit uses its own `native-media-format-v3` marker. Store
freezing, explicit SDK versioned requests, first approval and permit comparison
retain that version. v3 approval has a separate signing domain; a valid old v2
approval cannot approve it. NLMF carries the complete canonical format and exact
ACK identity. The local codec contract hash remains a separate domain and cannot
replace the signed canonical wire digest.

`HardwareHevcExecution` now owns a dedicated actual native worker and sealed
registration/AU/pixel receipts. Its source factory runs on that worker; original
COM/device/texture pointers cannot be transferred from the caller. A fresh
native UUID, monotonically increasing generation and the exact frozen original
adapter/driver are checked around operations. Only actual hardware outputs with
accepted exact AU admission receive output receipts. Byte, PTS, direction and
generation changes are rejected. Both caller authority and original retirement
invalidate copied receipts. The queue holds two commands, each with a 500ms
budget; startup uses two seconds and checked close/join uses 250ms. Timed-out
workers stay globally quarantined until actual thread join; failed native close
poisons replacement. A dropped or expired ticket retires its original generation.

`WindowsCaptureSource::start_hevc_encode` connects the factory to the real
previously enumerated monitor, complete session/display/DPI snapshot and sticky
OS observer. Source opening does not read pixels; explicit live commands capture
same-device NV12 surfaces. There is no synthetic source, software encoder or
implicit geometry replacement on this path. A platform/session/source change
fences output and closes the original worker resources.

Subsequent source additions implement an explicit single-target
`NativeMediaProvider::gpu_hevc_main8` preparation route and a separate
`GpuHevcPresenter` native HEVC subtype entry. The finite provider probe uses
synthetic quadrant input, requires at least sixteen actual hardware encode,
hardware decode and independent software decode outputs before EOS, checks exact
PTS/color/PTL history, accounts for every accepted/output/drained frame and
completes checked native close on the original worker. The announcement uses the
actual UUID of its own direction and original adapter/driver. These remain
closed historical capability observations, never live execution receipts or a
screen/cadence pass. The GPU presenter reuses the original NV12 video processor
and DXGI child surface with no CPU readback fallback; only actual successful
submissions can create its sealed QPC/sequence/PTS receipt. Its receipt explicitly
does not prove physical scanout or worker join. The new signed-target conversion
compares complete v3 PTL, geometry, integer timing, bitrate and canonical digest
against the live execution/submission target.

The exact-source ordinary-token Actions run
[41371616968](https://github.com/ZHanry/NestLink/actions/runs/41371616968), source
`122a1a9b946e0b2dce88e92c49d00afda988826e`, passed nine receiver diagnostic tests,
three existing presenter tests, five strict HEVC parser tests, four sealed HEVC
execution lifecycle negatives and nine real Store media-authority tests. Protocol
media tests, the three analyzer negatives and strict desktop/codec all-targets
Clippy passed as well. The artifact digest is
`5ff040351e75f98fef381aebd474b3b2ce816d5fa2eddf72bc52d67d1d8c5083`; the
[retained source-bound evidence](evidence/windows-media-owner-qualified-41371616968.json)
includes source/workflow/lock and downloaded log hashes. This verifies the source
and lifecycle boundary through the original capture factory. Provider, HEVC GPU
presentation and target-conversion additions after that source require their own
new exact-source results. None of these hosted boundary tests constitutes actual
physical GPU or independent target acceptance.

Subsequent source now connects the explicit Main8 provider, real daemon capture
and encode owner, exact v3 media authority/ACK/NLMF registry, original hardware
receive owner, native-TLS destination process export and desktop shared NV12
import/presentation. The desktop shared route opens no independent HEVC decoder;
its GPU consumption/submission receipt stays separate from the original daemon
decode receipt. See [the exact ownership and remaining-work record](gpu-shared-surface-owner.md).
The earlier hosted result above predates this route and does not validate it.

W33 remains incomplete in source: real 4:4:4 resources, HDR capture/
transfer/output metadata, the fractional target matrix and executable
per-combination fallback are not implemented by the Main8/420/eight-bit SDR
entry. Its original allocation/probe/capture/codec/import owners now admit
bounded exact 4K and integer targets through 144 FPS, within the same byte limits.
Each combination still requires an actual independently completed direction
probe and signed level/rate checks; configuration adds no qualified format.
W32 also retains decoder BGRA readback alongside the new GPU copy, so removing
that readback is further performance work. Actual cadence, device loss,
multi-adapter/display/DPI switching, input and concurrent workloads still need
same-source physical execution. `PRODUCTION_ISSUANCE_ENABLED` remains false.
These implementation gaps and acceptance gaps must remain distinct.

The Main10 SDR entry now has a separately versioned v4 signed scope and native
wire/IPC markers. Its exact SPS parser, original MF/P010 input/output, capture
video-processor P010 surface, finite depth-bound shared ring and actual P010
import/presentation are connected. Its real direction probe requires hardware
encode/decode and an independent software decoder before publication. The
desktop capture source remains BGRA8 SDR, so P010 conversion is not HDR or native
ten-bit capture qualification. These changes still need exact-source hosted
validation and physical hardware execution; see the detailed owner record.

The actual 1920x1080/60/8000 GPU controller direction attempt built by hosted run
41452426792 at `2ffc870909d50904379fdbd2b4dc5e060248a6d9` failed at MF
`STREAM_CHANGE`: the original SPS describes a 1920x1088 coded frame cropped to
1920x1080, and the decoder declared that same integer minimum display aperture,
but the presenter required raw coded dimensions to equal the visible dimensions.
That attempt remains failed. The repair pins the independently validated SPS
coded/crop geometry on the same native owner before input, accepts padded MF
output only when its complete aperture matches that geometry, and reconfigures
the video processor for the actual coded input with the unchanged visible
output. Already cropped raw output remains valid; unbound padding, foreign
coded extents, shifted/conflicting or fractional apertures and malformed blobs
remain invalid. The ordinary-token hosted metadata regression uses the same
production reader on real IMFMediaType objects. The corrected tool still needs
its own same-source hosted build and original target rerun; these metadata
checks do not establish GPU execution or physical scanout.
