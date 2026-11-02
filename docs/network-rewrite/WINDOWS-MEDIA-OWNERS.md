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
Its `owner-boundaries` job runs the same steps on both `windows-2022` and
`windows-2025` with matrix fail-fast disabled. The original `native_compressed`
integration command runs immediately after verifying the pinned native codecs,
before the desktop checks, so each Windows image retains an independent result
for actual two-TLS delivery, decoded credit reuse and joined cleanup. Original
assertions and deadlines remain unchanged; a pass on one image does not replace
a failure on the other. Source receipts include the runner label and OS.
Download each new artifact by its exact
`windows-media-owner-<windows-2022|windows-2025>-<source_revision>-<attempt>` name.
Repository scripts do not consume the old fixed artifact name; historical
evidence keeps the original artifact identities and results.

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
initial desktop capture source used BGRA8 SDR, so its P010 conversion was not HDR
or native ten-bit capture qualification. These changes still need exact-source hosted
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

The retained `2ffc870` Main8 encode and decode direction attempts both stopped
while validating the encoder-generated fixture: the original SPS reported
`vui.colour_primaries=0`, where the unchanged contract requires H.265 code point
1. No decoder-output success follows from those attempts. Both requested MF
types already used the correct Windows BT.709 enums (matrix 1, primaries 2,
transfer 5, limited range 2), and output-before-input type configuration follows
the [Microsoft HEVC encoder documentation](https://learn.microsoft.com/en-us/windows/win32/medfound/h-265---hevc-video-encoder).
Windows primaries enum 1 is reserved; replacing the correct MF value 2 with the
bitstream code point 1 would be incorrect.

The HEVC encoder now also negotiates the eight standard input/output
`ICodecAPI` primaries, transfer, matrix and range properties after setting the
media types and before beginning streaming. It uses the official
[`eAVEncVideoColorPrimaries`](https://learn.microsoft.com/en-us/windows/win32/api/codecapi/ne-codecapi-eavencvideocolorprimaries),
[`eAVEncVideoColorTransferFunction`](https://learn.microsoft.com/en-us/windows/win32/api/codecapi/ne-codecapi-eavencvideocolortransferfunction),
[`eAVEncVideoColorTransferMatrix`](https://learn.microsoft.com/en-us/windows/win32/api/codecapi/ne-codecapi-eavencvideocolortransfermatrix)
and [`eAVEncVideoColorNominalRange`](https://learn.microsoft.com/en-us/windows/win32/api/codecapi/ne-codecapi-eavencvideocolornominalrange)
enums. The documented
[`IsSupported`](https://learn.microsoft.com/en-us/windows/win32/api/strmif/nf-strmif-icodecapi-issupported)
results `S_FALSE` and `E_NOTIMPL` mean an absent property; they retain the correct
MF media type path and the original actual-AU acceptance gate. Supported
properties require `SetValue` and `GetValue` to return `S_OK` with the exact
`VT_UI4` value. In particular,
[`SetValue` returning `S_FALSE`](https://learn.microsoft.com/en-us/windows/win32/api/strmif/nf-strmif-icodecapi-setvalue)
means read-only and fails configuration. Unexpected support-call errors,
set/read errors, wrong variant types and conflicting values also fail.

Configuration logs each property receipt and both current MF media types. On
the first encoder validation rejection, the diagnostic records at most three
original VPS/SPS/PPS NALs, at most 256 bytes each, with their original lengths;
it never rewrites parameter sets, AUs or colour metadata. These changes still
need an exact-source hosted build and original target reruns. The native
metadata/property boundary test does not establish encoder signalling or GPU
execution. The separate original Main10 `0x8000ffff` creation failure remains
failed and is not explained by the Main8 SPS colour rejection.

The `b6b5520` target rerun still failed the original Main8 SPS colour assertion:
all eight standard colour properties reported `E_NOTIMPL`, while both current
MF types retained matrix/primaries/transfer/range 1/2/5/2. The bounded diagnostic
retained the exact 23-byte VPS, 52-byte SPS and 7-byte PPS. The fixed
[`hevc-main8-b6b5520-parameters.json`](fixtures/hevc-main8-b6b5520-parameters.json)
contains those original synthetic parameter NAL bytes and tool provenance, with
no VCL or image data. The original failed commands remain separately recorded.

The exact-source `hevc-parameter-diagnostic.yml` workflow submits this fixture to
the runner's FFmpeg `trace_headers` bitstream filter and ffprobe, using the
official Ubuntu package if the tools are absent. It first compares every fixture
byte with both original command logs, then supplies Annex-B delimiters without
changing the NAL payload. Its artifact records executable versions and SHA256,
source/workflow revisions, fixture and original-evidence hashes, raw stdout and
stderr, return codes, and the independently traced SPS field values/positions.
The small extractor reads only FFmpeg's textual field results; it does not parse
SPS bits. FFmpeg trace positions retain its own convention and must not be
equated directly with the local validator's `rbsp_bit` convention. Parameter-only
input contains no picture: exit codes and metadata extraction are retained as
diagnostics, with product/decode/GPU acceptance false. At introduction, this
independent hosted comparison remained pending and had to establish any parser
discrepancy before changing the original strict parser or attributing the failure
to the encoder.

The independently retained run
[41463941177](https://github.com/ZHanry/NestLink/actions/runs/41463941177), source
`3b4970f0cfa189dc54a46a709672c15896ebdb90`, has since compared the original
fixture bytes with both failed command logs. FFmpeg reports the same 1920x1088
coded extent, 1920x1080 conformance display, limited range, primaries 0,
transfer 1 and matrix 2. Its primaries start bit 271 includes the 16-bit NAL
header; removing that header and advancing through the eight-bit value yields
the original validator's `rbsp_bit=263`. This provides no evidence of a parser
offset defect. The parameter-only FFmpeg/ffprobe diagnostics provide no picture
decode or product acceptance. The unchanged exact HEVC contract independently
rejects the coded/display crop and colour values.

A separate, proven adapter request defect used `SetUINT64` for
`MFT_ENUM_ADAPTER_LUID`. The official
[`MFT_ENUM_ADAPTER_LUID` contract](https://learn.microsoft.com/en-us/windows/win32/medfound/mft-enum-adapter-luid)
specifies data type `LUID`, and the official
[`MFTEnum2` encoder example](https://learn.microsoft.com/en-us/windows/win32/api/mfapi/nf-mfapi-mftenum2)
uses `SetBlob(..., &adapterLuid, sizeof(LUID))`. The mature
[GStreamer implementation at 4a12497](https://github.com/GStreamer/gstreamer/blob/4a12497f066b3c02466800da6f19cbb8f409604e/subprojects/gst-plugins-bad/sys/mediafoundation/gstmftransform.cpp)
also writes a checked LUID blob. The thin native adapter now follows that
documented input representation and checks the exact blob type/size/value by
reading back its own request through the production identity reader.

An adapter-targeted input request is not evidence that every returned activation
publishes an adapter identity. The official enumeration contract does not make
that output guarantee. The mature
[Chromium implementation at 59017c5](https://github.com/chromium/chromium/blob/59017c54a7db7de13eff71f9fb71d34a9862e83e/media/gpu/windows/media_foundation_video_encode_accelerator_win.cc)
reads the activation attribute as a blob, checks the exact `sizeof(LUID)` and
both parts, and uses a separate resource-mapping path when they differ. It does
not infer adapter agreement from successful device-manager installation.
NestLink has no such cross-adapter resource-mapping path. Its supplied-device
encoder now accepts a candidate only when that exact activation blob is present
and matches the actual retained D3D source device. Missing, wrongly typed,
short, oversized and mismatching identities explicitly reject that candidate
before activation. This check also applies to `MFTEnumEx` when the runtime lacks
`MFTEnum2`; failed targeted enumeration never retries a global/CPU route.

The native diagnostics record the actual source D3D adapter LUID, description,
vendor/device IDs and driver-query result before codec configuration. They then
record the requested LUID and enumeration HRESULT/count, every attempted
activation's LUID read/binding result and blob length, bounded friendly name and
CLSID, and activation/configuration/selection results. Optional identity strings
remain `unknown` when their attribute calls fail. A zero-valued but correctly
typed LUID is a value, never a sentinel for a missing attribute. The earlier
failed HEVC commands did not retain their actual source/activation identities;
a successful H.264 command's adapter does not identify those HEVC attempts, and
their failure cannot be assigned to a GPU vendor.

The ordinary-token owner workflow now exercises real `IMFAttributes` using the
same production request writer, strict blob reader and adapter comparison. Its
nine boundaries cover the signed high LUID part, missing identity, the former
UINT64 representation, short/oversized blobs, independent low/high mismatches,
an explicit zero LUID and replacement of an existing wrongly typed attribute.
These metadata tests open no device or encoder. Their exact-source hosted result
and the original default physical commands still need a new build/rerun. No
adapter-selection CLI, AU/SPS rewriting, relaxed colour/geometry assertion or
GPU/performance/physical scanout qualification follows from this binding fix.

The existing v4 Main10 SDR source now selects WGC with a
`R16G16B16A16_FLOAT` frame pool and same-device retained RGB texture, followed by
the original P010 encoder surface. Its original monitor approval, worker,
session/DPI observer, deferred first-live-command `StartCapture`, format ACK and
actual SPS/PTS/colour/geometry gates remain in force. H.264/Main8 retain their
original BGRA8 duplication/WGC route. The Main10 route does not fall back through
BGRA8 or the GDI cursor compositor; WGC retains its system cursor composition.

This follows the official
[WGC high-colour capture guidance](https://learn.microsoft.com/en-us/windows/uwp/audio-video-camera/screen-capture)
and the separately selected Float16 WGC acquisition in
[Sunshine at c101250](https://github.com/LizardByte/Sunshine/blob/c10125088da1f61e72fe1c65faa996a297490d36/src/platform/windows/display_wgc.cpp).
The thin adapter first checks the exact Float16/scRGB interpretation to
P010/limited-range BT.709 combination with
[`CheckVideoProcessorFormatConversion`](https://learn.microsoft.com/en-us/windows/win32/api/d3d11_1/nf-d3d11_1-id3d11videoprocessorenumerator1-checkvideoprocessorformatconversion).
It requires `S_OK` and an affirmative support result, sets the explicit
`ID3D11VideoContext1` input/output colour spaces and requires exact readback.
Unknown interfaces, query failures, unsupported combinations and conflicting
readback fail source creation. No generic shader or tone-mapping fallback is
introduced.

The owner-local metadata receipt separates configured capture format, actual
first-frame texture format, configured input/output colour interpretation,
observed display colour space, display `BitsPerColor` and successful exact
conversion checking. The WGC Float16 interpretation is linear scRGB; the
receipt does not pretend that WGC supplies independent per-frame colour metadata.
Display precision and captured content precision are different observations.
An eight-bit SDR display is not promoted to a native ten-bit source by a
Float16 container, and every receipt explicitly leaves content precision and
HDR qualification false. Actual sample fidelity still requires physical
capture/conversion validation; the existing eight-bit decoded colour checks
cannot establish low-bit preservation.

The Main10 owner retains its original DXGI factory and colour-output snapshot.
Device borrowing, each live/repeated capture and the original HEVC source checks
require the factory to remain current and the display colour/precision,
primaries, white point, luminance, geometry, monitor and rotation facts to match.
Failure retires the source permanently and clears retained content; subsequent
matching facts cannot revive it. Actual foreign/changed Float16 surfaces also
retire the source. This follows the dynamic-output guidance in
[`GetDesc1`](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_6/nf-dxgi1_6-idxgioutput6-getdesc1).
The hosted metadata regression uses the same production native decisions with
DXGI/D3D structures, including unavailable conversion support, wrong formats,
foreign devices, HDR/precision changes and irreversible retirement. It creates
no device or capture session. These additions still require their exact-source
hosted results and authorized physical capture evidence. The original HDR
rejection and v4 SDR contract remain unchanged; the shared presenter still uses
its original eight-bit SDR output, so this increment does not complete W33.
