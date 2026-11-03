# Explicit AMF rate control for the original remote owner

The original Windows AMF owner keeps its supplied D3D11 device, ultra-low-latency
usage, CBR rate control, exact frame rate and target bitrate, Main tier and
workload level, GOP size 1, forced IDR pictures and existing color controls.
Its initialization now explicitly sets the official
`AMF_VIDEO_ENCODER_HEVC_ENFORCE_HRD` and
`AMF_VIDEO_ENCODER_HEVC_FILLER_DATA_ENABLE` bool properties to false. Remote
control has finite queues and a bounded transport budget; it does not need
filler bytes to pad a constant-rate HRD channel.

Both properties are required. An absent, contradictory or differently typed
descriptor, validation coercion, failed set, changed readback, changed canonical
alias value or post-Init change still rejects this owner. The only additional
aliases are the exact bool descriptors `TL0.QL0.HevcEnforceHRD` and
`TL0.QL0.HevcFillerDataEnable`. They use the existing complete bounded descriptor
inventory, uniqueness, same descriptor identity and exact canonical readback
checks. Temporal/quality layers, arbitrary prefixes, integer substitutions and
optional-property omission are refused. The same-file contract adds these
positive and negative cases while retaining the original Rust assertion and
its entire previous result mask.

The fixed official source is AMF 1.5.3, commit
`57ee0cfb0e1a08d9041f77435653794c1b012be0`, already selected in
`docs/refactor/native-codecs.lock.json`. The official header archive is
`AMF-headers-v1.5.3.tar.gz`, SHA256
`0f521ad98041f8001147cded4a660127f18b1c27a801a5cd691bda1fa48381be`.

- [Official HEVC interface, dynamic rate-control properties](https://github.com/GPUOpen-LibrariesAndSDKs/AMF/blob/57ee0cfb0e1a08d9041f77435653794c1b012be0/amf/public/include/components/VideoEncoderHEVC.h):
  `HevcEnforceHRD` and `HevcFillerDataEnable` are bool controls. They are also
  present in the independently retained official 1.4.21 interface.
- [Official HEVC API reference](https://github.com/GPUOpen-LibrariesAndSDKs/AMF/blob/57ee0cfb0e1a08d9041f77435653794c1b012be0/amf/doc/AMF_Video_Encode_HEVC_API.md):
  the `ENFORCE_HRD` section describes constraints on rate control to meet the
  HRD model; the `FILLER_DATA_ENABLE` section describes filler for CBR. The SVC
  per-layer table explicitly lists both controls and requires quality layer 0.

The retained aa1f5f0 target log independently records bool descriptors for both
base-layer aliases. It records AMF runtime 1.4.22 against 1.5.3 headers and a
41,060-byte filler NAL in the first rejected Main8 access unit. These observations
justify explicit settings and runtime verification rather than assuming the
newest documented defaults apply to the installed driver.

This is a configuration candidate, not evidence that POC timing is fixed or
that the target passes. The official properties do not promise control of
`vui_poc_proportional_to_timing_flag`. The aa1f5f0 original rejection remains
`sps.poc_timing`; its failure precedes the strict parser's HRD-flag read.
The original SPS parser, format contract, output bytes, assertions, ten-second
direction workloads, copy deadlines, cleanup and no-fallback behavior remain
unchanged. No NAL is rewritten. Main10 native-format refusal and all retained
MF/AMF target failures remain evidence. Only Actions-built tools and the original
strict target commands can establish the resulting native output behavior.

Source editing and manual review were local. All compilation, tests, formatting
and automated validation belong to GitHub-hosted Actions.

## Geometry investigation after the original target run

The independently retained original 4de4b9b output has 60/1 SPS timing,
`vui_poc_proportional_to_timing_flag=1`, ticks-minus-one 0, coded luma dimensions
1920×1088, and a conformance window removing eight bottom luma rows for a
1920×1080 display. Disabling HRD and filler removed the original 41,060-byte
filler NAL but did not change the original `sps.poc_timing` rejection. Even if
that earlier syntax condition were satisfied, the original exact uncropped
1920×1080 contract would reject this independently observed coded geometry.
The original parser, contract, assertions and failed commands remain unchanged.

The pinned official 1.5.3 HEVC header exposes `HevcFrameSize` and hardware
resolution ranges, but no public control for SPS coded dimensions, conformance
window or coding-unit size. The API reference's `FRAMESIZE` section describes
input frame dimensions and hardware-specific limits. `INTRA_REFRESH_NUM_CTBS_PER_SLOT`
controls how many 64×64 coding-tree blocks are refreshed; the ROI sections
assign importance per 64×64 block. Neither selects a coding-block geometry.
`AMFIOCaps::GetVertAlign` is explicitly documented as **memory alignment in
lines**. Its observed value cannot establish control over SPS geometry.

The retained original runtime's complete 126-property descriptor inventory
also exposes no coded-size, crop/conformance-window or coding-unit-size
property. Slice controls, frame size, GOP alignment and surface memory
alignment do not document the required behavior. No undocumented property is
invented, no padded input is relabeled as uncropped output, and no access unit
or SPS is rewritten. This establishes the absence of a supported configuration
fix in the reviewed pinned interface and observed runtime inventory. It does
not prove every AMD adapter/driver or future AMF version is unable to produce
an exact uncropped stream. The current original driver/adapter result remains
unqualified and must fail its actual requested mode.
