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
