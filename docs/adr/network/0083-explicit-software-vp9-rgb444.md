# ADR 0083: Explicit software VP9 sRGB 4:4:4

Date: 2026-11-03. Status: native adapter and shared execution source implemented;
hosted validation, independent wire contract and product wiring pending.

W33 requires actual full-resolution color components. The existing Windows MF
HEVC decoder publicly exposes NV12/P010 and Main/Main10. Its public contract
cannot establish a HEVC range-extension 4:4:4 decoder. Current target AMF/MF
failures remain failures. A software 4:4:4 capability will not satisfy HEVC444,
GPU444, HDR, capture/display or sustained high-frame-rate qualification.

Reuse fixed libvpx 1.16.0 (`1024874c5919305883187e2953de8fcb4c3d7fa6`)
and its already reviewed bundled libyuv 1711
(`a37e7bfece9e0676ae90a1700b0ec85b0f4f22a1`). The same archive, archive hash,
licenses and source receipt remain. Enable actual VP9 encoder/decoder build
features and verify their generated configuration. Add only upstream
`convert_from_argb.cc` to the previous fixed libyuv source closure. Both target
architectures and release MSVC dynamic CRT requirements remain enforced.

Select VP9 profile 1, eight-bit I444 storage with sRGB/full-range signaling.
libyuv `ARGBToRAW` and `SplitRGBPlane` map BGRA to full-size R/G/B components;
VP9 sRGB stores G/B/R in Y/U/V storage. `MergeRGBPlane` and `RAWToARGB` reverse
the mapping. This avoids the bundled libyuv `ARGBToI444` BT.601-only matrix.
No chroma subsampling or YUV color matrix is claimed. The stream remains lossy;
alpha is opaque. Hidden frames, interframes, reference replay, lag, alt-ref and
frame dropping are excluded. Every input must produce exactly one complete
visible keyframe at the original PTS.

Use libvpx's public `vpx_codec_peek_stream_info` before decode to reject
non-keyframe or wrong dimensions; do not implement a general VP9 parser. Actual
decoded frames must independently expose I444, eight bits, zero chroma shifts,
sRGB/full range, exact geometry, positive full-width planes and exactly one
output. These properties imply the selected eight-bit sRGB profile 1 contract.
Keep the 8MiB packet and 64MiB raw budgets. Raw samples and temporary conversion
buffers have wiping owners; native checked close errors preserve the native
state and fail owner retirement.

Generalize the original software execution owner to exact H264/VP9 targets,
retaining its bounded queue, command/start/join deadlines, sealed output hashes,
resource identity, cancellation fence, checked close and sticky quarantine.
Mint a private random identity only after successful actual native context
creation. No request, descriptor or IPC identifier can construct a live receipt.
There is no second scheduler or implicit codec/backend fallback.

New finite production-adapter probes require 32 immediate outputs, original
encode/decode contexts and identities, exact geometry/PTS, adjacent red/blue and
green/gray one-pixel samples, checked close and the original ten-second bound.
The probe proves functional work only. Its target geometry/rate/bitrate must
pass directly; they are never clamped or substituted. The standalone tool is
`vp9-rgb444-direction-probe encode|decode WIDTH HEIGHT FPS KBPS`.

The user explicitly authorized updating the old supplier tamper input from
VP9=true to VP9=false and adding VP9-encoder=false/RGB444-conversion=false
rejection cases. The original `assertRaises(SupplyError)` and every existing
performance, time and Luanti gate remain. No compiler, test, formatter,
dependency installer or other automatic check ran locally. New exact-source
GitHub-hosted supplier/build/Clippy/tests are required before any pass claim.

Public sources:

- [libvpx public interfaces](https://github.com/webmproject/libvpx/tree/1024874c5919305883187e2953de8fcb4c3d7fa6/vpx)
- [Pinned VP9 encoder and sRGB contract](https://github.com/webmproject/libvpx/blob/1024874c5919305883187e2953de8fcb4c3d7fa6/vp9/vp9_cx_iface.c)
- [Pinned bundled libyuv interfaces](https://github.com/webmproject/libvpx/tree/1024874c5919305883187e2953de8fcb4c3d7fa6/third_party/libyuv/include/libyuv)
- [Microsoft HEVC decoder profiles and output](https://learn.microsoft.com/en-us/windows/win32/medfound/h-265---hevc-video-decoder)
