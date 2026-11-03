# ADR 0081: Request an AMF level for the actual workload

Date: 2026-11-03. Status: implemented source; hosted and target validation pending.

The original eight finite commands on source `8f1ac1d` all failed. In particular,
the AMF Main8 decode direction reached two accepted inputs and one output, then
the original incomplete diagnostic parser rejected actual level 186 (6.2).
Its existing `!complete && level >= 156` boundary remains unchanged. The enum
list in that diagnostic does not override this additional condition. The encode
direction separately failed its original 16ms GPU copy deadline; that failure
and deadline also remain unchanged.

After the existing explicit copy/EVENT flush, its poll now uses the supported
`D3D11_ASYNC_GETDATA_DONOTFLUSH` flag, avoiding repeated implicit flushes while
observing the same EVENT. This does not establish the cause of the earlier
timeout or guarantee a faster GPU. The original deadline, retained source,
EVENT, slot, error and close/quarantine conditions all remain in force.

The official pinned AMF 1.5.3
[HEVC header](https://github.com/GPUOpen-LibrariesAndSDKs/AMF/blob/57ee0cfb0e1a08d9041f77435653794c1b012be0/amf/public/include/components/VideoEncoderHEVC.h)
documents `HevcProfileLevel` and says its default depends on hardware capability.
The adapter had configured profile, Main tier, geometry and rate, but left this
level at the hardware default. A 1080p60 request therefore need not get a level
appropriate to its actual workload.

We compared accepting that default through the newer complete parser and
requesting a level through the existing official encoder API. Choose the latter
so the original diagnostic gate remains meaningful. A small local policy chooses
conservative Main-tier levels 4.1, 5.1 or 6.2 from actual picture size, luma sample
rate, bitrate and both dimension bounds. The numeric standard limits were
cross-checked against the existing pinned FFmpeg n8.1.2
[H.265 profile/level reference](https://github.com/FFmpeg/FFmpeg/blob/38b88335f99e76ed89ff3c93f877fdefce736c13/libavcodec/h265_profile_level.c).
No FFmpeg implementation or new parser is imported. These three choices are a
conservative application request, not a minimum-level or standards-conformance
attestation. No supported workload is silently resized, slowed or clamped.

`HevcProfileLevel` uses the same required descriptor/type/range validation,
set/readback and post-Init readback as the other exact AMF controls. The runtime
must accept this value; there is no retry with a different level, backend,
adapter or source. The existing output validators still decide whether actual
SPS, color, geometry and access units are acceptable. A requested level cannot
make a failed actual output pass. High workloads that require level 6.2 still
do not satisfy the old incomplete diagnostic boundary.

A separate scalar boundary regression checks the real selection helper at
picture/rate/bitrate/dimension limits and invalid workloads. All earlier native
contract assertions are retained. No compiler, test, formatter or native tool
ran locally while authoring this change. New exact-source Actions builds and
the unchanged original eight target commands are required; all previous target
failures remain failed.
