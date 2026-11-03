# Independent HDR PQ/BT2020 product path

This source slice adds an explicit Windows HDR target through the existing local
request/approval, exact signed format, capture, encode, decode, original-process
P010 export and desktop presenter owners. It is implementation awaiting hosted
build/tests and actual HDR hardware qualification. No synthetic or parser result
qualifies a physical display or closes W33/AC56.

## Explicit entry and wire boundary

```powershell
nestlink-daemon --native-gpu-hevc-hdr10-target 1920x1080@60:8000 --native-gpu-hevc-encoder amd-amf
nestlink-daemon media-capabilities --mode hevc-hdr10 --dynamic-range hdr10 --direction encode --target 1920x1080@60:8000 --encoder amd-amf
```

`system-mf` is also an explicit encoder selection. A failure never tries another
encoder, adapter, bit depth, color interpretation or software implementation.
The optional existing `--native-gpu-hevc-fallback-target` selects only one lower
rate/bitrate at the same geometry and HDR mode; both targets need complete actual
direction probes and the exact signed intersection. The original owner must
pause/close/join and its replacement must produce accepted output and obtain a
new exact NLMF ACK before delivery.

The independent descriptor and set use canonical version 5, the required marker
`native-media-format-v5`, separate format/set hash domains, and the approval domain
`nestlink/media-approval/v5`. The 69-byte descriptor retains actual full PTL and
explicit PQ, BT2020 primaries, nonconstant-luminance BT2020 matrix and limited
range. Version 3 remains Main8 SDR and version 4 remains Main10 SDR. A v4 envelope
with HDR color, a v5 envelope with SDR color, mixed catalogs, wrong markers or
wrong approval domains fail. Native video uses the existing Main10 codec number;
the signed exact format/epoch/hash establishes the independent color contract.

## Actual source, codec and output

The new native capture entry requires an approved original monitor whose current
DXGI output reports PQ/BT2020, at least ten bits per color and attachment to the
desktop. It creates WGC Float16/scRGB, checks actual frame texture format,
geometry and original device, and requires the exact D3D11 video-processor
conversion FP16/scRGB to P010/PQ/BT2020. Format/color conversion support and
video-context color readbacks must agree. Opening does not start capture; the
authorized execution's first explicit frame command does. Changes in monitor,
session, desktop, DPI, geometry, HDR mode or retained display metadata retire
the source. HDR has no duplication/GDI/BGRA replacement.

MF sets and checks its explicit BT2020/PQ/limited media types. Its old CodecAPI
color enums do not define PQ/BT2020, so this independent branch does not invent
values or apply the old SDR list. AMF requires explicit official BT2020 studio
profile, PQ transfer, BT2020 primaries/matrix and limited range. In every backend
the actual complete accepted SPS must prove Main10, 4:2:0, ten-bit luma/chroma and
VUI code points 9/16/9 with limited range. Original restrictions on PTL, crop,
timing, HRD, IDR/reference history, bounds and deadlines remain; rejected syntax
is never rewritten. V4 Main10 cannot pass through the independent HDR parser.

The independent ten-second probe uses actual P010 quadrants with explicit
ten-bit Y/Cb/Cr samples. The selected hardware encoder must produce 32 accepted
units with at least sixteen live outputs before EOS; both the original hardware
decoder and independent software decoder must preserve each quadrant within
the finite original accounting and checked close rules. Readback for this mode
packs three ten-bit samples into each 32-bit diagnostic word. It is never BGRA
or an HDR desktop presentation; ordinary CPU polling/export rejects it.

The live receiver retains its original P010 output and exports a version-5
native ring to the authenticated original local process. Native ring depth,
color marker, signed IPC descriptor and sealed frame fingerprint must agree.
The existing shared-ring size, keys, deadlines, original-process ownership,
consumption and checked retirement rules remain. The desktop requires an actual
HDR output and exact P010/PQ/BT2020 to Float16/scRGB video-processor conversion,
uses a Float16 flip-model swapchain explicitly set to scRGB, and checks current
monitor/color/luminance metadata around consumption/submission. Output changes
black and retire the owner. There is no SDR swapchain/CPU fallback for HDR.
Successful DXGI submission is still distinct from physical scanout proof.

The exact mandatory metadata here is actual SPS VUI plus current source/output
DXGI metadata and video-processor interpretation. This slice does not claim
content-specific mastering-display or MaxCLL/MaxFALL SEI extraction/authority,
dynamic HDR metadata, HLG, 4:4:4, lossless encoding or a calibrated display.

## Component choice and alternatives

The smallest complete integration reuses WGC, D3D11 video processing, existing
MF/AMF Main10 and original P010 sharing. This preserves existing owners and
requires no additional codec dependency. Microsoft's capture guidance requires
Float16 throughout HDR capture; Advanced Color guidance describes scRGB linear
BT709 composition, reference white of 80 nits and Float16/scRGB presentation.
Exact `CheckVideoProcessorFormatConversion` support still requires the actual
driver. Float16/P010 storage alone establishes neither capture precision nor HDR.

Alternative NVENC explicitly exposes HEVC FRExt/4:4:4 capability and planar
YUV444 ten-bit formats. It needs a new runtime, exact RExt SPS validation,
independent decode and a 4:4:4 capture/presenter chain, so it is a separate
remaining W33 path. AMF AYUV/Y410/RGBA surface enums do not establish HEVC 4:4:4.
The current slice makes no 4:4:4 capability announcement.

Sources reviewed:

- Microsoft WGC capture: https://learn.microsoft.com/en-us/windows/uwp/audio-video-camera/screen-capture
- Microsoft Advanced Color, docs snapshot `ca8274decead49403d70ceeed4af8d4ca74eaf11`:
  https://github.com/MicrosoftDocs/win32/blob/ca8274decead49403d70ceeed4af8d4ca74eaf11/desktop-src/direct3darticles/high-dynamic-range.md
- Exact D3D11 conversion API:
  https://learn.microsoft.com/en-us/windows/win32/api/d3d11_1/nf-d3d11_1-id3d11videoprocessorenumerator1-checkvideoprocessorformatconversion
- Microsoft Windows SDK `mfobjects.h` and `codecapi.h`, win32metadata main,
  read on 2026-11-03. MF transfer 2084=15 is distinct from HEVC VUI transfer=16;
  legacy CodecAPI primaries/transfer enums cannot be substituted for VUI values.
- AMF 1.5.3 headers/docs, source `57ee0cfb0e1a08d9041f77435653794c1b012be0`,
  already pinned in the repository's original AMF boundary review.
- `nv-codec-headers` n13.0.19.0 annotated tag
  `57f8cc0bb68e5f16f3787ea92cea59000f7bf97f`, source commit
  `e844e5b26f46bb77479f063029595293aa8f812d`. This is research, not a bundled
  runtime dependency or evidence that this machine supports NVENC/4:4:4.

All compilation, formatter output, tests and packages must come from hosted
GitHub Actions under R02. Target execution must retain the exact Actions
artifact hashes and both build/execution provenance. Original SDR/AMF failures
remain applicable and cannot be waived by the new mode.
