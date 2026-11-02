# ADR 0075: Explicit AMF encoder with the original HEVC owner contract

Date: 2026-11-03. Status: initial adapter implemented; hosted and target
qualification pending; production provider/live selection integration in progress.

The existing System MF path can activate a Main8 encoder on the current AMD
device, but its original SPS declares primaries 0 where the signed BT.709
contract requires 1, and the recorded coded geometry is 1920x1088 rather than
the exact uncropped 1920x1080 contract. Original Main10 activation found no
encoder in the exact AMD scope. These are retained failures. Rewriting SPS,
weakening geometry or silently choosing another encoder cannot qualify them.

R01 requires mature reuse. We compared retaining MF alone, official AMD AMF
interfaces with the installed driver, and FFmpeg's mature AMF adapter. FFmpeg
n8.1.2 commit `38b88335f99e76ed89ff3c93f877fdefce736c13` was read as a
device/surface-lifetime reference; adopting it here would add libavcodec,
libavutil, their build/license closure and another frame owner. Select the
official header interface and a small first-party owner adapter. No FFmpeg or
AMF sample/helper implementation is copied into the product.

The official AMF v1.5.3 tag resolves to
`57ee0cfb0e1a08d9041f77435653794c1b012be0`. The release's header-only archive
has 88,584 bytes and SHA256
`0f521ad98041f8001147cded4a660127f18b1c27a801a5cd691bda1fa48381be`.
The native lock freezes its exact URL/root, extraction bounds and MIT license.
Only this fixed GitHub release URL may redirect to the exact HTTPS
`release-assets.githubusercontent.com` asset path. Size and SHA256 still bind
every byte; existing libvpx and Opus URL rules remain exact. Headers are supplied
only by hosted Actions. Their original root MIT and codec standards notice is
retained under `packaging/notices`, hash-bound in the lock, and included by both
metadata producers. The root license's separate repository FFmpeg notice does
not mean FFmpeg is imported. AMF appears separately as MIT in both SPDX lists.

`SystemMf` remains the default. `AmdAmf` is an explicit local typed encoder
choice, with a separate diagnostic executable using the same original workload.
No production CLI or wire codec is added. The decoder remains the original
hardware MF decoder on the same supplied device plus the independent software
decoder. A completed diagnostic owner grants no live execution authority.
Production integration must freeze the successful local backend and AMF
runtime version through provider selection and the actual live owner; it must
never probe AMF and later open MF as if it were the same selection.

The native adapter loads only the absolute System32 `amfrt64.dll`, validates
the actual loaded path and queries the installed version. It neither installs
nor distributes a driver/runtime. It initializes the context with the supplied
device, requires AMD vendor identity, compares COM device identity and requires
native DX11 NV12/P010 plus hardware acceleration and exact geometry caps.
Header version and adapter name alone are insufficient evidence.

Configure usage, exact profile/depth/tier/rate/geometry and BT.709 limited SDR
before Init. Validate every property without clamping or type coercion; set and
read it back, then read all retained values again after Init. Published older
headers declare the nominal range as integers FULL=1/STUDIO=2; new headers use
boolean false for limited. Read the real property type/range and support only
known boolean, 1..2 or 0..1 layouts. Unknown/ambiguous ranges fail. Missing
separate matrix/input range is acceptable only when the older explicit 709
profile expresses the same semantics, followed by unchanged original SPS and
independent color verification. Missing SmartAccess/timeout means that feature
is absent; an exposed property must be disabled and read back. Other failures
are fatal. No property compatibility branch is a codec or device fallback.

Four same-device GPU textures retain each accepted input until the runtime's
release observer marks its atomic flag free. The callback touches no owner or
D3D state. Copy completion retains the original 16ms bound; an incomplete copy
retires the owner so a pending texture cannot be reused. There is no CPU map or
pixel conversion in this adapter. Original frame/aggregate/packet bounds and a
16-entry PTS ledger remain. AMF 100ns timestamps are checked against the exact
accepted 90kHz ledger. Submit-full is unaccepted input; output always retires
the original entry before any simultaneous new acceptance. Drain retries a
full queue; EOF requires the ledger empty. Original compressed bytes pass to
the existing SPS/contract parser unchanged.

Cancel/error close explicitly flushes, terminates and checks surface release,
context termination and module unload. Any unknown close permanently retains
the native resources and poisons later AMF opens. Existing outer worker start,
command/join deadlines, sticky retirement and owner identity remain required.

Initial hosted checks add an independent scalar native range/callback/null
device regression. The original 511 and 255 adapter masks are unchanged.
Original four MF commands remain. Four explicit AMF commands retain the same
ten-second deadline, 32 accepted inputs, at least 16 actual outputs before EOS,
all-output accounting, exact uncropped geometry, strict original SPS and both
decoders. Failure remains failure; no byte rewriting, threshold relaxation or
old artifact substitution is authorized. Main10's synthetic BGRA8-to-P010
source does not prove native ten-bit capture, HDR, sustained cadence, input
latency, scanout or W27/AC44 completion.

R02 applies to every build, dependency installation, formatter, automated
check/test and artifact. Local work was source reads/edits/manual review and
Git only. Pending assumptions include actual installed ABI/property support,
strict output color/geometry, pool/drain/cleanup behavior, production freeze
and actual target performance. The driver may expose the same underlying
encoder as MF and still fail the original contract; this ADR makes no promise
that another API repairs its output.
