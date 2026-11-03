# ADR 0075: Explicit AMF encoder with the original HEVC owner contract

Date: 2026-11-03. Status: adapter and explicit provider/live selection implemented;
exact-source hosted owner/strict checks and diagnostic builds passed. Real
target output and complete product qualification remain pending.

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
The existing daemon HEVC opt-in has one explicit encoder selector; no wire codec
is added. The decoder remains the original
hardware MF decoder on the same supplied device plus the independent software
decoder. A completed diagnostic owner grants no live execution authority.
`NativeSessionConfig::with_gpu_hevc_main8_encoder` and the Main10 counterpart
select the local backend explicitly. Existing target constructors select MF.
The provider freezes the successful backend and queried runtime in a local
registry keyed by the complete original authorized ProbeIdentity. The registry
has at most 16 entries, retains each original four-minute expiry, removes only
expired entries and rejects capacity exhaustion instead of evicting a live
entry. A changed runtime does not replace an old probe's selection. The typed
selection enters the daemon's live capture target and actual native encoder;
the encoder rechecks it on every owner observation. Registration and subsequent
route/frame access compare it against the current View-authorized local probe.
The shared provider is retained from the validated original configuration.
Replacing the public provider with one using another backend fails configuration
validation. Decode remains MF and rejects an encoder runtime selection. The
daemon's optional `--native-gpu-hevc-encoder system-mf|amd-amf` selects the same
builder and requires exactly one existing Main8/Main10 target. Unknown values,
standalone/repeated selector use, CPU targets and software policies are rejected
by the real Clap parser and repeated actual configuration checks before a
native probe or policy read. Omitting the selector keeps MF. No wire schema
or default is changed; local display approval, peer/request approval, signed
scope, View lease and the closed production rollout gate remain. This operator
entry does not claim a desktop settings UI or completed target acceptance.

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
pixel conversion in this adapter. The original EVENT query remains retained
after any timeout/query failure. Close reads it once with DONOTFLUSH; S_FALSE
or error returns failed cleanup and retains query, original source texture,
context, input slots and module
in the original sticky quarantine. Releasing COM references alone never counts
as physical copy completion, and no second wait extends the original bound.
The query is created and retained before CopyResource, so query-allocation
failure cannot leave an unobserved submitted copy. The original borrowed source
also has a retained COM reference until this EVENT completes. Original
frame/aggregate/packet bounds and a
16-entry PTS ledger remain. AMF 100ns timestamps are checked against the exact
accepted 90kHz ledger. Submit-full is unaccepted input; output always retires
the original entry before any simultaneous new acceptance. Drain retries a
full queue; EOF requires the ledger empty. Original compressed bytes pass to
the existing SPS/contract parser unchanged.

The Microsoft [EVENT query contract](https://learn.microsoft.com/en-us/windows/win32/api/d3d11/ne-d3d11-d3d11_query)
states that S_OK means GPU command completion. The
[GetData contract](https://learn.microsoft.com/en-us/windows/win32/api/d3d11/nf-d3d11-id3d11devicecontext-getdata)
allows a null output and zero bytes for a status check and defines S_FALSE as
unavailable data. The adapter requires S_OK and retains all resources on any
other status; it does not infer completion from observer release or COM Drop.

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
check/test and artifact. Local work was source reads/edits/manual review, Git,
Actions log reads and downloaded artifact verification only. Exact source
`4a4496b77cf5923a1b39c85c757b7cc6a7f3dc00` passed owner run
[`41488394638`](https://github.com/ZHanry/NestLink/actions/runs/41488394638):
both Windows 2022/2025 owner jobs and the Windows/Linux actual native peer
process jobs succeeded. Both Windows owner jobs retain the original `511` and
`255` MF assertions and pass the AMF boundary, frozen provider identity,
backend/runtime, actual CLI/configuration and strict-check suites. These
hosted tests do not execute the physical AMF workload.

The same source and workflow revision passed diagnostic build/strict run
[`41488400735`](https://github.com/ZHanry/NestLink/actions/runs/41488400735).
Official tools artifact `13164255472` is 1,036,113 bytes with SHA256
`397557734a6830cc2f8eb0719fc054b4742b2b16aadeab5929f706bb9e17eb60`.
All five official owner/peer/tools ZIP sizes and digests, all 234 uncompressed
file hashes, all 171 producer payload records and the original 1,747-byte AMF
notice were independently verified. The owner producer has no payload hash
manifest; its 30 filenames per runner match the reviewed workflow output
inventory, with independent file hashes recorded separately. Full logs,
receipts, exact job identity and inventory are retained in
[`windows-media-owner-tools-4a4496b.json`](../../network-rewrite/evidence/windows-media-owner-tools-4a4496b.json).

Pending assumptions include actual installed ABI/property support, strict
output color/geometry, physical pool/drain/copy/cleanup behavior and target
performance. The original four MF failures remain independent evidence; the
four AMF commands require separate actual target execution. The driver may
expose the same underlying encoder as MF and still fail the original contract;
this ADR makes no promise that another API repairs its output. This evidence
does not complete W27, W33, AC44 or the release gate, and preserves the original
Luanti 25-second failure.
