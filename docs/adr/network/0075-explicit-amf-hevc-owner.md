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

The original eight direction commands on source `4a4496b` all exited 1; see
[`windows-hevc-target-4a4496b.json`](../../network-rewrite/evidence/windows-hevc-target-4a4496b.json).
The actual AMD runtime was 1.4.22, while the supplied interface headers are
1.5.3. Main10 rejected its actual non-native P010 capability. Main8 successfully
set/read all first sixteen required properties, then returned result 4 at
`property-info` before encoder Init. The old diagnostic omitted the name;
source order locates the next lookup at `HevcInMatrixCoeff`, without proving
that absence caused this runtime error. The original logs and failure remain.

The pinned official
[`Result.h`](https://github.com/GPUOpen-LibrariesAndSDKs/AMF/blob/57ee0cfb0e1a08d9041f77435653794c1b012be0/amf/public/include/core/Result.h)
defines 4 as `AMF_INVALID_ARG`. The official API reference and
[`public property storage implementation`](https://github.com/GPUOpen-LibrariesAndSDKs/AMF/blob/57ee0cfb0e1a08d9041f77435653794c1b012be0/amf/public/common/PropertyStorageExImpl.h)
specify `AMF_NOT_FOUND` for an absent named descriptor.
The older official
[`VideoEncoderHEVC.h` at 1.4.23](https://github.com/GPUOpen-LibrariesAndSDKs/AMF/blob/55e4d844b77885cc3f7832bdb3cf41a1f16950ef/amf/public/include/components/VideoEncoderHEVC.h)
already exposes explicit input/output 709 profiles and required nominal range,
but lacks the separate matrix/input-range and SmartAccess properties. This
establishes the API compatibility boundary, not the installed driver's output.

The corrected descriptor helper records the exact name/result on every lookup.
Only the existing five explicitly optional extension properties may be absent:
input/output matrix, input full-range, disabled SmartAccess and zero query
timeout. Neither `AMF_INVALID_ARG` nor `AMF_NOT_FOUND` alone authorizes omission.
With a null returned descriptor, the helper enumerates the entire nonempty
registered descriptor inventory, capped at 512 entries with bounded valid
unique names, requires the requested name absent, checks the count unchanged
and requires `HasProperty` false. Any indexed-query failure, malformed or
contradictory descriptor, unknown error or required property still fails.
Present properties still pass unchanged validation/set/readback and repeated
post-Init readback. Output limited range remains required. No original SPS,
dual-decoder accounting, color/geometry or workload gate is changed. A separate
nineteen-case native regression exercises these actual helper decisions without
a runtime/device; the original `127`, `511` and `255` assertions remain. This
repair requires new exact-source hosted verification and fresh target execution;
the earlier successful `4a4496b` build does not verify the repair.

The subsequent eight actual commands on source `f0c65e1` also exited 1, retained
separately in
[`windows-hevc-target-f0c65e1.json`](../../network-rewrite/evidence/windows-hevc-target-f0c65e1.json).
AMF Main8 reached a successful `HevcFrameRate` descriptor query, then the new
descriptor-name consistency guard rejected it before validation/set/readback.
Its actual descriptor name was not logged, so neither an alias nor an absent
property has been established. Both reviewed official header versions use
the exact `HevcFrameRate` spelling. The next diagnostic change records each
bounded actual descriptor name/type and index and, on a name mismatch, the
bounded descriptor inventory as diagnostic data only. It preserves the failure
and all original conditions; no unknown alias is accepted and no quality or
output gate changes. The optional-absence proof still requires the complete
consistent inventory described above. This diagnostic addition requires its
own exact-source build and target result.

Source `f0c65e1` completed both Windows owner jobs and both native peer process
jobs in run `41561895385`, including the original AMF regression and separate
nineteen-case optional-absence regression; its tools build/strict run
`41561899380` also passed. Exact run/job receipts, all five official ZIP
digests, 234 file hashes and 171 producer payload records are in
[`windows-media-owner-tools-f0c65e1.json`](../../network-rewrite/evidence/windows-media-owner-tools-f0c65e1.json).
The diagnostic-only source `46bc44d` passed tools build/strict run
`41563437605`; its complete 167-payload verification is separate in
[`windows-media-tools-46bc44d.json`](../../network-rewrite/evidence/windows-media-tools-46bc44d.json).

All eight actual `46bc44d` directions still exited 1, preserved in
[`windows-hevc-target-46bc44d.json`](../../network-rewrite/evidence/windows-hevc-target-46bc44d.json).
The Main8 diagnostic now records the exact returned rate descriptor
`TL0.QL0.HevcFrameRate`, type `AMF_VARIANT_RATE`, at index 71 of the complete
126-entry inventory. The pinned official
[`HEVC API SVC table 11`](https://github.com/GPUOpen-LibrariesAndSDKs/AMF/blob/57ee0cfb0e1a08d9041f77435653794c1b012be0/amf/doc/AMF_Video_Encode_HEVC_API.md)
documents `TL<temporal>.QL<quality>.<parameter>`, specifically including
`HevcFrameRate`, `HevcTargetBitrate` and `HevcRateControlSkipFrameEnable`, and
requires quality layer `QL0`. This is a documented rate-control namespace,
not an unknown spelling that can be accepted by removing arbitrary prefixes.

The production correction permits only those three complete `TL0.QL0` aliases
for the existing three controls, with exact rate/int64/bool descriptor types.
The original named lookup, canonical named lookup, repeated original lookup
and one indexed entry must return the same descriptor pointer. The entire
nonempty, bounded, uniquely named inventory must remain stable, contain that
canonical descriptor exactly once and have no conflicting flat descriptor;
both names must report `HasProperty`. Unknown controls, prefixes, temporal
layers and quality layers fail. Validation/set/readback still use the original
flat name; an additional typed canonical value read must agree exactly. Both
names are read again after Init against the same stored value. Canonical names
retained by the owner are fixed static strings, not borrowed driver memory.
No second encoder, source, depth, format, parameter set, deadline or threshold
is selected. A new independent native regression checks the three exact
aliases, identity contradictions, unknown namespaces, malformed inventories
and typed readback failures. Original `127`, `511`, `255` and `524287` assertions
remain unchanged. This correction still needs new exact-source hosted owner,
strict/build and actual target evidence. Earlier failures and the original
Luanti 25-second failure remain failed.

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
