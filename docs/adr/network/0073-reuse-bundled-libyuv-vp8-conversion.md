# 0073 — Reuse the pinned bundled libyuv conversion for VP8 output

Date: 2026-11-02. Status: implemented; original both-OS focused resident matrix
passed on exact source4a; broader qualification remains separate.
Scope: the existing software VP8 decode output, on the three existing native
codec supplier targets. This does not change the negotiated codec or color space.

Original source915 resident run 41466485538 passed all four Linux cases and two
of four Windows cases. Both original QUIC rebuild cases passed. In the Windows
TLS rebuilt-pixel failure the original sessions remained Connected/Running and
the original cumulative budget still had time left. The controller dropped
actual decoded frames at its unchanged queue-admission late check. The first
observed ingress-to-output interval was 124676 us; later intervals were about
79–83 ms. Those intervals include locks, first decoder initialization, actual
decode, conversion and wipes. They do not isolate libvpx decode CPU time.

The previous path allocated packed I420, copied every libvpx image row into it,
allocated BGRA, ran a scalar Rust per-pixel conversion, then wiped the I420
allocation. The original hosted Rust test profile is unoptimized. Native
libvpx is Release and already requests a maximum of two decoder threads.
Actual VP8 row parallelism also depends on token partitions. No claim of two
active workers or of a specific conversion speedup follows from those facts.

The selected mature converter is the libyuv snapshot already embedded in
the unchanged libvpx 1.16.0 archive, commit
`1024874c5919305883187e2953de8fcb4c3d7fa6`, SHA256
`274c00c0b21f03a9152e324b1989f73b74268aa8545b39ef5faccc50fdb56393`.
Its original `third_party/libyuv/README.libvpx` identifies upstream commit
`a37e7bfece9e0676ae90a1700b0ec85b0f4f22a1`; its version header is 1711.
The README records disabled AVX512VBMI RGB24 code, rearranged directories and
removed umbrella/compare headers. This is an attributed upstream implementation,
not newly authored or clean-room conversion code.

Existing packed-BGRA scaling through fast_image_resize does not convert I420.
The existing Windows NV12/MF conversion has a different BT.709 contract and
would not serve the cross-platform VP8 BT.601 boundary. Merely enabling the
libvpx libyuv option builds example/tool helpers; the selected supplier disables
those, and the example source list does not provide this conversion closure.

This embedded snapshot has no CMakeLists.txt to reuse. The supplier therefore
generates one fixed static `yuv` target outside the verified source tree, using
its existing CMake/Ninja and preflighted native C++ compiler. The 17 unchanged
source files are explicitly locked: convert_argb, cpu_id, planar_functions,
the seven row implementations and seven scale-row implementations. Planar
helpers require scale-row symbols. Compiler/profile, actual compilation units,
Release optimization and Windows dynamic CRT are checked and recorded. Linux
uses PIC and the native GNU target; upstream CPU dispatch selects SIMD rows.
No global AVX flags, new runtime thread or general build framework is added.

The C bridge retains every original packet/header/keyframe/hidden-frame,
corruption, image-format/bit-depth, geometry, raw/packet-budget and single-frame
check. It validates non-null planes and sufficient positive strides, then calls
`I420ToARGB` synchronously on the original libvpx planes before another codec
call. No plane pointer escapes. The exact `4 * width * height` Rust BGRA output
has a Zeroizing owner on failure and moves to the existing wiping DecodedVideo
owner on success. The encoder and its conversion are unchanged.

I420ToARGB selects libyuv's `kYuvI601Constants`: limited-range BT.601 with actual
B,G,R,255 bytes. Its integer approximation is not bit-exact with the retired
Rust formula: Y=100/U=200/V=128 yields [242,70,98,255], while the old formula
gave [243,70,98,255]. Original black/white, odd-chroma, PSNR, resident pixel,
file, stop/rebuild and timing assertions remain unchanged. New actual converter
vectors and odd/padded-stride/unaligned-output guards supplement them. The
original sanitizer keeps its real frames, all mutations and prefix truncations,
using the required BGRA output length. Upstream native archives remain outside
that first-party ASan/UBSan instrumentation boundary.

Only the first three decode calls per context in debug builds emit fixed Rust
geometry/allocation/whole-FFI/total stage durations and status. Logs contain no
packet or pixel bytes. Whole FFI includes lazy libvpx decoder setup and mature
conversion; split C timing is deferred unless actual evidence requires it.
The validated-ingress 60 ms immutable anchor, 40 ms late threshold, all PTS and
capture clocks, deadlines, queue admission and cumulative leases are unchanged.

The native lock/receipt declares a bundled component within the original
archive, checks all installed bytes and parent source digests before/after
building, and includes the exact BSD LICENSE and original README. Both metadata
producers emit a distinct libyuv SPDX package with a parent CONTAINS relation,
explicit source subdirectory/commit/archive hash and no invented independent
archive checksum or download. Both original notice files enter license bundles.

No local build, formatting, lint, tests, Python execution or packaging was run.
The qualification requires hosted native builds, strict lint, unchanged original
color/quality tests, boundary sanitizer and the full original resident matrix.
Follow-ups below record the completed focused scope. Broader checks, formal
device acceptance, public-NAT coverage and release readiness remain separate.

Reviewed original sources:

- <https://github.com/webmproject/libvpx/tree/1024874c5919305883187e2953de8fcb4c3d7fa6/third_party/libyuv>
- <https://github.com/webmproject/libvpx/blob/1024874c5919305883187e2953de8fcb4c3d7fa6/third_party/libyuv/source/convert_argb.cc>
- <https://github.com/webmproject/libvpx/blob/1024874c5919305883187e2953de8fcb4c3d7fa6/third_party/libyuv/source/row_common.cc>
- <https://github.com/webmproject/libvpx/blob/1024874c5919305883187e2953de8fcb4c3d7fa6/third_party/libyuv/README.libvpx>
- <https://github.com/webmproject/libvpx/blob/1024874c5919305883187e2953de8fcb4c3d7fa6/examples.mk>

Follow-up actual execution: source `e2026fb523db32c45a14ec66f01a4a22a964d38e`,
run41478056075, built and verified the17-file native x64 closure on both OS,
including Windows dynamic CRT. Original Rust consumers linked and ran; all
focused strict clippy commands passed. Windows original resident passed4/4,
including QUIC/TLS actual pixels, two completed files, original rebuild and
EOF/IPC Exit. Initial/rebuilt Windows Rust decode totals were28–33ms, with
whole FFI22–25ms; later observed FFI was1.6–3.1ms. Original Linux passed3/4,
including complete TLS; its initial/rebuilt first decode totals were5–6ms,
FFI about1ms. These observations keep the original unoptimized Rust test
profile, validated-ingress60ms anchor and40ms late threshold unchanged and
include lazy native decoder setup in first FFI. No finer C timing is warranted
by this result. Linux's remaining case failed before native media, at the
original protected-login Secret Service gate. Full independent hashes and
original failure are in
[native-offline-resident-e2026fb.json](../../network-rewrite/evidence/native-offline-resident-e2026fb.json).
Broader VP8 quality/sanitizer/notice and ARM64 checks remain separate evidence;
both-OS original resident completion still requires the newer Linux setup repair
and a complete exact-source run. No local project execution was performed.

Follow-up source `4a4496b77cf5923a1b39c85c757b7cc6a7f3dc00`, run41488486927,
now passes all four original resident cases on each OS: Linux245.79s and
Windows289.20s. Each ran management8, pending EOF/Stop/logout/identity,
QUIC/TLS actual initial/rebuilt pixels, both262144-byte files per carrier
and original EOF/IPC Exit. Both native suppliers built/verified the fixed17
unmodified libyuv units and all original focused strict commands passed.
The separate Linux real Secret Service regression and its added strict command
also passed. Source4ec's unrelated DNS/socket failures remain preserved;
no socket algorithm or original frame/authority/deadline assertion was changed.

Linux full-case first decode totals were4.8–5.6ms with whole FFI0.68–0.90ms;
Windows first totals were37–44ms with whole FFI27–34ms. Later observed full-case
FFI was0.46–0.72ms on Linux and1.32–1.35ms on Windows. These original debug
context observations include lazy native setup and do not isolate pure decode
or establish throughput. The original60ms anchor and40ms threshold remain.
All46 extracted artifact files and two complete job logs were independently
hashed; all38 producer entries match, with clean identical source facts.
See [source4a evidence](../../network-rewrite/evidence/native-offline-resident-4a4496b.json).
Full Rust quality/sanitizer/notice, ARM64 and physical device results remain
separate. This VP8 resident run does not establish actual AMF hardware acceptance.

Full-workspace follow-up: source `745c05a8016c1d33c193706171714fa8b72c30cf`,
run41479911345, actually passed the original Linux media-codec suite 45/45 in
0.63s, including all eight VP8 cases. These retain the original BT.601/color,
odd geometry/PSNR, key/delta/reference, live bitrate, PTS and corrupt/truncated
frame assertions and the added mature-conversion vectors. The independent
Rust native-prefix integration passed 3/3 in 0.01s. Both OS built and verified
the native supplier and passed workspace type-checking. The Opus native-bridge
ASan/UBSan unit test passed; it is distinct from the original separate VP8
boundary sanitizer, which was skipped after the Linux workspace resident
failure. Python supplier/notice regressions and cargo xtask check were likewise
skipped, so sanitizer and complete notice qualification remain pending.
Windows workspace did not reach media-codec or Rust prefix before its own
original 60-minute job timeout. The early serial resident passed 4/4 on both
OS, but Linux's later parallel workspace resident failed 1/4, and Windows's
later workspace resident has no final summary. None of these facts replaces
the original failed/incomplete workflow with a passing release gate. See
[source745 evidence](../../network-rewrite/evidence/full-rust-core-745c05a.json)
for both independently hashed complete logs, metadata and independently
downloaded artifact ZIPs matching GitHub's official digests. Original timing,
authority and cleanup assertions remain unchanged; newer platform ownership
changes require newer exact-source hosted execution.
