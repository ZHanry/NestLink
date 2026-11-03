# Original Windows media direction diagnostic tools

Build with `windows-media-target-tools.yml` on GitHub-hosted Windows. Verify the
official artifact ZIP digest and every file in `receipt.json` before running
the downloaded executable under an ordinary interactive Windows account. No
local compilation, dependency installation or development runtime is required.
Do not run a failed or incomplete build artifact.

The verified source `4a4496b77cf5923a1b39c85c757b7cc6a7f3dc00` has successful
hosted build/strict run
[`41488400735`](https://github.com/ZHanry/NestLink/actions/runs/41488400735),
attempt 1. Its official artifact `13164255472` is 1,036,113 bytes with SHA256
`397557734a6830cc2f8eb0719fc054b4742b2b16aadeab5929f706bb9e17eb60`.
The official ZIP digest and all 167 producer payload sizes/hashes were checked,
including the four executables and original AMF notice. This record establishes
build provenance; it records no target execution. See the complete owner/tools
receipts, file inventory and retained failures in
[`windows-media-owner-tools-4a4496b.json`](evidence/windows-media-owner-tools-4a4496b.json).

These tools call the existing production direction-probe implementations.
They use bounded synthetic input and original deadlines, exact output checks
and checked native owner cleanup. Each command is independent and its failure
must be retained. Successful finite output is not a whole-product qualification.
No tool reads the desktop, installs a service, changes a driver or changes media
issuance. The HEVC profile is explicitly Main8 or Main10 SDR. Main10's synthetic
BGRA8-to-P010 conversion does not establish native ten-bit capture or HDR.

Examples, executed from the verified extracted artifact folder:

```powershell
.\windows-cpu-direction-probe.exe encode 1920 1080 60 8000
.\windows-cpu-direction-probe.exe decode 1920 1080 60 8000
.\windows-controller-direction-probe.exe 1920 1080 60 8000 gpu
.\windows-hevc-direction-probe.exe encode main8 1920 1080 60 8000
.\windows-hevc-direction-probe.exe decode main8 1920 1080 60 8000
.\windows-hevc-direction-probe.exe encode main10 1920 1080 60 8000
.\windows-hevc-direction-probe.exe decode main10 1920 1080 60 8000
```

The separate `windows-amf-hevc-direction-probe.exe` explicitly selects the
installed AMD AMF hardware encoder with the same supplied D3D11 device. Its
decoder remains the original hardware MF decoder plus independent software
decoder. Run the following additional commands independently; preserve all
four original MF results above as separate evidence:

```powershell
.\windows-amf-hevc-direction-probe.exe encode main8 1920 1080 60 8000
.\windows-amf-hevc-direction-probe.exe decode main8 1920 1080 60 8000
.\windows-amf-hevc-direction-probe.exe encode main10 1920 1080 60 8000
.\windows-amf-hevc-direction-probe.exe decode main10 1920 1080 60 8000
```

The official AMF 1.5.3 headers are built into the Actions artifact. The runtime
comes only from the existing driver at the absolute Windows System32 path;
the tool installs no SDK or driver and distributes no AMD runtime. Header
version does not prove installed runtime support. Each run records the queried
runtime version and actual property types/readback before requiring the
unchanged original SPS, BT.709 limited color, exact uncropped geometry,
32 accepted inputs, at least 16 outputs before EOS, exact two-decoder accounting
and original ten-second budget. The tool never rewrites a parameter set or
retries another backend, device, depth or source after a failure. A successful
finite probe does not enable the product's live encoder by itself.

The existing production `NativeSessionConfig` also has explicit local
`with_gpu_hevc_main8_encoder(target, HevcEncoderBackend::AmdAmf)` and Main10
builders. They run the same original provider probe before publication, then
bind the actual live target and owner to that probe's exact implementation and
runtime. Existing target builders keep SystemMf. The existing daemon HEVC
target flags also accept an explicit `--native-gpu-hevc-encoder amd-amf` selector;
see [operator configuration and restrictions](gpu-hevc-opt-in.md). Neither
entry establishes a target pass or bypasses the original approval/rollout gates.

Record the complete arguments, exit status, stdout/stderr, wall time, actual
Windows build and GPU/driver inventory, tool receipt, exact source and all
executable digests. An unsupported hardware/parser/runtime result is a failure
of that exact workload, never a skipped pass. Independent CPU results cannot
replace a failed GPU workload. Do not infer another adapter, target, direction
or format from one successful result.

These tools do not establish 58fps sustained desktop presentation, input delay,
weak-network recovery, concurrent files, capture/transport/presenter continuity,
4:4:4, HDR or full fallback behavior. They are diagnostic tools, separate from
the original candidate build, required workflows and release evidence gates.
