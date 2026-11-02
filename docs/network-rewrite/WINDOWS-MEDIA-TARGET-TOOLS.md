# Original Windows media direction diagnostic tools

Build with `windows-media-target-tools.yml` on GitHub-hosted Windows. Verify the
official artifact ZIP digest and every file in `receipt.json` before running
the downloaded executable under an ordinary interactive Windows account. No
local compilation, dependency installation or development runtime is required.
Do not run a failed or incomplete build artifact.

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
