# Inspect an explicit local media mode

`nestlink-daemon media-capabilities` runs the original `NativeMediaProvider`
direction probe without starting a user runtime, loading installation keys,
logging in, publishing an announcement or creating remote authority. It uses
the same target validation, native worker, output validation, cancellation,
checked close, join and quarantine rules as the product provider.

Select the mode, exact target and direction explicitly. For example, with an
Actions-built executable on Windows:

```powershell
nestlink-daemon media-capabilities --mode hevc-main8 --target 1920x1080@60:8000 --direction encode --encoder amd-amf
nestlink-daemon media-capabilities --mode hevc-main10 --target 1920x1080@60:8000 --direction decode --encoder system-mf
nestlink-daemon media-capabilities --mode cpu-h264 --target 1920x1080@30:4000 --direction encode
```

The requested encoder is also the source of the decode probe's encoded samples.
The HEVC decoder remains the original MF hardware owner. A missing or rejected
sample producer therefore makes either direction unavailable; this command does
not mistake that dependency failure for independent proof that a decoder cannot
decode a valid external sample. The JSON records those probe dependencies.

The command prints one JSON result. `available: true` is emitted only after the
requested actual direction's complete original workload, output accounting,
color/geometry/format checks, checked close and worker join succeed. The result
contains the historical native probe identity and canonical observed formats.
It excludes the fresh ephemeral label used internally to construct the local
unsigned observation. It is neither a device identity nor a signed capability.
The result explicitly retains `end_to_end_qualified: false`: desktop capture,
continuous frame rate, physical presentation and full remote qualification
remain separate acceptance work.

Any provider/configuration/native failure produces `available: false`, no
observation, the original error kind and text, and a nonzero exit status.
Ctrl+C cancels the original provider and waits for its existing cancellation
result; retained or quarantined native owners keep their original lifecycle.
No timeout, copy deadline or parser assertion is relaxed.

All current modes use 4:2:0 SDR. Main10 explicitly selects P010/10-bit SDR;
it does not claim HDR capture, PQ/HLG, BT2020 or an HDR presenter. Requests with
`--chroma 444`, `--dynamic-range hdr10` or `--dynamic-range hlg` are explicitly
rejected before creating a native owner, because those exact product owners
are absent. These are supported error reports, not implementations of 4:4:4 or
HDR. They remain required W33 work.

Failure never retries another encoder, pixel depth, geometry, frame rate or
software codec. To request another mode, the user runs a new explicit command.
For actual runtime selection, the existing daemon flags remain
`--native-media-target`, `--native-gpu-hevc-target`,
`--native-gpu-hevc-main10-target` and `--native-gpu-hevc-encoder` with their
existing conflicts and authorization gates.

The CLI tests cover missing and malformed targets, allocation/rate ceilings,
unknown mode values, incompatible CPU/HEVC encoder selection, explicit
unsupported color requests, and the distinction between configuration and an
observed capability. All compilation, tests, formatting and automated checks
must run on GitHub-hosted Actions. Local work is source editing and manual
review only; this document does not assert those checks or any native probe
have passed for the new source.
