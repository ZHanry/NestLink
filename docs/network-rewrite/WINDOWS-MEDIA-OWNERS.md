# Windows media owner evidence and remaining integration

The real desktop GPU receiver now records the original worker's successful DXGI
submission QPC values. Recording is O(1): one lifetime first/last/count and at
most 512 recent timestamps. A duplicate or reversed native timestamp is retained
as an error count. The normal diagnostic report and the actual joined terminal
receipt carry that metadata; a new receiver owner starts its own window.

Use the downloaded Actions product, retain its independent source and executable
hash, collect the real product's GPU diagnostic report after stopping the session,
and run the Actions-built inspection source as an explicit target evidence step:

```text
python network-rewrite-gpu-cadence.py --diagnostics native-gpu-diagnostics.json --product nestlink-desktop.exe --product-sha256 <independent-Actions-hash> --source-revision <40-character-source> --output gpu-submit-measurement.json
```

The tool requires a live observed terminal from the original recorder, completed
worker join and revocation, no failed or pending terminal write, consistent actual
output counts, configured 1920x1080 and the real positive QPC frequency. It reports
the original 60-second, 58fps and p95 25ms thresholds using integer comparisons.
The p95 covers the explicitly bounded recent window; it cannot qualify the whole
session when that window rotated. The supplied executable hash does not prove
which image ran. DXGI submission is not physical scanout. Accordingly the report
keeps AC54 and physical GPU qualification false; target topology, exact running
image/driver/display identity and actual screen presentation evidence remain
required. Synthetic analyzer fixtures are never GPU evidence.

The exact-source `windows-media-owner.yml` workflow runs ordinary-token receiver
diagnostic/presenter regressions, negative analyzer cases and strict desktop
Clippy. It records source, workflow, dependency lock and tool hashes independently
of its runtime logs. Hardware absence cannot be turned into a physical GPU pass.

The HEVC addition reuses the existing bounded Annex-B/SPS parser and original MF
transform, timestamp ledger, bounded tracked textures and checked teardown. An
immutable local Main8 output contract records every general PTL compatibility
and constraint bit, exact uncropped coded/display geometry, explicit BT709
limited color, target rate and bitrate. Unknown color is rejected. Changed PTL
or rejected parameter sets cannot replace accepted parser history.

`MfHevcTextureEncoder` accepts an original worker's real same-device NV12 texture
without requiring a synthetic source. It checks authority and exact native
resource/adapter/driver identity around work, separates input acceptance from
actual output, validates each returned AU against the original contract and
requires actual hardware-output identity before returning bytes. Returned bytes
and scratch storage are zeroized. The owner retains the existing MF pump and
checked close; its caller must own approval, worker stop/join and signed epochs.

This is an implemented lower codec boundary, not completed W33 production
integration. Current v2 signed `VideoFormat`/NLMF/IPC and live execution receipts
remain H264-only for executable media. The local HEVC contract digest is a
separate domain and cannot be substituted for the current signed wire digest.
Actual high-format provider announcements, signed exact PTL negotiation, live
capture/decode/presenter execution owner binding, Main10/4:4:4 and required target
GPU/driver/fallback evidence remain mandatory work. No probe, wrapper rename or
codec enum switch closes those requirements.
