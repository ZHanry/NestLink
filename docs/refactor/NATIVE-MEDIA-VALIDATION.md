# Native media validation

The Windows H.264 product pipeline and the synthetic HEVC diagnostic are
separate validation boundaries. Successful compilation, opening a transform,
or accepting an input is not a decoded or displayed picture.

## Live H.264 observations

The existing Windows host owner records its actual capture backend, adapter
LUID, live encoder SPS, accepted and encoded PTS, and actual worker join. The
daemon persists bounded scalar samples and terminal history in the private
state directory as `native-gpu-host.json`. One retained blocking writer handles
storage; the control-loop timer never waits for an unfinished write. Shutdown
consumes the actual commit result. A stalled driver remains pending.

The Windows receiver records successful decode, retirement, GPU conversion and
Present submission, actual output PTS and submission QPC. Its private files are
`native-gpu-receiver.json` and `native-gpu-receiver-terminal.json`. One bounded
background worker owns receiver storage reads and writes. UI retirement and
polling perform no filesystem I/O. Pending, failed, visible and durable writes
remain distinct. A queued write may remain incomplete on process exit or a
storage stall.

The existing **Copy redacted diagnostics** action exports at most 64 KiB. Full
request/runtime/stream identifiers stay out of serialized diagnostics. Imported
host observations are explicitly local-host history and do not describe the
remote sender. Historical disk receipts cannot replace a terminal witnessed by
the current live recorder. These records never restore media authority.

These are sparse observations, not an end-to-end per-frame ledger. Present
submission does not establish physical scanout. No zero-copy, throughput,
latency or complete hardware qualification follows from the counters.

## Synthetic HEVC diagnostic

GitHub builds `windows-hevc-gpu-probe.exe` as the separate
`nestlink-hevc-gpu-target-probe` artifact, with exact source/run/attempt and file
hashes. It is not executed as a hardware-success test on the GitHub runner.
Target execution needs an external process watchdog and its actual result must
be preserved, including failure or unavailable components.

The diagnostic uploads known NV12 colors, uses a hardware HEVC Main8 encoder,
then checks same-adapter GPU decode and a separate software decode. It requires
at least 16 live decoded pictures before EOS, drains every accepted input,
checks exact output PTS and color, requires zero pending ledgers, rejects
revoked ownership, and confirms checked cleanup and the real owner join.
Missing components or unsupported restricted syntax fail; they never become a
successful skip.

Its restricted IDR parser is for locally generated diagnostic output. Full
hostile-input HEVC parsing, signed format negotiation, transport, IPC and
production presentation remain required before announcing HEVC product
support. The diagnostic does not capture a screen or qualify M04, 4:4:4,
10-bit, high-frame-rate, physical scanout or performance. Existing product
authorization and report publication gates still apply.
