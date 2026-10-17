# Native channel profile 1

`nestlink.proto` defines the messages; `contract.json` defines length budgets.
Every path requires pinned mutual TLS, a verified permit and both endpoint key
proofs before business delivery. Sensitive operations never use 0-RTT.

Frames have schema byte 1, channel byte and big-endian u32 payload length.
Channels: Control=1, Input=2, Video=3, Audio=4, FileRead=5, FileWrite=6,
ClipboardRead=7, ClipboardWrite=8, VideoFeedback=9. VideoFeedback requires View
permission and fits within 256 bytes. A bound stream checks the expected channel
and byte budget before reading or allocating the body.

## QUIC

The controller opens one bidirectional proof stream regardless of the network
initiator; the host accepts it. Business streams/datagrams observed before
mutual proof terminate setup. Proof and channel negotiation share one
three-second deadline. Cancellation closes the connection. There is no implicit
fallback to the previous single-stream profile.

After proof, peers exchange Control-framed `NativeQuicProfile`. The binding is
SHA-256 of prost-encoded `EndpointProofClaims` with `challenge` cleared. It
includes the original signed permit digest, both keys, actual path and connection
generation; the permit binds deployment, resource, permissions, capability and
policy. Peers must advertise identical schema, binding, generation, reliable
channel list and Audio fragment size. Profile/stream headers fit within 512
bytes. Renewal never changes this original binding or adds permissions.

Each direction opens one unidirectional stream per approved reliable channel,
ordered Input, VideoFeedback, Video, FileRead, FileWrite, ClipboardRead, ClipboardWrite with
unapproved channels omitted. Incoming order may vary. Each starts with a
Control-framed `NativeQuicStream` binding its channel. Duplicates, unapproved,
wrongly bound and extra streams are terminal. The proof stream stays open and
reserved; EOF or extra bytes is terminal. Each business stream has its own
reader/writer. Input and VideoFeedback have higher Quinn scheduling priority and files lower.

Independent streams remove application/per-stream flow-control blocking
between files and input/media. They still share congestion control, connection
flow control, socket and CPU. Current receive windows are 2 MiB per stream and
16 MiB per connection. At most seven business streams per direction plus the
proof stream are used. This is not a latency guarantee. Video stays reliable
and preserves every encoded reference frame.

Approved Audio requires DATAGRAM support with at least 1100 payload bytes.
Each Audio frame of 1..2048 bytes becomes one to three protobuf
`NativeQuicAudioFragment` datagrams. Each carries 960 payload bytes except the
last. Metadata binds the connection, per-direction transport packet sequence
in 1..i64::MAX, zero-based fragment index, exact count and total frame size.
Encoded datagrams fit within 1100 bytes. This transport sequence is separate
from media source sequence and sample clock.

Receivers retain at most eight partial packets (16 KiB total payload). Fragment
geometry must exactly match total size; conflicting duplicates or metadata,
wrong schemas and wrong bindings are terminal. Identical duplicates never renew
first arrival. Reassembly and the incoming queue share the first-arrival time;
packets aged 100 ms cannot be delivered. Expiration, eviction and delivery
advance a replay floor; older packets cannot reappear. Reordered fragments can
complete a packet. Completing a later packet discards older incomplete packets.
No partial packet reaches Opus; losses use the media layer's bounded PLC policy.

The sender drops Audio under queue age, insufficient datagram buffer space or
an observed MTU reduction. Native send/receive buffers are 16/32 times 1100
bytes. These local budgets do not bound network delay. These datagrams carry
endpoint Audio; outer QUIC relay allocation and virtual UDP remain separate
unimplemented requirements.

## TLS/WSS and SDK

Direct TLS and endpoint TLS inside WSS retain one reliable framed stream and
wire head-of-line blocking, reported as `TransportMode::ReliableByteStream`.
QUIC reports `QuicStreamsAndDatagrams`. Both use the same permissions, generation,
lease supervision, platform cleanup and terminal stop.

`NativeConnection::authorize` retains candidate diagnostics, binds the original
endpoint network observer and selected path, performs proof and returns the
runtime. Stop/drop closes owned I/O and clears queues. `wait_stopped` keeps task
ownership across cancellation, shares one cleanup deadline and preserves prior
cleanup failure on repeated waits.

Native video feedback uses its own reliable queue of eight messages. Its
nonblocking insertion reports a full queue without consuming a request sequence;
the receiver's fixed recovery deadline still runs. Video is assigned to an
exclusive decoder consumer, separate from the four-event application FIFO.
Recovery identity, attempts and cached keyframes are defined in
[native-media.md](native-media.md).

Browser RTP/RTCP, A/V synchronization, jitter
adaptation and installed-product performance acceptance remain separate work.
