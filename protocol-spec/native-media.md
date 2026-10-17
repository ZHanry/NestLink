# Native media v1

`nestlink.proto` is the only definition of `NativeVideo`, `NativeVideoFeedback`
and `NativeAudio`.
`contract.json` defines their byte and geometry budgets. These envelopes run
inside already authenticated, permission-gated native Video/Audio channels;
they do not define browser RTP/WebRTC media or grant capture/playback permission.

Both envelopes use schema 1. Connection generation and sequence are in
`1..=i64::MAX`; PTS is in `0..=i64::MAX`. Source is an opaque `u32` identifier
(zero is valid), which must be present in the session's approved source set.
The receiver verifies connection identity before changing codec history.
There are at most 64 approved sources, with separate codec state per source.
Sequence starts at 1 and increases without wrap. Timestamps strictly increase
within each source stream. Reconnection creates new state with a new approved
connection generation; old packets cannot reset the current state.

Video has an additional nonzero layout epoch. Layout and dimensions are frozen
for the approved stream. A change requires a newly approved layout and fresh
encoder/decoder state, beginning with a keyframe. Each payload is one complete,
visible VP8 frame in 8-bit I420, with no hidden altref frame or scaling.
The keyframe flag and dimensions must agree with the VP8 uncompressed header.
The complete protobuf envelope, including all metadata, fits within 8 MiB.
Dimensions are at most 8192 per axis and decoded packed BGRA fits within 64 MiB.
PTS uses a 90 kHz clock; the codec's internal fixed frame clock is not exposed.

The initial native reliable transport keeps at most one queued encoded video
packet per direction, in addition to the frame currently being transferred.
When the queue is full the producer waits. It never replaces or expires a
reference frame. The source may replace raw frames before encoding. Receivers
must decode every accepted reference packet in sequence, even when presentation
of an old decoded image is skipped. A sequence gap or decode error requires a
fresh decoder and a keyframe before presentation resumes. Datagram packet loss,
browser PLI and browser negotiation are separate protocols, not implied here.
Round-robin scheduling keeps other outgoing channels progressing once the
current frame finishes. A reliable TCP/WSS byte stream still has wire and
incoming-consumer head-of-line blocking.

## Native video recovery

The View-authorized VideoFeedback channel carries at most 256 bytes. Each
request binds schema, connection, layout and approved source, a separate
per-source request sequence starting at 1 and the latest consumed video
sequence (0 before any frame). Reasons are KeyframeMissing, ReferenceGap and
DecoderFailure. Unknown reasons and wrong identity, layout, geometry, sequence
or PTS remain terminal; recovery never changes consent or revives a stopped lease.

A missing initial keyframe, a forward sequence gap or an entropy decode failure
discards the decoder and unpresented image for that source. Deltas are discarded
while awaiting a new keyframe; their validated sequence/PTS still advance so
they cannot replay. A new decoder processes the next keyframe. Each recovery
has one two-second deadline, never extended by retries or more deltas. At most
three recovery starts/failed entropy attempts fit in a rolling 30-second window.
Budget exhaustion stops the session and clears output. An independent watchdog
supervises published recovery deadlines even if the codec or file dispatcher
stalls; a late decode cannot clear an expired deadline. Codec cleanup retains
its separate bounded join and explicit timeout result.

The receiver sends feedback at most once per source per 250 ms; a full outgoing
queue defers insertion without consuming the request sequence. The sender
requires consecutive requests, nondecreasing acknowledgments no greater than
its prepared video sequence, and the same approved binding. An exact duplicate
of the most recent request is idempotent; conflicting or older requests fail.
Requests coalesce; feedback-forced keyframes are spaced by at least 250 ms per
source, including the initial keyframe. Feedback is consumed even while video
waits for queue capacity; already encoded references are kept in order.

The sender retains latest approved pixels per source, within the existing
128 MiB selected-source bound (excluding codec buffers and current work). It
checks current platform, lease and layout facts before re-encoding static pixels.
Such a recovery keyframe sets `repeated_source=true`; it is not a new capture.
Its new PTS identifies the recovery encoding time. Ordinary fresh frames set
false; repeated-source delta frames are invalid. A busy display cannot starve
a due static display recovery; only unencoded raw pixels may be deferred.

Development tests omit an application video frame to exercise the automatic
sender/receiver feedback loop. This does not simulate reliable QUIC packet loss,
which the transport retransmits. Synthetic static-source feedback is separately
tested over real loopback QUIC and framed in-memory transport. Browser RTCP,
network congestion control and product latency acceptance remain separate work.

## Audio

Audio uses 48 kHz PCM, exactly 960 sample frames per channel (20 ms), one or two
channels, and one complete Opus packet of 1..1275 bytes. The entire protobuf
envelope fits within 2048 bytes. PTS uses the 48 kHz sample clock. Its TOC channel
identity must match the envelope. The codec also parses the complete packet,
checks duration/channel identity and rejects zero-length coded frames before
decoding. Audio queue loss is permitted; sequence/PTS gaps must be handled by
the session's explicit, bounded PLC policy. An empty or malformed network
payload never requests PLC. FEC, DTX and channel resampling are absent from this
profile.

The native session now assigns incoming Audio to an exclusive local consumer
and dedicated codec thread. PTS is aligned to 960 frames; received sequence and
PTS increase, with the sequence delta no larger than elapsed 20 ms intervals.
Initial queue loss may omit early sequence numbers. Complete Opus framing is
parsed before gap handling. Gaps of one to three intervals use explicit PLC;
longer gaps reset once and decode the current packet without synthesizing a
backlog. A bounded batch is published only after decode succeeds. This is
local dispatch and PCM delivery, not RTP, network jitter correction, A/V sync,
or evidence of installed OS audio capture/playback.

Rust `decode_validated` checks the received byte budget before protobuf decode
and then validates framing. `encode_validated` validates before serialization.
Unknown optional protobuf fields are ignored, but their received bytes still
count against the transport/envelope budget. Stateless validation does not
prove entropy validity, sequence progression, source consent or current epoch;
the codec and authorized media worker perform those checks in that order.
