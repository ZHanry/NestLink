# Internal legacy media format admission

This increment adds bounded discrete format data and strengthens the existing
VP8/H264 native paths. It does not announce a new capability, change signed
claims or IPC messages, or enable production HEVC, 4:4:4, ten-bit or HDR.

`protocol::media_format` validates exact codec/profile/level, chroma, depth,
color, geometry, rational frame rate and bitrate tuples. Intersection preserves
whole tuples; it cannot combine one endpoint's resolution with another entry's
frame rate. Canonical version two includes the actual H264 constraint flags,
coded geometry and crop in luma samples, separately from displayed dimensions.
Canonical format/set digests have separate domains. These data
structures and digests are not hardware evidence or authorization.

The configured media-session sender and both actual daemon producers validate
emitted H264 access units before transport. The bounded SPS/PPS/IDR parser checks
geometry, profile and SDR color; the sender also checks its real configured
target against the observed SPS level. Absent VUI inherits the existing local
BT709 limited conversion contract. It does not prove explicitly signaled VUI,
capture transfer characteristics, achieved frame rate or display output.

CPU and external receiver admission occurs before decoder submission and new
pending credits. Recovery, display reprepare and dynamic resize retire parameter
history. Existing authority, sequence/PTS anti-replay, source/layout/generation,
credit accounting, deadlines and real cleanup checks remain required. External
Prepare and dynamic CPU decoder placeholders do not establish a wire bitrate or
frame-rate contract.

The CPU encoder/decoder wrapper continues to support odd visible dimensions:
321x241 is replicated to a 322x242 H264 input, which may have 336x256 coded
geometry and SPS crop, then decoded BGRA is cropped back to 321x241. The actual
SPS display dimensions and crop are recorded without rewriting them as an odd
4:2:0 SPS surface. Native layout and input coordinates retain visible dimensions.
External/GPU surfaces retain strict even-dimension admission. Regressions use
the actual CPU encoder, lazy decoder and authorized sender/receiver roundtrip;
their execution remains subject to the Windows GitHub result.

Windows target probe receipts retain the requested configuration separately
from the actual encoded configuration, SPS constraints and crop. Probe decoder
setup uses the requested configuration rather than legacy default rate/bitrate.
These receipts are diagnostics and do not establish signed directional support.

Decoded output records encoded source-color information: legacy VP8 uses BT601
limited YUV with unspecified primaries/transfer; legacy H264 uses the existing
BT709 limited conversion. This does not label packed BGRA as limited-range RGB
or claim HDR presentation. The independent browser SDP/RTP pipeline is unchanged.

New regressions cover canonical tuples/digests, level and combination limits,
actual SPS/config correspondence, explicit color conflicts, malformed-AU credit
preservation and retirement of old SPS history across recovery/resize. Positive
parser fixtures prove admission only. Platform decode, presentation and product
transport still require actual GitHub and target execution results; local
verification was limited to source hashes, patch review and rustfmt.

M04 remains incomplete. The next atomic increment must bind actual directional
backend/adapter probe results to device announcements, the approved DB request
snapshot, signed allowed-format scope, renewal/reconnection, SessionBinding,
versioned selection/ack and IPC/data tickets. It must retain every existing
authority and credit identity. The internal exact SPS constraint flags and
coded/display/crop representation must be bound to that approved authority
before its digest can authorize a negotiated production format.
Production HEVC, P010/ten-bit, actual 4:4:4 and high-frame qualified combinations
then need positive resource creation, fallback and hardware/network acceptance.
