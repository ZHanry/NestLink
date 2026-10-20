# Browser WebRTC signaling

The browser controller is the initial offerer and is the only endpoint that requests ICE restart in the current browser contract. SDP is carried in signed `SignalPayload` records. In 0.7, peers advertising `webrtc-trickle-v1` on direct-only permits publish bounded cumulative candidate snapshots while gathering continues. TURN and older clients retain complete gathering. Every description binds its DTLS SHA-256 fingerprint to the signed payload.

In 0.7.0 RC, access approval first makes the request discoverable through the host-only browser inbox. The host prepares capture and obtains explicit local screen consent while `lease_sequence` is zero. A device signature using `PREPARE_BROWSER_HOST` binds readiness to the approved request nonce, deployment, security epoch, account and connection generation. Readiness grants no media or signaling rights. The browser waits for readiness before requesting a permit. Signed readiness and browser capabilities jointly enable a 30-second `setup-budget-v1` permit; older peers retain the 15-second profile. A setup permit permits negotiation and proof only: media, input and business access remain forbidden until both endpoints prove possession and submit a dual-signed renewal for the normal 15-second running lease. If the request, login, device or approval deadline cannot cover the full setup window, issuance fails with `SETUP_BUDGET_EXHAUSTED` without consuming a lease sequence. The host checks the signed permit against the original permissions, paths, policy revision and device identities, and still starts capture only after mutual endpoint proof. Revocation, original management-login expiry and policy changes invalidate preparation as well as permits.

`SignalPayload.network_generation` is monotonic for its sender and is not shared between endpoints. A controller offer increments its own network generation after a network change. A host answer keeps the host's own network generation and sets `WebRtcDescription.in_reply_to_sequence` to the exact `SignalPayload.sequence` of the offer it answers. Offers omit this field. Answers without a positive offer sequence are invalid.

The browser applies an answer only when its `in_reply_to_sequence` matches its latest published offer sequence. A lower reference is a delayed answer and is ignored; a higher reference is a protocol error. The SDK independently enforces monotonic signaling sequence, lease sequence, sender identity, and sender-local network generation. A restart that fails after changing local ICE state closes the old peer instead of presenting it as an active session.

The management server accepts a host answer only when the referenced sequence is the latest stored controller offer for that session. This check is transactional with storing the answer, so an answer racing a newer offer is rejected. The browser controller and native host answerer both use the verified permit and signed signaling APIs. The browser has an account-scoped persistent installation identity and obtains permits and TURN credentials from the trusted management SDK; it does not trust ICE servers or TURN credentials embedded in peer SDP. Stopping a connection revokes its request while preserving the enrolled browser identity.

The browser controller receives video/audio and can request input, files and clipboard through separate explicit permissions and local data consent. Availability depends on the host platform and its capture provider. Managed TURN allocations remain peerless until both endpoints sign the current candidate binding. NodeControl gives that binding an independent monotonic deadline, clears its allowlist when a signed snapshot omits the binding, and accepts a replacement only when its signed issue time advances. Expiry denies peer operations immediately and the TURN service closes the active allocation on its reaper cadence without changing the grant's separate lease deadline.

The host approves a bounded display catalog locally before capture activation; the controller can select only approved sources. Automated loopback WebRTC/VP8 checks use owned synthetic capture and do not establish installed-platform capture/input quality, cross-network TURN reachability or 90-minute stability. Those remain separate RC acceptance cases.

## Cumulative Trickle snapshots

The immutable SDP and `description_sequence` identify one description. Each
signed update carries all candidates so far and an irreversible end marker.
The server retains the latest snapshot per endpoint, allowing missed polls to
recover without an unbounded message queue. Validation binds candidate MID,
m-line, username fragment and ICE generation to the description, enforces
count/length bounds, deduplication and permitted paths, and rejects appends
after completion. Restart creates a new description; old generations cannot
be reused. Publish retries retain exactly the same signed bytes and deadline.

## Media and diagnostics

Browser video remains VP8 with Opus audio. Windows native H.264 negotiation
is a separate signed capability and does not imply browser H.264 support.
The receiver samples bounded `getStats` counters once per second for interval
FPS, bitrate, loss, RTT, decode cost and jitter-buffer cost. Missing/reset
counters remain unknown. Exports contain a request hash and metric allowlist,
never SDP, credentials or candidate addresses. RTT and decoder/buffer timings
are different measurements and are not an end-to-end input latency estimate.
