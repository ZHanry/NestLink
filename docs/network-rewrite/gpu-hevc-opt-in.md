# Explicit GPU HEVC Main8 entry

The user daemon accepts one exact GPU target, for example:

```text
nestlink-daemon --native-gpu-hevc-target 1920x1080@60:8000
```

This selects the existing Windows hardware HEVC Main8 provider. Width and height must be multiples of eight, with width between 16 and 1920 and height between 16 and 1080; the target accepts 1–120 integer FPS and 64–100000 kbps. Each target is exact. A different resolution, FPS, bitrate, profile, chroma or bit depth requires its own verified implementation and authority. This argument conflicts with `--native-media-target` and `--internal-software-media-candidate`. Non-Windows hardware publication returns an unsupported-platform error.

Configuration supplies selection intent. It does not certify hardware, start capture, approve a peer, or enable production media issuance. `PRODUCTION_ISSUANCE_ENABLED` remains false. Current ordinary production servers reject a v3 media request while that rollout gate is closed; the daemon returns the failure and does not create a legacy request as a fallback. This implementation is not an instruction to enable the gate.

After a locally enrolled host signs in, the existing native inbox obtains its own actual Encode probe through the configured provider and publishes the signed, expiring result. The controller's ordinary local-approval request obtains and publishes its independent actual Decode probe before calling the versioned v3 request endpoint. Both probes retain the original bounded native worker, checked close/join, adapter LUID, driver version and full observed profile-tier-level behavior. Merely constructing a target does not add a probe result. Provider replacement, probe failure, expired announcements and an empty intersection stop this flow. GPU opt-in requires local approval and rejects the trusted-device request shortcut.

The server freezes the exact format intersection and both catalog revisions for review. The host's existing request review must submit `ApproveMediaRemote` with the displayed nonce, policy revision and complete `FrozenMediaScope`. Before a hardware probe or approval signature, AppCore checks the actual local host key, pending status, deadline, exact nonce/revision/scope, View permission, and permission/path subsets. GPU approval accepts one v3 Main8 target matching the local configuration and cannot use the H264 software candidate policy. The host then publishes its own actual Encode result, verifies every reviewed format is still available, and re-reads the request and scope after the probe before signing. The SDK and Store retain their independent signature, identity, scope, liveness and permit checks.

After an eventual qualified issuance, the existing native preparation and renewal paths bind the local direction announcement to the signed permit. Capture still requires the original local display approval and View lease. Live output still requires an actual sealed original execution, exact adapter/driver/format identity, format propose/ACK and current execution fence. Probe observations do not substitute for a live output receipt. This change does not transfer the daemon's sealed decoder owner to an independent desktop process; the unproven transfer remains rejected.

Hosted regression tests cover configuration exclusivity, exact routing, changed or absent providers, wrong directions and target formats, stale reviews, permission expansion, and rejection before a hardware probe through the real AppCore/HTTP entry. Synthetic format and announcement objects in predicate tests exercise syntax and policy only. They do not claim physical GPU capture, decode, presentation or performance.

W32/W33 target acceptance remains open: physical GPU 1080p60 cadence, p95 interval, display/DPI and multiple-adapter behavior, device loss and fallback, weak networks and concurrent file workloads, and every applicable M04 advanced-format case require same-source target evidence. HEVC Main8 entry does not establish 4:4:4, ten-bit, HDR or the full high-frame-rate matrix. Existing Luanti 25-second checks and their recorded failure remain unchanged.
