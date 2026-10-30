# Authenticated native PCP deployment policy

`GET /api/v3/discovery/native/pcp` returns a strict `NativePcpPolicy` document to a currently signed-in account. An ordinary member may read the same deployment policy as an administrator. Anonymous, expired and logged-out sessions receive an authentication error. The public health response does not advertise this policy.

```json
{"deployment_id":"ea96f315-6471-4859-a1dc-cb06acb3a021","allowed":false}
```

Both fields are required; unknown fields are rejected. `deployment_id` must be a canonical deployment UUID and must match the SDK's pinned deployment. `allowed` is a Boolean. The policy contains no gateway address, route, mapping, nonce, port or local-network consent.

The persisted server TOML field `allow_pcp_mapping` defaults to `false`, including configuration files written before this endpoint existed. A trusted deployment operator may set `allow_pcp_mapping = true` and restart the server. The startup path copies that persisted value into `AppState`; no request or peer message can enable it and there is no policy mutation API.

Successful policy readback with `allowed = false` remains useful for settings and diagnostics, but cannot authorize a PCP operation. An explicit local PCP gateway requires **both** deployment permission and local gateway consent. The caller must reject an explicit mapping request when policy is false, absent, unauthorized, malformed, from another deployment or unavailable. A 404 response, including an older server's `ProtocolMismatch`, never implies permission. The SDK does not substitute the older STUN endpoint for this policy.

Default native operation without a locally selected PCP gateway does not fetch this endpoint. PCP policy does not widen LAN discovery consent, path grants, business permits, relay access, forwarding permissions or resource budgets. The existing ICE owner must retain responsibility for the original UDP socket, mapping lifetime, renewal and cleanup; this management endpoint alone is not evidence that a router mapping or end-to-end ICE business path succeeded.

The existing authenticated `GET /api/v3/network/discovery` remains unchanged. Its strict `NativeDiscoveryConfig` JSON still has exactly `deployment_id` and `stun_servers`; PCP permission uses this separate additive route so existing clients can continue decoding the STUN document.

The real HTTP/SDK regressions are in `crates/sdk/tests/native_pcp_policy.rs`, with the persisted configuration reload regression in `apps/server/tests/native_pcp_config.rs`. They must be executed on GitHub-hosted Actions under R02; adding these sources does not record a passing result or satisfy full W10 router/NAT acceptance.
