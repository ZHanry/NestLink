# Managed TURN protocol fuzz run

`crates/turn-service/examples/turn_protocol_fuzz.rs` starts the managed Rust TURN service on loopback-only ephemeral listener ports and mutates STUN, ChannelData, and stream framing over UDP, TCP, and TLS. TLS uses an ephemeral self-signed certificate created for the local run. The harness installs no grants, so it also checks that unauthenticated traffic cannot leave a live allocation behind.

Run a short smoke check first:

```sh
cargo run --offline -p nestlink-turn-service --example turn_protocol_fuzz -- --duration-seconds 60
```

The harness caps a single run at 90 minutes. Use short durations for smoke checks and keep only completed-run output and its source receipt:

```sh
python3 scripts/refactor-run-check.py \
  --log artifacts/core-verification/native-turn-protocol-fuzz-linux.log \
  --source-prefix crates/turn-service \
  --source-prefix crates/traversal \
  -- cargo run --release --offline -p nestlink-turn-service --example turn_protocol_fuzz
```

The log reports progress once per minute and ends with `TURN_FUZZ_REPORT`. A completed capped development run requires the requested duration, nonzero UDP/TCP/TLS session counts, zero active allocations, exit code 0, unchanged source inputs, and no panic or task-failure output. An interrupted run does not count as a completed result.

This harness exercises the local managed TURN implementation and its wire parser. It does not test public DNS, firewall/NAT traversal, external certificates, enterprise TURN/TLS on port 443, or fixed-release binaries; those remain separate G2/A19 acceptance work.

The current-source debug and release smoke runs passed on 2026-10-17. The original 24-hour release run was stopped after 540 seconds when the user set the single-test limit to 90 minutes; that interrupted attempt remains recorded separately. The subsequent capped release run completed all 5400 seconds with 483280 UDP datagrams, 21482 TCP sessions, 5390 TLS sessions, no send/connect/handshake errors, and no active allocations at exit. Its 151 selected source inputs were unchanged and owned scratch was removed. The retained log and receipt are linked from [the current verification index](current-verification-2026-10-17.json). This completed development run does not establish public-network or fixed-release acceptance.
