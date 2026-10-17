# Linux workspace attempt 06 (2026-10-17)

The bounded Linux workspace rerun ended when its 25-minute worker window expired. It is a partial run and does not replace the previously completed Linux workspace result or count as a full workspace pass.

The retained runtime log contains 1,237 passed, 0 failed, and 12 ignored test cases before the interruption. It begins workspace doctests and ends at `Doc-tests nestlink_sdk`, without a completion summary. No successful-run receipt or matching runtime source manifest was produced, so the partial counts are evidence of completed test output only.

The workspace doctests were then run independently with `cargo test --workspace --doc --locked --offline`. All 36 doctest targets completed with exit code 0; none contained runnable examples. The selected-source receipt records 1,081 source inputs unchanged and owned scratch cleanup. This standalone check does not turn the interrupted workspace command into a completed run.

The authorized WSL clock window started at 2026-10-17 07:32:05 +08:00 and expired at 07:57:06. The worker was stopped. The independent watchdog recorded zero clock steps and no restoration errors, and confirmed restoration of the original `tsc` clocksource and active `systemd-timesyncd` state. Ubuntu and Docker Desktop WSL distributions are both stopped again, matching their pre-run state.

| Evidence | SHA-256 |
| --- | --- |
| [`workspace-linux-attempt06.log`](../../artifacts/native-network-integration-20261016/workspace-linux-attempt06.log) | `b5cdc42a6450a2448215d0618c8fe0a9815f6ac7b37fb53e2c02e7d15c2d9ca6` |
| [`linux-clock-window-attempt06.json`](../../artifacts/native-network-integration-20261016/linux-clock-window-attempt06.json) | `4d7be7657f167c05fd211f5264dd99edd3015e27bf3bf5304c2e9f6a857240e9` |
| [`linux-clock-watchdog-attempt06.json`](../../artifacts/native-network-integration-20261016/linux-clock-watchdog-attempt06.json) | `16858be70ac518416c5c1d9b2971ff399f7aebecc11ab46f25cbf13a35a012e5` |
| [`workspace-linux-doc-attempt01.log`](../../artifacts/native-network-integration-20261016/workspace-linux-doc-attempt01.log) | `7327350d186927cad0615b85db3c6f10595b877e9158c7cb3db4892b3b67f0aa` |
| [`workspace-linux-doc-attempt01.receipt.json`](../../artifacts/native-network-integration-20261016/workspace-linux-doc-attempt01.receipt.json) | `5660e4844245c776c97693ba94eb5daea587c21000e82afa40e35c39b02986e8` |

