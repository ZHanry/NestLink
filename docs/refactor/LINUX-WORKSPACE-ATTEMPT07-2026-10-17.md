# Linux workspace attempt 07 (2026-10-17)

The full Linux workspace runtime command completed with exit code 0:

```text
cargo test --workspace --locked --offline -- --test-threads=1
```

Across 141 test-result groups, 1,237 tests passed, 0 failed, and 12 remained ignored for their documented environment or upstream constraints. The selected source manifest contained 1,081 files; hashes and file lists were unchanged across the run, and owned scratch cleanup completed.

The user-authorized 30-minute WSL test window began with clocksource `tsc` and `systemd-timesyncd=active`. The watchdog recorded 10,783 samples and no wall-clock steps. It restored `tsc` and the active service state without errors. Ubuntu and Docker Desktop WSL distributions were stopped after the run, matching their pre-run state.

| Evidence | SHA-256 |
| --- | --- |
| [`workspace-linux-attempt07.log`](../../artifacts/native-network-integration-20261016/workspace-linux-attempt07.log) | `b496afe6cc1399b492216b18be7c0cbd2b8bfe7b89f4d263e7316f89ec4e626f` |
| [`workspace-linux-attempt07.receipt.json`](../../artifacts/native-network-integration-20261016/workspace-linux-attempt07.receipt.json) | `135422fa4e0af24202752bd573135ac83c58b47e489ebfad2fd4b62903c75766` |
| [`linux-clock-window-attempt07.json`](../../artifacts/native-network-integration-20261016/linux-clock-window-attempt07.json) | `5de92419bf877cd48c1f022e37b2d94e75eb06287a81c2d903e1970e555dfef1` |
| [`linux-clock-window-attempt07.py`](../../artifacts/native-network-integration-20261016/linux-clock-window-attempt07.py) | `f49aad57e15c9a267e165d4a817244292d5384ca7f926c51ad6ba58aab217d9d` |
| [`linux-clock-window-attempt07-derivation.json`](../../artifacts/native-network-integration-20261016/linux-clock-window-attempt07-derivation.json) | `fbb2661a2c18de53f75ab02bdc5007a182562445860ffa4a6f2a193a735a55a4` |

This is development-level Linux workspace evidence. It does not replace the fixed signed installation and platform acceptance required by A01–A21.
