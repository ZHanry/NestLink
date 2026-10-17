# Current remote preservation inventory (2026-10-17)

The read-only GitHub inventory completed at 2026-10-17 08:52:52 +08:00. All four repository IDs matched the approved list, and their refs were stable during each collection. The snapshot contains 136 refs, 66 Releases and 799 assets totaling 16,177,009,767 bytes.

The current asset metadata was compared by asset ID with the 2026-10-17 full local-archive verification report. All 799 IDs, repository/release/tag, filename, size, uploaded state and SHA-256 matched; no asset was added, removed or changed. The earlier archive report had rehashed all 799 local blobs, totaling 16,177,009,767 bytes. This follow-up reused that verified result and did not rehash the 16 GB archive a second time.

| Repository | Refs | Releases | Assets | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `ZHanry/home-tunnel` | 47 | 26 | 120 | 1,120,661,056 |
| `ZHanry/home-tunnel-server` | 43 | 14 | 144 | 20,093,670 |
| `ZHanry/home-tunnel-client` | 26 | 15 | 368 | 9,856,093,755 |
| `ZHanry/home-tunnel-android` | 20 | 11 | 167 | 5,180,161,286 |

The [machine-readable remote inventory](remote-preservation-inventory-2026-10-17.json) retains the raw GET/`ls-remote` observations. The [archive cross-check](remote-release-archive-crosscheck-2026-10-17.json) binds its summary to the previously verified local archive report. The inventory tool itself does not claim that assets are durably archived remotely: `durable_remote_archive_uploaded` and `finalization_ready` remain false.

The cross-check also matched all 136 ref-object IDs in this snapshot to objects in the restored local source bundle (85,678,333 bytes; SHA-256 `ebf6650beae9d180daa8b7dc7d48e9fb91283a28151d22c31865d3f71c9cb943`). That bundle was restored in a fresh bare repository with 317 refs and passed strict `fsck`; the receipt is recorded in the cross-check and current verification index. This establishes availability of the observed ref-tip objects, not completeness for hidden/unreachable GitHub objects or the three unresolved `hbb_common` gitlinks listed below.

The current refs inventory does not include hidden refs, deleted refs, reflog-only or unreachable objects. Three historical hbb_common gitlinks remain unavailable from the documented public sources. Historical source has not been imported, no archival release has been uploaded to the main repository, and no repository, branch or Release was modified.
