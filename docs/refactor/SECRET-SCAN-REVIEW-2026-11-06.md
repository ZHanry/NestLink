# Public fixture assignment review — 2026-11-06

The 0.8.1 UI development check found credential-assignment matches already present
in source commit `3ac017a18a8c9e14a517d361d56c2894e466ddcb`. Each match below is
inside test-only code: synthetic account passwords for temporary in-memory or
loopback test servers, fixed ICE test parameters, or intentional secret-redaction
fixtures. They are not credentials for a deployed control center. The diagnostic
and Python fixtures deliberately verify that secret-shaped data is excluded from
public exports.

The scanner keeps its original patterns. Exemptions apply only to the complete
match SHA-256 and exact source path, and only to `credential-assignment`. Changing
the literal or moving it to another path produces a finding. No key/token rule is
exempted. Matching values are omitted from this report.

| Source | Test helper / case | Complete-match SHA-256 |
| --- | --- | --- |
| `apps/daemon/src/diagnostics/export.rs:249` | `export_reprojects_nested_unknown_data_and_retains_unknown_metrics` | `c854d8d51609d3cbc1d53c2e5ccc7a779f9cfdc5c5d0c0c80f2211361c21e987` |
| `apps/daemon/src/private_service_proxy/host/tests.rs:806` | `host_identity_different_account_cannot_approve_original_target` | `607768c2d21021214db3711225d537311a71e885719d3199673f3bf84aee0d80` |
| `apps/daemon/src/space_dns_system/tests.rs:174` | `actual_os_split_dns_resolves_and_recovers_without_changing_unrelated_policy` | `ebe9d73f0ff772302508f6215a8c0d56e2a42062cc5b1f18aed8c3809555b286` |
| `apps/server/src/node_control/revocation_tests.rs:28` | `new` | `907fca66db9b2b22bbe8cb581a8e3856b6db836ec4f3456e5d92422400cdc3b0` |
| `apps/server/tests/internal_software_media_candidate.rs:129` | `candidate_http` | `7d748e29f38e96a0edf3b9a46cf6be5058227ca4bd2a367856247b5e291399ef` |
| `crates/app-core/src/native_session.rs:1239` | `explicit_pcp_requires_deployment_permission_even_without_deployment_stun` | `2dd7f7052d66c7ad0e31d1ea899d0e1a756cead0fb602588300266158228e4bd` |
| `crates/app-core/src/runtime/native_routed.rs:839` | `client_fixture` | `1c49017d6e6335e1ca8823979cb237b2ba5519ac0a06641424b9d2146252915d` |
| `crates/protocol/src/native_ice.rs:75` | `parameters` | `6c1c869501c113082d5a0b724e2955c6ee446836f848df1bc06b6ead0527f444` |
| `crates/sdk/src/webrtc_host/tests/data_loopback_tests.rs:1027` | `new` | `acb74a6b9bf2e17de4d5b8c4d5cd31aebc17612d1d4a57c679895e69667f897d` |
| `crates/sdk/tests/ice_relay_contract.rs:105` | `relay_ice_observer_accepts_payload_writes_and_transfers_both_directions` | `f11e4556d083551449a5e8b90afd81caa6fcc1e3d6729d3f6711eee4385f8fe3` |
| `crates/sdk/tests/network_relay.rs:163` | `with_permissions` | `94a95b076f4e35c077355c092130454315ab7ecef7281f2fcd10f3f953f6fb72` |
| `crates/storage/src/media_authority_tests.rs:23` | `hevc_signed_lifecycle` | `a7fb0c0bbf493482fea1a69e807a52b2dec2f0cc17806ec1870e339027417293` |
| `crates/storage/src/media_authority_tests.rs:212` | `frozen_scope_requires_explicit_signed_approval_and_never_widens_from_latest_catalog` | `a7fb0c0bbf493482fea1a69e807a52b2dec2f0cc17806ec1870e339027417293` |
| `crates/storage/src/media_authority_tests.rs:335` | `new_with_candidate` | `757c3f0bab9545249f71a14b36608edf54b4dd1f8099e382739dfb12f2675f83` |
| `crates/storage/src/services/publication/tests/private_policy/offline.rs:11` | `offline_distinct_accounts_cannot_approve_or_consume_the_other_endpoint` | `c97cfd8a7f5d05d965234d0131f3ec3ad225924788039d1f761c509e9f08a688` |
| `crates/storage/src/services/publication/tests/space_policy.rs:348` | `member_removal_and_rule_expiry_never_revive_service_publication` | `845b47bef3d6e8cb9c8dcdd305101b9a89e3369f911847d41a3c631c7aae7a82` |
| `crates/storage/tests/control/native_ice_capabilities.rs:124` | `native_ice_requires_both_signed_device_capabilities_and_direct_permission_and_survives_renewal` | `6c1c869501c113082d5a0b724e2955c6ee446836f848df1bc06b6ead0527f444` |
| `crates/storage/tests/control/native_readiness.rs:84` | `signed_address_free_rendezvous_and_native_ice_wake_only_the_live_authorized_host` | `6c1c869501c113082d5a0b724e2955c6ee446836f848df1bc06b6ead0527f444` |
| `tests/refactor/test_browser_native_runner.py:392` | `test_publish_allowlist_excludes_ready_profile_logs_and_private_key` | `c0dc8f1be2b46b0ef1fac85cf6b3b04bf41177820d0008bdfe2fe682d8c00d5e` |
| `tests/refactor/test_browser_native_runner.py:430` | `test_public_progress_inventory_hashes_sanitized_bytes_without_replacing_private_digest` | `d2a786e79cf2b9f688a4964ddf294991d2bccd2704eb71cfff0d9923401844f1` |
