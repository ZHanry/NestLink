#![allow(clippy::unwrap_used, clippy::expect_used)]
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::PermitSigner;
use nestlink_platform_input::{InputCapabilities, NativeInput};
use nestlink_privileged::{
    BrokerError, BrokerGate, Grant, Layout, Stamp, TrustPins,
    wire::{self, BrokerAction, BrokerState, Command, Request},
};
use nestlink_protocol::{Path, Permission, PermitClaims, SCHEMA_VERSION};
use nestlink_remote::input::{InputDevice, InputLayout, PlatformInput};
use prost::Message;
use std::{
    io,
    sync::{Arc, Mutex},
};

fn id(number: u8) -> String {
    format!("{number:08x}-1111-4111-8111-111111111111")
}
fn now(offset: u64) -> Stamp {
    Stamp {
        monotonic_ms: offset,
        unix_ms: 1_000_000 + offset,
    }
}
fn layout() -> Layout {
    Layout {
        left: -1920,
        top: 0,
        width: 3840,
        height: 1080,
    }
}
fn fixture() -> (PermitSigner, PermitClaims, TrustPins) {
    let signer = PermitSigner::from_seed([1; 32]);
    let claims = PermitClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 1,
        session_id: id(2),
        account_id: id(3),
        controller_device_id: id(4),
        host_device_id: id(5),
        controller_key_sha256: vec![2; 32],
        host_key_sha256: vec![3; 32],
        resource_id: id(6),
        permissions: vec![Permission::View as i32, Permission::Input as i32],
        paths: vec![Path::Direct as i32],
        policy_revision: 1,
        connection_generation: 1,
        lease_sequence: 1,
        issued_at_unix_ms: 1_000_000,
        expires_at_unix_ms: 1_015_000,
        capability_sha256: vec![7; 32],
        required_capabilities: vec!["vp8".into()],
    };
    let pins = TrustPins {
        issuer: signer.public_key(),
        deployment_id: id(1),
        host_device_id: id(5),
        host_key_sha256: [3; 32],
    };
    (signer, claims, pins)
}
fn signed(signer: &PermitSigner, claims: &PermitClaims) -> String {
    URL_SAFE_NO_PAD.encode(signer.sign(claims).unwrap().encode_to_vec())
}
#[derive(Default)]
struct Effects {
    injected: usize,
    released: usize,
    begin_reset: usize,
    reset: usize,
    fail_inject: bool,
    fail_reset: bool,
    fail_check: bool,
}
struct Device(Arc<Mutex<Effects>>);
impl InputDevice for Device {
    fn check(&mut self) -> io::Result<()> {
        if self.0.lock().unwrap().fail_check {
            Err(io::Error::other("platform changed"))
        } else {
            Ok(())
        }
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        let mut effects = self.0.lock().unwrap();
        match input {
            PlatformInput::Action(_) => effects.injected += 1,
            PlatformInput::Release(_) => effects.released += 1,
        }
        if effects.fail_inject {
            Err(io::Error::other("partial input failure"))
        } else {
            Ok(())
        }
    }
    fn begin_reset(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().begin_reset += 1;
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        let mut effects = self.0.lock().unwrap();
        effects.reset += 1;
        if effects.fail_reset {
            Err(io::Error::other("release refused"))
        } else {
            Ok(())
        }
    }
}
impl NativeInput for Device {
    fn layout(&self) -> InputLayout {
        layout().into()
    }
    fn capabilities(&self) -> InputCapabilities {
        InputCapabilities {
            physical_keys: true,
            pointer_buttons: true,
            text_commit: true,
        }
    }
}
fn active() -> (
    BrokerGate<Device>,
    Grant,
    Arc<Mutex<Effects>>,
    PermitSigner,
    PermitClaims,
) {
    let (signer, claims, pins) = fixture();
    let effects = Arc::new(Mutex::new(Effects::default()));
    let mut gate = BrokerGate::new(pins).unwrap();
    gate.begin_authorize(&signed(&signer, &claims), 1, 1, layout(), now(0))
        .unwrap();
    let grant = gate
        .approve_authorization(Device(effects.clone()), now(1))
        .unwrap();
    (gate, grant, effects, signer, claims)
}

#[test]
fn a_signed_permit_is_only_a_proposal_until_the_local_consent_path_approves_it() {
    let (signer, claims, pins) = fixture();
    let mut gate = BrokerGate::<Device>::new(pins).unwrap();
    let facts = gate
        .begin_authorize(&signed(&signer, &claims), 1, 1, layout(), now(0))
        .unwrap();
    assert_eq!(facts.controller_device_id, claims.controller_device_id);
    assert_eq!(gate.status().state, BrokerState::Idle);
    let fake_binding = wire::GrantBinding {
        session_id: claims.session_id.clone(),
        connection_generation: 1,
        lease_sequence: 1,
        input_epoch: 1,
        layout_epoch: 1,
    };
    assert_eq!(
        gate.input(
            &[0; 32],
            &fake_binding,
            1,
            BrokerAction::Key {
                code: 4,
                down: true
            },
            now(1)
        ),
        Err(BrokerError::Authorization)
    );
    gate.cancel_authorization();
    assert!(matches!(
        gate.approve_authorization(Device(Arc::default()), now(2)),
        Err(BrokerError::Authorization)
    ));
}

#[test]
fn issuer_host_deployment_and_input_permission_are_independently_enforced() {
    for variant in 0..5 {
        let (signer, mut claims, mut pins) = fixture();
        match variant {
            0 => pins.issuer = PermitSigner::from_seed([9; 32]).public_key(),
            1 => claims.host_device_id = id(9),
            2 => claims.host_key_sha256 = vec![9; 32],
            3 => claims.deployment_id = id(9),
            _ => claims.permissions = vec![Permission::View as i32],
        }
        let mut gate = BrokerGate::<Device>::new(pins).unwrap();
        let result = gate.begin_authorize(&signed(&signer, &claims), 1, 1, layout(), now(0));
        assert!(matches!(
            result,
            Err(BrokerError::Authorization | BrokerError::Permission)
        ));
        assert_eq!(gate.status().state, BrokerState::Idle);
    }
}

#[test]
fn a_forged_or_unbounded_permit_and_zero_epochs_cannot_authorize() {
    let (signer, claims, pins) = fixture();
    let mut gate = BrokerGate::<Device>::new(pins).unwrap();
    let mut bytes = signer.sign(&claims).unwrap();
    bytes.signature[0] ^= 1;
    assert!(matches!(
        gate.begin_authorize(
            &URL_SAFE_NO_PAD.encode(bytes.encode_to_vec()),
            1,
            1,
            layout(),
            now(0)
        ),
        Err(BrokerError::Authorization)
    ));
    assert!(matches!(
        gate.begin_authorize(&"a".repeat(100000), 1, 1, layout(), now(0)),
        Err(BrokerError::Protocol)
    ));
    assert!(matches!(
        gate.begin_authorize(&signed(&signer, &claims), 0, 1, layout(), now(0)),
        Err(BrokerError::Epoch)
    ));
}

#[test]
fn time_spent_in_local_consent_never_refreshes_the_original_deadline() {
    let (signer, claims, pins) = fixture();
    let mut gate = BrokerGate::<Device>::new(pins).unwrap();
    gate.begin_authorize(&signed(&signer, &claims), 1, 1, layout(), now(0))
        .unwrap();
    assert!(matches!(
        gate.approve_authorization(Device(Arc::default()), now(15000)),
        Err(BrokerError::Expired)
    ));
    assert_eq!(gate.status().state, BrokerState::Idle);
}

#[test]
fn grant_nonce_all_epochs_lease_sequence_and_input_sequence_are_required() {
    let (mut gate, grant, effects, _, _) = active();
    assert_eq!(
        gate.input(
            &[0; 32],
            &grant.binding,
            1,
            BrokerAction::Key {
                code: 4,
                down: true
            },
            now(2)
        ),
        Err(BrokerError::Authorization)
    );
    for field in 0..5 {
        let mut binding = grant.binding.clone();
        match field {
            0 => binding.session_id = id(8),
            1 => binding.connection_generation += 1,
            2 => binding.lease_sequence += 1,
            3 => binding.input_epoch += 1,
            _ => binding.layout_epoch += 1,
        }
        assert_eq!(
            gate.input(
                &grant.nonce,
                &binding,
                1,
                BrokerAction::Key {
                    code: 4,
                    down: true
                },
                now(2)
            ),
            Err(BrokerError::Epoch)
        );
    }
    gate.input(
        &grant.nonce,
        &grant.binding,
        1,
        BrokerAction::Key {
            code: 4,
            down: true,
        },
        now(2),
    )
    .unwrap();
    assert_eq!(
        gate.input(
            &grant.nonce,
            &grant.binding,
            1,
            BrokerAction::Key {
                code: 4,
                down: true
            },
            now(3)
        ),
        Err(BrokerError::Replay)
    );
    assert_eq!(effects.lock().unwrap().injected, 1);
}

#[test]
fn layout_and_bounded_text_restrictions_are_checked_before_any_platform_effect() {
    let (mut gate, grant, effects, _, _) = active();
    for action in [
        BrokerAction::Pointer {
            button: None,
            down: false,
            x: 1920,
            y: 0,
        },
        BrokerAction::Pointer {
            button: Some(6),
            down: true,
            x: 0,
            y: 0,
        },
        BrokerAction::Key {
            code: 3,
            down: true,
        },
        BrokerAction::Text {
            text: "x".repeat(4097),
        },
        BrokerAction::Text {
            text: "bad\0text".into(),
        },
    ] {
        assert_eq!(
            gate.input(&grant.nonce, &grant.binding, 1, action, now(2)),
            Err(BrokerError::Protocol)
        );
    }
    assert_eq!(effects.lock().unwrap().injected, 0);
}

#[test]
fn renewals_cannot_replay_expand_permissions_or_change_any_original_session_binding() {
    for variant in 0..7 {
        let (mut gate, grant, _, signer, mut claims) = active();
        claims.lease_sequence = 2;
        claims.issued_at_unix_ms += 1000;
        claims.expires_at_unix_ms += 1000;
        match variant {
            0 => claims.lease_sequence = 1,
            1 => claims.connection_generation += 1,
            2 => claims.permissions.push(Permission::FileWrite as i32),
            3 => claims.session_id = id(8),
            4 => claims.controller_device_id = id(8),
            5 => claims.capability_sha256 = vec![8; 32],
            _ => claims.policy_revision += 1,
        }
        assert!(matches!(
            gate.renew(&grant.nonce, &signed(&signer, &claims), now(1000)),
            Err(BrokerError::Replay | BrokerError::Authorization)
        ));
    }
    let (mut gate, grant, effects, signer, mut claims) = active();
    claims.lease_sequence = 2;
    claims.issued_at_unix_ms += 1000;
    claims.expires_at_unix_ms += 1000;
    let renewed = gate
        .renew(&grant.nonce, &signed(&signer, &claims), now(1000))
        .unwrap();
    assert_eq!(renewed.lease_sequence, 2);
    assert_eq!(
        gate.input(
            &grant.nonce,
            &grant.binding,
            1,
            BrokerAction::Key {
                code: 4,
                down: true
            },
            now(1001)
        ),
        Err(BrokerError::Epoch)
    );
    gate.input(
        &grant.nonce,
        &renewed,
        1,
        BrokerAction::Key {
            code: 4,
            down: true,
        },
        now(1002),
    )
    .unwrap();
    assert_eq!(effects.lock().unwrap().injected, 1);
}

#[test]
fn an_expired_grant_cannot_be_revived_by_a_new_signed_renewal() {
    let (mut gate, grant, effects, signer, mut claims) = active();
    claims.lease_sequence = 2;
    claims.issued_at_unix_ms += 15000;
    claims.expires_at_unix_ms += 15000;
    assert!(matches!(
        gate.renew(&grant.nonce, &signed(&signer, &claims), now(15000)),
        Err(BrokerError::Expired)
    ));
    assert_eq!(effects.lock().unwrap().reset, 1);
    assert_eq!(gate.status().state, BrokerState::Idle);
}

#[test]
fn monotonic_expiry_still_fires_with_a_stalled_wall_clock_and_clock_rollback_is_terminal() {
    let (mut gate, _, effects, _, _) = active();
    assert_eq!(
        gate.tick(Stamp {
            monotonic_ms: 15000,
            unix_ms: now(1).unix_ms
        }),
        Err(BrokerError::Expired)
    );
    assert_eq!(effects.lock().unwrap().reset, 1);
    let (mut gate, _, effects, _, _) = active();
    assert_eq!(gate.tick(now(0)), Err(BrokerError::Clock));
    assert_eq!(gate.status().state, BrokerState::Stopped);
    assert_eq!(effects.lock().unwrap().reset, 1);
}

#[test]
fn release_all_releases_only_owned_buttons_and_allows_text_after_the_release() {
    let (mut gate, grant, effects, _, _) = active();
    gate.input(
        &grant.nonce,
        &grant.binding,
        1,
        BrokerAction::Key {
            code: 4,
            down: true,
        },
        now(2),
    )
    .unwrap();
    gate.release_all(&grant.nonce, &grant.binding, 2, now(3))
        .unwrap();
    assert_eq!(effects.lock().unwrap().released, 1);
    assert_eq!(effects.lock().unwrap().reset, 0);
    gate.input(
        &grant.nonce,
        &grant.binding,
        3,
        BrokerAction::Text {
            text: "local test".into(),
        },
        now(4),
    )
    .unwrap();
    gate.revoke(&grant.nonce).unwrap();
    assert_eq!(effects.lock().unwrap().reset, 1);
    assert_eq!(gate.status().state, BrokerState::Idle);
}

#[test]
fn partial_injection_platform_loss_disconnect_and_explicit_exit_all_release_the_device() {
    for reason in 0..4 {
        let (mut gate, grant, effects, signer, claims) = active();
        match reason {
            0 => {
                effects.lock().unwrap().fail_inject = true;
                assert_eq!(
                    gate.input(
                        &grant.nonce,
                        &grant.binding,
                        1,
                        BrokerAction::Key {
                            code: 4,
                            down: true
                        },
                        now(2)
                    ),
                    Err(BrokerError::Platform)
                );
            }
            1 => {
                effects.lock().unwrap().fail_check = true;
                assert_eq!(gate.tick(now(2)), Err(BrokerError::Platform));
            }
            2 => gate.disconnect().unwrap(),
            _ => {
                gate.stop_user().unwrap();
                assert!(matches!(
                    gate.begin_authorize(&signed(&signer, &claims), 1, 1, layout(), now(2)),
                    Err(BrokerError::Stopped)
                ));
            }
        }
        drop(gate);
        assert_eq!(effects.lock().unwrap().begin_reset, 1);
        assert_eq!(effects.lock().unwrap().reset, 1);
    }
}

#[test]
fn cleanup_failure_is_observable_and_permanently_prevents_this_broker_from_reauthorizing() {
    let (mut gate, grant, effects, signer, claims) = active();
    effects.lock().unwrap().fail_reset = true;
    assert_eq!(gate.revoke(&grant.nonce), Err(BrokerError::Cleanup));
    assert!(gate.status().cleanup_failed);
    assert_eq!(gate.status().state, BrokerState::Stopped);
    assert!(matches!(
        gate.begin_authorize(&signed(&signer, &claims), 1, 1, layout(), now(2)),
        Err(BrokerError::Stopped)
    ));
    assert_eq!(gate.stop_user(), Err(BrokerError::Cleanup));
}

#[tokio::test]
async fn framing_rejects_unbounded_lengths_before_body_allocation_and_unknown_commands_or_fields() {
    use tokio::io::AsyncWriteExt;
    for length in [0, (wire::FRAME_BYTES + 1) as u32, u32::MAX] {
        let (mut sender, mut receiver) = tokio::io::duplex(8);
        sender.write_u32_le(length).await.unwrap();
        assert!(matches!(
            wire::read::<_, Request>(&mut receiver).await,
            Err(BrokerError::Protocol)
        ));
    }
    for (index, json) in [
        r#"{"version":1,"id":1,"command":{"operation":"execute","command":"bad"}}"#,
        r#"{"version":1,"id":1,"command":{"operation":"stop_user","issuer":"untrusted"}}"#,
        r#"{"version":1,"id":1,"command":{"operation":"status","issuer":"untrusted"}}"#,
        r#"{"version":1,"id":1,"command":{"operation":"status","operation":"stop_user"}}"#,
        r#"{"version":1,"id":1,"command":{"operation":"status"},"extra":true}"#,
        r#"{"version":1,"id":1,"id":2,"command":{"operation":"status"}}"#,
        r#"{"version":1,"id":1,"command":{"operation":"status"},"command":{"operation":"stop_user"}}"#,
    ].into_iter().enumerate() {
        let (mut sender, mut receiver) = tokio::io::duplex(4096);
        sender.write_u32_le(json.len() as u32).await.unwrap();
        sender.write_all(json.as_bytes()).await.unwrap();
        assert!(matches!(
            wire::read::<_, Request>(&mut receiver).await,
            Err(BrokerError::Protocol)
        ), "invalid request fixture {index} was accepted");
    }
    let mut request = Request {
        version: wire::VERSION,
        id: 1,
        command: Command::Status {},
    };
    request.validate(0).unwrap();
    assert_eq!(request.validate(1), Err(BrokerError::Protocol));
    request.version += 1;
    assert_eq!(request.validate(0), Err(BrokerError::Protocol));
}

#[tokio::test]
async fn empty_commands_and_replies_preserve_wire_shape_and_reject_extra_fields() {
    use tokio::io::AsyncWriteExt;
    for (operation, command) in [
        ("status", Command::Status {}),
        ("stop_user", Command::StopUser {}),
    ] {
        assert_eq!(
            serde_json::to_value(&command).unwrap(),
            serde_json::json!({ "operation": operation })
        );
        let request = Request {
            version: wire::VERSION,
            id: 1,
            command,
        };
        let (mut sender, mut receiver) = tokio::io::duplex(4096);
        wire::write(&mut sender, &request).await.unwrap();
        let received: Request = wire::read(&mut receiver).await.unwrap();
        received.validate(0).unwrap();
        assert_eq!(
            serde_json::to_value(&received.command).unwrap(),
            serde_json::json!({ "operation": operation })
        );
    }
    for (status, result) in [
        ("applied", wire::ReplyValue::Applied {}),
        ("released", wire::ReplyValue::Released {}),
        ("revoked", wire::ReplyValue::Revoked {}),
        ("stopped", wire::ReplyValue::Stopped {}),
    ] {
        assert_eq!(
            serde_json::to_value(&result).unwrap(),
            serde_json::json!({ "status": status })
        );
        let reply = wire::Reply {
            version: wire::VERSION,
            id: 1,
            result,
        };
        let (mut sender, mut receiver) = tokio::io::duplex(4096);
        wire::write(&mut sender, &reply).await.unwrap();
        let received: wire::Reply = wire::read(&mut receiver).await.unwrap();
        assert_eq!(
            serde_json::to_value(&received.result).unwrap(),
            serde_json::json!({ "status": status })
        );

        let invalid = serde_json::json!({ "version": wire::VERSION, "id": 1,
            "result": { "status": status, "issuer": "untrusted" } })
        .to_string();
        let (mut sender, mut receiver) = tokio::io::duplex(4096);
        sender.write_u32_le(invalid.len() as u32).await.unwrap();
        sender.write_all(invalid.as_bytes()).await.unwrap();
        assert!(
            matches!(
                wire::read::<_, wire::Reply>(&mut receiver).await,
                Err(BrokerError::Protocol)
            ),
            "empty reply variant {status} accepted an unknown field"
        );
    }
    let duplicate = r#"{"version":1,"id":1,"result":{"status":"applied","status":"stopped"}}"#;
    let (mut sender, mut receiver) = tokio::io::duplex(4096);
    sender.write_u32_le(duplicate.len() as u32).await.unwrap();
    sender.write_all(duplicate.as_bytes()).await.unwrap();
    assert!(matches!(
        wire::read::<_, wire::Reply>(&mut receiver).await,
        Err(BrokerError::Protocol)
    ));
}
