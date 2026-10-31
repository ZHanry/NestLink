//! The resident local guard closes the original activated authority even when
//! the command actor is awaiting an unrelated management operation.
use super::*;
use nestlink_identity::{
    network::NetworkAuthoritySigner,
    offline::{OfflineAdmission, OfflineVerification, verify_offline_bundle},
};
use nestlink_protocol::offline::*;

fn authority() -> Result<(OfflineProcess, OfflineProcess, OfflineAdmission)> {
    let source = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let issued = now()?;
    let mut process = OfflineProcess::new(
        source.device_id.clone(),
        source.identity.public_key(),
        issued,
        1,
    )?;
    let peer = OfflineProcess::new(
        host.device_id.clone(),
        host.identity.public_key(),
        issued,
        1,
    )?;
    let random = nestlink_auth::random_id;
    let claims = OfflineGrantBundleClaims {
        bundle_version: 1,
        deployment_id: random(),
        space_id: random(),
        bundle_id: random(),
        policy_epoch: 1,
        security_epoch: 1,
        highest_revocation_epoch: 1,
        issued_at_ms: issued,
        expires_at_ms: issued + 60_000,
        members: [
            OfflineMember {
                installation_id: source.device_id,
                account_id: random(),
                public_key: source.identity.public_key(),
                membership_epoch: 1,
                process_nonce: process.nonce(),
            },
            OfflineMember {
                installation_id: host.device_id,
                account_id: random(),
                public_key: host.identity.public_key(),
                membership_epoch: 1,
                process_nonce: peer.nonce(),
            },
        ],
        connection: OfflineConnection {
            connection_id: random(),
            path_id: random(),
            direct_transports: vec![OfflineDirectTransport::Quic],
        },
        business: OfflineBusiness::PrivateService {
            service_id: random(),
            service_revision: 2,
            definition_digest: [8; 32],
            target_digest: [9; 32],
        },
        resources: OfflineResourceReservation {
            reservation_id: random(),
            byte_limit: 4096,
            file_write_limit: 0,
            connection_limit: 2,
        },
    };
    let signer = NetworkAuthoritySigner::from_master_seed(&[77; 32])?;
    let key = signer.public_key();
    let revoked = std::collections::BTreeSet::new();
    let context = OfflineVerification {
        authority: &key,
        deployment_id: &claims.deployment_id,
        space_id: &claims.space_id,
        policy_epoch: 1,
        security_epoch: 1,
        highest_revocation_epoch: 1,
        revoked_bundle_ids: &revoked,
        now_ms: issued,
    };
    let bundle = verify_offline_bundle(&signer.sign_offline_bundle(&claims)?, &context)?;
    let digest = bundle.digest();
    let mut owner = process.activate(bundle, &context, digest)?;
    owner.admit_connection(
        issued,
        OfflineDirectTransport::Quic,
        &claims.members[1].public_key,
    )?;
    Ok((process, peer, owner))
}

#[tokio::test]
async fn original_resident_guard_terminates_authority_on_logout_login_identity_and_maintenance()
-> Result<()> {
    for mode in 0..4 {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("private");
        nestlink_platform_security::new_private_directory(&directory)?;
        nestlink_platform_security::create_private(
            &directory.join("remember-login.json"),
            b"true",
        )?;
        // This test starts after authenticated restoration. These protected
        // snapshots test local lifecycle changes; they never authenticate SDK.
        nestlink_platform_security::create_private(
            &directory.join("management-login.enc"),
            b"original protected authenticated snapshot",
        )?;
        nestlink_platform_security::create_private(
            &directory.join("installation-device.json"),
            b"{\"fixture\":\"original registered identity\"}",
        )?;
        let login = crate::space_dns::session_snapshot(&directory)?;
        let guard = LocalGuard::new(directory.clone(), login)?;
        let (process, _peer_process, mut owner) = authority()?;
        guard.attach(&process)?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        guard.check()?;
        owner.admit_private_service(now()?, &[8; 32], &[9; 32], 1)?;
        let mut maintenance = None;
        match mode {
            0 => std::fs::remove_file(directory.join("remember-login.json"))?,
            1 => {nestlink_platform_security::replace_private_metadata(
                &directory.join("management-login.enc"),
                b"replacement login",
            )?;},
            2 => {nestlink_platform_security::replace_private_metadata(
                &directory.join("installation-device.json"),
                b"{\"fixture\":\"replacement identity\"}",
            )?;},
            _ => {
                maintenance = Some(nestlink_local_ipc::maintenance::MaintenanceGuard::acquire(
                    &directory,
                )?)
            }
        }
        tokio::time::timeout(Duration::from_millis(1500), async {
            while owner.check_current(now()?).is_ok() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await??;
        assert!(owner.is_stopped());
        assert!(guard.check().is_err());
        assert!(
            owner
                .admit_private_service(now()?, &[8; 32], &[9; 32], 1)
                .is_err()
        );
        drop(maintenance);
        drop(guard);
        drop(process);
    }
    Ok(())
}
