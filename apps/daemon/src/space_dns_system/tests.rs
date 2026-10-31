use super::*;
use nestlink_platform_security::new_private_directory;

fn plan() -> Result<DnsPlan> {
    let now = wall_ms()?;
    Ok(DnsPlan {
        schema_version: 1,
        owner_id: nestlink_auth::random_id(),
        space_id: nestlink_auth::random_id(),
        suffix: String::new(),
        listen: "127.0.0.1:53".parse()?,
        process: ProcessIdentity {
            pid: std::process::id(),
            incarnation: "test-process-incarnation".into(),
            image: std::env::current_exe()?.to_string_lossy().into(),
        },
        created_at_ms: now,
        expires_at_ms: now + 60_000,
    })
}
fn complete_plan() -> Result<DnsPlan> {
    let mut plan = plan()?;
    plan.suffix = format!("s-{}.nestlink.internal", plan.space_id);
    Ok(plan)
}

#[test]
fn public_plan_accepts_real_uuid_ids_and_rejects_unmanaged_suffix_bind_and_unknown_fields() -> Result
{
    let plan = complete_plan()?;
    plan.validate(true)?;
    assert_eq!(plan.link().len(), 15);
    for fault in 0..5 {
        let mut changed = plan.clone();
        match fault {
            0 => changed.suffix = "local".into(),
            1 => changed.listen = "0.0.0.0:53".parse()?,
            2 => changed.owner_id = "../../foreign".into(),
            3 => changed.expires_at_ms = changed.created_at_ms,
            4 => changed.created_at_ms = changed.created_at_ms.saturating_sub(400_000),
            _ => unreachable!(),
        }
        assert!(changed.validate(true).is_err(), "plan fault {fault}");
    }
    let mut json = serde_json::to_value(&plan)?;
    json["management_token"] = serde_json::json!("unexpected");
    assert!(serde_json::from_value::<DnsPlan>(json).is_err());
    Ok(())
}

#[test]
fn real_private_journal_keeps_prepared_and_installed_state_across_owner_restart() -> Result {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("owner");
    new_private_directory(&directory)?;
    let journal = Journal {
        schema_version: 1,
        plan: complete_plan()?,
        installed: None,
    };
    let store = JournalStore::open(&directory)?;
    assert!(
        JournalStore::open(&directory).is_err(),
        "a second helper cannot share the journal"
    );
    store.save(&journal)?;
    drop(store);
    let store = JournalStore::open(&directory)?;
    let mut resumed = store.read()?.ok_or("journal missing")?;
    assert!(resumed.installed.is_none());
    assert_eq!(resumed.plan.owner_id, journal.plan.owner_id);
    resumed.installed = Some(serde_json::json!({"observed":"installed-state"}));
    store.save(&resumed)?;
    drop(store);
    let store = JournalStore::open(&directory)?;
    assert_eq!(
        store.read()?.ok_or("journal missing")?.installed,
        resumed.installed
    );
    store.clear()?;
    assert!(store.read()?.is_none());
    Ok(())
}

#[cfg(unix)]
#[test]
fn journal_refuses_symlink_directory_and_a_widened_private_directory() -> Result {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("owner");
    new_private_directory(&directory)?;
    let alias = temporary.path().join("alias");
    symlink(&directory, &alias)?;
    assert!(JournalStore::open(&alias).is_err());
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))?;
    assert!(JournalStore::open(&directory).is_err());
    Ok(())
}

struct HttpServer(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for HttpServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// This test is intentionally explicit: it changes only a fresh random private
/// suffix on an isolated hosted VM and uses the real OS resolver. Never invoke
/// it on a developer workstation or reuse a non-ephemeral runner.
#[tokio::test]
#[ignore = "requires an isolated elevated GitHub-hosted Windows/Linux VM with NESTLINK_SYSTEM_DNS_LAB=1"]
async fn actual_os_split_dns_resolves_and_recovers_without_changing_unrelated_policy() -> Result {
    use nestlink_auth::{Secret, VaultKey};
    use nestlink_identity::PermitSigner;
    use nestlink_protocol::spaces::{
        SpaceCreateRequest, SpaceDeviceJoin, addressing::SpaceAddressIssue,
    };
    use nestlink_sdk::{DeploymentTrust, DeviceIdentity, Sdk, SpaceDns};
    use nestlink_server::{AppState, router};
    use nestlink_storage::Store;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    if std::env::var("NESTLINK_SYSTEM_DNS_LAB").as_deref() != Ok("1") {
        return Err("set NESTLINK_SYSTEM_DNS_LAB=1 only on an isolated hosted VM".into());
    }
    require_admin().await?;
    let deployment = nestlink_auth::random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let mut store = Store::in_memory(&deployment)?;
    let password = "real-os-dns-private-test-password";
    store.bootstrap_admin("owner", password)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([103; 32]),
        signer,
        origin.clone(),
        false,
    )?);
    let _server = HttpServer(tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    }));
    let mut sdk = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id: deployment,
            permit_issuer: issuer,
        },
        true,
    )
    .await?;
    sdk.login("owner".into(), Secret::from_text(password.into()), None)
        .await?;
    let device = DeviceIdentity::generate();
    sdk.enroll(
        &device,
        "DNS probe".into(),
        if cfg!(windows) {
            "windows"
        } else {
            "linux-x11"
        }
        .into(),
        vec!["controller".into()],
        "direct_preferred".into(),
    )
    .await?;
    let space = sdk
        .create_space(SpaceCreateRequest {
            name: "isolated OS DNS".into(),
        })
        .await?;
    sdk.join_space_device(
        &space.space_id,
        SpaceDeviceJoin {
            expected_revision: space.revision,
            expected_membership_epoch: 0,
            installation_id: device.device_id.clone(),
        },
    )
    .await?;
    let issued = sdk
        .issue_space_address(
            &space.space_id,
            SpaceAddressIssue {
                expected_revision: 0,
                expected_address_epoch: 0,
                expected_membership_epoch: 1,
                installation_id: device.device_id,
                name: "os-probe".into(),
            },
        )
        .await?;
    let expected = issued
        .addresses
        .first()
        .ok_or("address missing")?
        .ipv4
        .clone();
    let sdk = Arc::new(RwLock::new(sdk));
    let baseline = native_unrelated_state().await?;
    for committed in [true, false] {
        let bind = if cfg!(windows) {
            "127.0.0.1:53"
        } else {
            "127.0.0.1:0"
        };
        let mut dns = SpaceDns::start(sdk.clone(), &space.space_id, bind.parse()?).await?;
        let plan = DnsPlan::current(&space.space_id, dns.local_addr(), wall_ms()? + 60_000).await?;
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("journal");
        new_private_directory(&directory)?;
        let store = JournalStore::open(&directory)?;
        let mut journal = Journal {
            schema_version: 1,
            plan,
            installed: None,
        };
        preflight(&journal.plan).await?;
        store.save(&journal)?;
        let operation = async {
            install(&journal.plan).await?;
            let observation = inspect(&journal.plan).await?.ok_or("OS policy missing")?;
            verify_installed(&journal.plan, &observation)?;
            if committed {
                journal.installed = Some(observation);
                store.save(&journal)?;
            }
            let answer = native_query(&journal.plan).await?;
            assert!(
                answer.contains(&expected),
                "actual OS resolver answer: {answer}"
            );
            assert!(
                recover(&store).await.is_err(),
                "recovery must refuse a live resolver"
            );
            if committed {
                native_change_owned(&journal.plan).await?;
                assert!(
                    remove(&journal).await.is_err(),
                    "external change must be preserved"
                );
                assert!(
                    store.read()?.is_some(),
                    "external change retains the journal"
                );
                native_restore_owned(
                    &journal.plan,
                    journal
                        .installed
                        .as_ref()
                        .ok_or("installed snapshot missing")?,
                )
                .await?;
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }
        .await;
        let stopped = dns.shutdown().await;
        // Re-open after losing the controller's in-memory state, including the
        // crash window before installed readback was committed.
        drop(store);
        let store = JournalStore::open(&directory)?;
        let cleanup = recover(&store).await;
        if let Err(error) = cleanup {
            let retained = temporary.keep();
            return Err(io::Error::other(format!(
                "OS cleanup requires recovery; test journal retained at {}: {error}",
                retained.display()
            ))
            .into());
        }
        operation?;
        stopped?;
        assert!(inspect(&journal.plan).await?.is_none());
        assert!(store.read()?.is_none());
        assert_eq!(
            native_unrelated_state().await?,
            baseline,
            "unrelated policy changed"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
use super::linux::{
    native_change_owned, native_query, native_restore_owned, native_unrelated_state,
};
#[cfg(windows)]
use super::windows::{
    native_change_owned, native_query, native_restore_owned, native_unrelated_state,
};
