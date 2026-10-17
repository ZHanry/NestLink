//! Actual offline commands, OS-private files and the singleton control lease.
use nestlink_identity::{
    PermitSigner,
    service_quota_recovery::{ExternalServiceQuotaSigner, service_quota_recovery_request_digest},
};
use nestlink_operations::deployment::DeploymentLease;
use nestlink_platform_security::{create_private, load_key, new_private_directory, read_private};
use nestlink_protocol::{
    SCHEMA_VERSION,
    service_quota_recovery::{ServiceQuotaReconciliationClaims, ServiceQuotaRecoveryRequest},
};
use nestlink_server::config::ServerConfig;
use nestlink_storage::Store;
use std::{
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn actual_offline_quota_commands_require_external_trust_and_stopped_control() -> Result {
    let temporary = tempfile::tempdir()?;
    let private = temporary.path().join("private");
    new_private_directory(&private)?;
    let directory = private.join("restored");
    let config_path = directory.join("server.toml");
    let binary = env!("CARGO_BIN_EXE_nestlink-server");
    let initialized = Command::new(binary)
        .args(["init", "--directory"])
        .arg(&directory)
        .args(["--management-origin", "https://quota.example.test"])
        .output()?;
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let request_path = private.join("request.json");
    let request_command = || {
        Command::new(binary)
            .args(["quota-recovery-request", "--config"])
            .arg(&config_path)
            .arg("--output")
            .arg(&request_path)
            .output()
    };
    assert!(!request_command()?.status.success());
    assert!(!request_path.exists());
    let config = ServerConfig::load(&config_path)?;
    {
        let mut store = Store::open_existing(&config.database, &config.deployment_id)?;
        store.invalidate_after_restore()?;
    }
    let runtime = DeploymentLease::runtime(&directory)?;
    assert!(!request_command()?.status.success());
    assert!(!request_path.exists());
    drop(runtime);
    assert!(request_command()?.status.success());
    assert!(!request_command()?.status.success());
    let request: ServiceQuotaRecoveryRequest =
        serde_json::from_slice(&read_private(&request_path, 1024 * 1024)?)?;
    let at: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let external = ExternalServiceQuotaSigner::from_external_seed(&[0xa1; 32]);
    let external_key = private.join("independently-provisioned-ledger.pub");
    create_private(&external_key, &external.public_key())?;
    let proof_path = private.join("external-proof.json");
    let proof = external.sign(&ServiceQuotaReconciliationClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: request.deployment_id.clone(),
        restored_security_epoch: request.restored_security_epoch,
        policy_revision: request.policy_revision,
        quota_revision: request.quota_revision,
        request_sha256: service_quota_recovery_request_digest(&request)?,
        ledger_id: nestlink_auth::random_id(),
        checkpoint_id: nestlink_auth::random_id(),
        checkpoint_sha256: [0xa2; 32],
        all_prior_grants_accounted: true,
        prior_authority_stopped_at_unix_ms: at - 12000,
        issued_at_unix_ms: at - 100,
        expires_at_unix_ms: at + 60000,
        // The independent test fixture has never issued any service grant.
        totals: Vec::new(),
    })?;
    create_private(&proof_path, &serde_json::to_vec_pretty(&proof)?)?;
    let reconcile = |key: &Path| {
        Command::new(binary)
            .args(["quota-reconcile", "--config"])
            .arg(&config_path)
            .arg("--trusted-ledger-key")
            .arg(key)
            .arg("--proof")
            .arg(&proof_path)
            .output()
    };
    let copied_key = directory.join("restored-self-asserted-ledger.pub");
    create_private(&copied_key, &external.public_key())?;
    assert!(!reconcile(&copied_key)?.status.success());
    let deployment_key = private.join("deployment-derived.pub");
    let seed = load_key(&config.permit_key_file)?;
    create_private(
        &deployment_key,
        &PermitSigner::from_seed(*seed)
            .service_lease_signer()?
            .public_key(),
    )?;
    assert!(!reconcile(&deployment_key)?.status.success());
    let runtime = DeploymentLease::runtime(&directory)?;
    assert!(!reconcile(&external_key)?.status.success());
    drop(runtime);
    let accepted = reconcile(&external_key)?;
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert!(!reconcile(&external_key)?.status.success());
    let mut store = Store::open_existing(&config.database, &config.deployment_id)?;
    assert!(store.service_quota_recovery_request().is_err());
    assert_eq!(
        std::fs::read_dir(&directory)?
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with("quota-reconciliation-"))
            .count(),
        1
    );
    Ok(())
}
