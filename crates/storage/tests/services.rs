//! Real on-disk SQLite, signed installation consent, and terminal rollback facts.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, hash_password, random_id};
use nestlink_identity::{
    InstallationIdentity,
    nodes::NodeIdentity,
    services::{approval_transcript, local_target_digest},
};
use nestlink_policy::{NetworkPolicy, PeerPathMode, PublicIngress, ServerForwarding};
use nestlink_protocol::{NodeRole, api::*};
use nestlink_storage::{StorageError, Store, accounts::Principal, services::MAX_ACCOUNT_SERVICES};
use rusqlite::{Connection, params};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const PASSWORD: &str = "service-registry-test-password";

struct Fixture {
    directory: tempfile::TempDir,
    store: Store,
    vault: VaultKey,
    dummy: String,
    admin: Principal,
    member: Principal,
    identity: InstallationIdentity,
    host: String,
    node: String,
}
impl Fixture {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let mut store = Store::open(&directory.path().join("services.sqlite3"), &random_id())?;
        store.bootstrap_admin("admin", PASSWORD)?;
        let vault = VaultKey::from_bytes([3; 32]);
        let dummy = hash_password("service-dummy-test-password")?;
        let admin = store
            .login("admin", PASSWORD, None, 1000, &vault, &dummy)?
            .principal;
        store.create_member(&admin, "member", PASSWORD)?;
        let member = store
            .login("member", PASSWORD, None, 1000, &vault, &dummy)?
            .principal;
        let identity = InstallationIdentity::generate();
        let host = enroll(&mut store, &admin, &identity, false)?;
        let node = random_id();
        let node_identity = NodeIdentity::generate();
        store.register_node(
            &admin,
            NodeRegistration {
                id: node.clone(),
                name: "service-edge".into(),
                public_key: URL_SAFE_NO_PAD.encode(node_identity.public_key()),
                roles: vec![NodeRole::NodeEdge as i32],
                max_connections: 16,
                bytes_per_second: 1_048_576,
            },
        )?;
        Ok(Self {
            directory,
            store,
            vault,
            dummy,
            admin,
            member,
            identity,
            host,
            node,
        })
    }
    fn raw(&self) -> Result<Connection> {
        Ok(Connection::open(
            self.directory.path().join("services.sqlite3"),
        )?)
    }
    fn allow(&mut self) -> Result {
        self.store.apply_policy(
            self.store.policy()?.0,
            NetworkPolicy {
                server_forwarding: ServerForwarding::Allow,
                peer_path_mode: PeerPathMode::DirectOnly,
                public_ingress: PublicIngress::Enabled,
            },
        )?;
        Ok(())
    }
    fn definition(&self) -> ServiceDefinition {
        ServiceDefinition {
            name: "Approved local web service".into(),
            host_device_id: self.host.clone(),
            edge_node_id: self.node.clone(),
            requested_ingress: ServiceIngress::Tcp { port: 29100 },
            allowed_sources: vec![],
            limits: ServiceLimits {
                maximum_connections: 8,
                bytes_per_second: 1_048_576,
                maximum_bytes: 1_073_741_824,
                idle_timeout_seconds: 60,
            },
        }
    }
    fn create(&mut self) -> Result<ServiceView> {
        Ok(self.store.create_service(
            &self.admin,
            ServiceCreate {
                id: random_id(),
                definition: self.definition(),
            },
            1001,
        )?)
    }
    fn challenge(&mut self, view: &ServiceView) -> Result<ServiceApprovalChallenge> {
        Ok(self
            .store
            .service_approval_challenge(&self.admin, &view.id, view.revision, 1001)?)
    }
    fn proof(
        &self,
        view: &ServiceView,
        challenge: &ServiceApprovalChallenge,
    ) -> Result<ServiceTargetApproval> {
        proof(&self.identity, view, challenge)
    }
}
fn enroll(
    store: &mut Store,
    actor: &Principal,
    identity: &InstallationIdentity,
    browser: bool,
) -> Result<String> {
    let challenge = store.enrollment_challenge(actor, 1000)?;
    let descriptor = DeviceDescriptor {
        id: random_id(),
        name: "local-service-host".into(),
        platform: if browser { "web" } else { "windows" }.into(),
        public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
        capabilities: if browser {
            vec!["controller".into(), "vp8".into()]
        } else {
            vec!["host".into(), "vp8".into()]
        },
        path_mode: "direct_only".into(),
    };
    let id = descriptor.id.clone();
    if browser {
        let mut body = BrowserEndpointRegistration {
            challenge_id: challenge.id,
            device: descriptor,
            signature: String::new(),
        };
        body.signature = URL_SAFE_NO_PAD
            .encode(identity.sign_action(&store.browser_endpoint_transcript(actor, &body, 1000)?)?);
        store.register_browser_endpoint(actor, body, 1000)?;
    } else {
        let mut body = DeviceRegistration {
            challenge_id: challenge.id,
            device: descriptor,
            signature: String::new(),
        };
        body.signature = URL_SAFE_NO_PAD
            .encode(identity.sign_action(&store.registration_transcript(actor, &body, 1000)?)?);
        store.register_device(actor, body, 1000)?;
    }
    Ok(id)
}
fn proof(
    identity: &InstallationIdentity,
    view: &ServiceView,
    challenge: &ServiceApprovalChallenge,
) -> Result<ServiceTargetApproval> {
    let target = random_id();
    let choice = ServiceTargetChoice {
        expected_revision: view.revision,
        target_id: target.clone(),
        target_sha256: URL_SAFE_NO_PAD.encode(local_target_digest(
            view,
            &target,
            "tcp",
            "127.0.0.1:8080".parse()?,
        )?),
        expires_at_unix_ms: challenge.issued_at_unix_ms + 60000,
    };
    let signature =
        URL_SAFE_NO_PAD.encode(identity.sign_action(&approval_transcript(challenge, &choice)?)?);
    Ok(ServiceTargetApproval {
        challenge_id: challenge.id.clone(),
        choice,
        signature,
    })
}

#[test]
fn default_deny_saves_configuration_but_never_grants_or_publishes_a_target() -> Result {
    let mut f = Fixture::new()?;
    let view = f.create()?;
    assert_eq!(view.approval, ServiceApprovalState::Pending);
    assert_eq!(view.publication, ServicePublicationStatus::NotPublished);
    assert!(
        matches!(f.store.service_approval_challenge(&f.admin,&view.id,1,1001),Err(StorageError::Proof(error)) if error.code==nestlink_protocol::ErrorCode::PublicIngressDisabled)
    );
    assert_eq!(
        f.raw()?
            .query_row("SELECT count(*) FROM service_target_approvals", [], |r| r
                .get::<_, u64>(
                0
            ))?,
        0
    );
    Ok(())
}

#[test]
fn private_target_consent_requires_no_public_edge_or_public_ingress() -> Result {
    let mut f = Fixture::new()?;
    let mut definition = f.definition();
    definition.edge_node_id.clear();
    assert_eq!(definition.accounting_node_id(), f.host);
    let pending = f.store.create_service(
        &f.admin,
        ServiceCreate {
            id: random_id(),
            definition,
        },
        1001,
    )?;
    let challenge = f.challenge(&pending)?;
    let proof = f.proof(&pending, &challenge)?;
    let approved = f
        .store
        .approve_service_target(&f.admin, &pending.id, proof, 1001)?;
    assert_eq!(approved.approval, ServiceApprovalState::ApprovedTarget);
    assert_eq!(approved.publication, ServicePublicationStatus::NotPublished);
    assert!(approved.definition.edge_node_id.is_empty());
    let edge: Option<String> = f.raw()?.query_row(
        "SELECT edge_node_id FROM services WHERE id=?1",
        [&pending.id],
        |r| r.get(0),
    )?;
    assert!(edge.is_none());
    assert!(!f.raw()?.prepare("PRAGMA foreign_key_check")?.exists([])?);
    let mut changed = approved.definition.clone();
    changed.name = "Private service revised locally".into();
    let changed = f.store.update_service(
        &f.admin,
        &approved.id,
        ServiceUpdate {
            expected_revision: approved.revision,
            definition: changed,
        },
        1001,
    )?;
    assert_eq!(changed.approval, ServiceApprovalState::Invalidated);
    assert!(changed.definition.edge_node_id.is_empty());
    Ok(())
}

fn remove_schema_42_relays(raw: &Connection) -> Result {
    raw.execute_batch("DROP VIEW all_relay_capacity; DROP TABLE private_service_relay_hops;
        CREATE VIEW all_relay_capacity AS SELECT id,kind,controller_account_id,host_account_id,node_id,promised_until FROM relay_reservations
        UNION ALL SELECT allocation_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_relays
        UNION ALL SELECT route_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_chain_hops
        UNION ALL SELECT allocation_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_route_set_members;")?;
    Ok(())
}
#[test]
fn schema_39_upgrade_preserves_approved_public_target_and_child_foreign_keys() -> Result {
    let mut f = Fixture::new()?;
    f.allow()?;
    let pending = f.create()?;
    let challenge = f.challenge(&pending)?;
    let proof = f.proof(&pending, &challenge)?;
    let approved = f
        .store
        .approve_service_target(&f.admin, &pending.id, proof, 1001)?;
    let deployment = f.store.deployment_id()?;
    let Fixture {
        directory,
        store,
        admin,
        ..
    } = f;
    drop(store);
    let path = directory.path().join("services.sqlite3");
    let raw = Connection::open(&path)?;
    remove_schema_42_relays(&raw)?;
    // Build the historical parent table from its authoritative schema, retaining
    // the real signed consent and challenge children created through Store.
    let historical = include_str!("../migrations/018_service_registry.sql")
        .split("CREATE INDEX services_owner")
        .next()
        .ok_or("historical schema missing")?
        .replace("CREATE TABLE services (", "CREATE TABLE services_v39 (");
    raw.pragma_update(None, "foreign_keys", "OFF")?;
    raw.execute_batch(&historical)?;
    raw.execute_batch("INSERT INTO services_v39 SELECT * FROM services; DROP TABLE services; ALTER TABLE services_v39 RENAME TO services; CREATE INDEX services_owner ON services(account_id,id); ALTER TABLE private_service_leases DROP COLUMN network_json; PRAGMA user_version=39;")?;
    drop(raw);
    let store = Store::open_existing(&path, &deployment)?;
    assert_eq!(
        serde_json::to_value(store.service(&admin, &approved.id, 1001)?)?,
        serde_json::to_value(&approved)?
    );
    let raw = Connection::open(&path)?;
    assert!(!raw.prepare("PRAGMA foreign_key_check")?.exists([])?);
    assert_eq!(
        raw.pragma_query_value(None, "user_version", |r| r.get::<_, i32>(0))?,
        nestlink_storage::SCHEMA_VERSION
    );
    raw.pragma_update(None, "foreign_keys", "ON")?;
    assert!(
        raw.execute("DELETE FROM services WHERE id=?1", [&approved.id])
            .is_err()
    );
    let definition: String = raw.query_row(
        "SELECT definition_json FROM services WHERE id=?1",
        [&approved.id],
        |r| r.get(0),
    )?;
    assert_eq!(definition, serde_json::to_string(&approved.definition)?);
    Ok(())
}

#[test]
fn schema_40_upgrade_preserves_consent_without_minting_private_network_authority() -> Result {
    let mut f = Fixture::new()?;
    f.allow()?;
    let pending = f.create()?;
    let challenge = f.challenge(&pending)?;
    let proof = f.proof(&pending, &challenge)?;
    let approved = f
        .store
        .approve_service_target(&f.admin, &pending.id, proof, 1001)?;
    let deployment = f.store.deployment_id()?;
    let Fixture {
        directory,
        store,
        admin,
        ..
    } = f;
    drop(store);
    let path = directory.path().join("services.sqlite3");
    let raw = Connection::open(&path)?;
    remove_schema_42_relays(&raw)?;
    raw.execute_batch(
        "ALTER TABLE private_service_leases DROP COLUMN network_json; PRAGMA user_version=40;",
    )?;
    drop(raw);
    let store = Store::open_existing(&path, &deployment)?;
    assert_eq!(
        serde_json::to_value(store.service(&admin, &approved.id, 1001)?)?,
        serde_json::to_value(&approved)?
    );
    let raw = Connection::open(&path)?;
    assert!(!raw.prepare("PRAGMA foreign_key_check")?.exists([])?);
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM private_service_leases WHERE network_json IS NOT NULL",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        0
    );
    assert_eq!(
        raw.pragma_query_value(None, "user_version", |row| row.get::<_, i32>(0))?,
        nestlink_storage::SCHEMA_VERSION
    );
    Ok(())
}
#[test]
fn direct_only_allows_independent_target_consent_and_fences_all_older_challenges() -> Result {
    let mut f = Fixture::new()?;
    f.allow()?;
    let view = f.create()?;
    let first = f.challenge(&view)?;
    let older = f.challenge(&view)?;
    let body = f.proof(&view, &first)?;
    let stale = f.proof(&view, &older)?;
    let count = f.store.audit_count()?;
    let approved = f
        .store
        .approve_service_target(&f.admin, &view.id, body.clone(), 1001)?;
    assert_eq!(approved.revision, 2);
    assert_eq!(approved.approval, ServiceApprovalState::ApprovedTarget);
    assert_eq!(approved.publication, ServicePublicationStatus::NotPublished);
    assert_eq!(approved.target_id.as_ref(), Some(&body.choice.target_id));
    assert_eq!(f.store.audit_count()?, count + 1);
    assert!(
        f.store
            .approve_service_target(&f.admin, &view.id, body, 1001)
            .is_err()
    );
    assert!(
        f.store
            .approve_service_target(&f.admin, &view.id, stale, 1001)
            .is_err()
    );
    assert_eq!(f.store.audit_count()?, count + 1);
    assert_eq!(
        f.store.service(&f.admin, &view.id, 1001)?.target_id,
        approved.target_id
    );
    let revoked = f
        .store
        .revoke_service(&f.admin, &view.id, approved.revision, 1001)?;
    assert_eq!(revoked.revision, 3);
    assert_eq!(revoked.approval, ServiceApprovalState::Revoked);
    f.store
        .revoke_service(&f.admin, &view.id, approved.revision, 1001)?;
    assert_eq!(f.store.audit_count()?, count + 2);
    assert!(
        f.store
            .update_service(
                &f.admin,
                &view.id,
                ServiceUpdate {
                    expected_revision: 3,
                    definition: f.definition()
                },
                1001
            )
            .is_err()
    );
    Ok(())
}
#[test]
fn tampered_target_wrong_installation_and_changed_definition_do_not_consume_consent() -> Result {
    let mut f = Fixture::new()?;
    f.allow()?;
    let view = f.create()?;
    let challenge = f.challenge(&view)?;
    let body = f.proof(&view, &challenge)?;
    let count = f.store.audit_count()?;
    let mut changed = body.clone();
    changed.choice.target_id = random_id();
    assert!(
        f.store
            .approve_service_target(&f.admin, &view.id, changed, 1001)
            .is_err()
    );
    let mut changed = body.clone();
    changed.choice.target_sha256 = URL_SAFE_NO_PAD.encode([9; 32]);
    assert!(
        f.store
            .approve_service_target(&f.admin, &view.id, changed, 1001)
            .is_err()
    );
    let wrong = proof(&InstallationIdentity::generate(), &view, &challenge)?;
    assert!(
        f.store
            .approve_service_target(&f.admin, &view.id, wrong, 1001)
            .is_err()
    );
    assert!(!f.raw()?.query_row(
        "SELECT consumed FROM service_approval_challenges WHERE id=?1",
        [&challenge.id],
        |r| r.get::<_, bool>(0)
    )?);
    assert_eq!(f.store.audit_count()?, count);
    let mut definition = f.definition();
    definition.limits.maximum_connections += 1;
    f.store.update_service(
        &f.admin,
        &view.id,
        ServiceUpdate {
            expected_revision: 1,
            definition,
        },
        1001,
    )?;
    assert!(
        f.store
            .approve_service_target(&f.admin, &view.id, body, 1001)
            .is_err()
    );
    assert_eq!(
        f.raw()?
            .query_row("SELECT count(*) FROM service_target_approvals", [], |r| r
                .get::<_, u64>(
                0
            ))?,
        0
    );
    Ok(())
}
#[test]
fn approval_login_is_independent_and_either_logout_invalidates_it() -> Result {
    let mut f = Fixture::new()?;
    f.allow()?;
    let view = f.create()?;
    let local = f
        .store
        .login("admin", PASSWORD, None, 1001, &f.vault, &f.dummy)?
        .principal;
    let challenge = f
        .store
        .service_approval_challenge(&local, &view.id, 1, 1001)?;
    let body = f.proof(&view, &challenge)?;
    assert!(
        f.store
            .approve_service_target(&f.admin, &view.id, body.clone(), 1001)
            .is_err()
    );
    let approved = f
        .store
        .approve_service_target(&local, &view.id, body.clone(), 1001)?;
    assert_eq!(approved.approval, ServiceApprovalState::ApprovedTarget);
    f.store.logout(&local)?;
    assert_eq!(
        f.store.service(&f.admin, &view.id, 1001)?.approval,
        ServiceApprovalState::Invalidated
    );
    let updated = f.store.update_service(
        &f.admin,
        &view.id,
        ServiceUpdate {
            expected_revision: 2,
            definition: f.definition(),
        },
        1001,
    )?;
    let fresh = f.challenge(&updated)?;
    let proof = f.proof(&updated, &fresh)?;
    f.store
        .approve_service_target(&f.admin, &view.id, proof, 1001)?;
    assert!(
        f.store
            .approve_service_target(&f.admin, &view.id, body, 1001)
            .is_err()
    );
    let second = f
        .store
        .login("admin", PASSWORD, None, 1001, &f.vault, &f.dummy)?
        .principal;
    f.store.logout(&f.admin)?;
    assert_eq!(
        f.store.service(&second, &view.id, 1001)?.approval,
        ServiceApprovalState::Invalidated
    );
    Ok(())
}
#[test]
fn policy_change_expiry_wall_rollback_device_and_node_revocation_invalidate_consent() -> Result {
    let mut f = Fixture::new()?;
    f.allow()?;
    let view = f.create()?;
    let challenge = f.challenge(&view)?;
    let body = f.proof(&view, &challenge)?;
    assert!(
        f.store
            .approve_service_target(&f.admin, &view.id, body.clone(), 1000)
            .is_err()
    );
    assert!(
        f.store
            .approve_service_target(&f.admin, &view.id, body.clone(), 1061)
            .is_err()
    );
    f.store
        .apply_policy(f.store.policy()?.0, f.store.policy()?.1)?;
    assert!(
        f.store
            .approve_service_target(&f.admin, &view.id, body, 1001)
            .is_err()
    );
    let fresh = f.challenge(&view)?;
    let body = f.proof(&view, &fresh)?;
    f.store
        .approve_service_target(&f.admin, &view.id, body, 1001)?;
    assert_eq!(
        f.store.service(&f.admin, &view.id, 1000)?.approval,
        ServiceApprovalState::Invalidated
    );
    assert_eq!(
        f.store.service(&f.admin, &view.id, 1061)?.approval,
        ServiceApprovalState::Invalidated
    );
    f.store.revoke_node(&f.admin, &f.node)?;
    assert_eq!(
        f.store.service(&f.admin, &view.id, 1001)?.approval,
        ServiceApprovalState::Invalidated
    );
    f.store
        .revoke_device_as(&f.admin, &random_id(), &f.host, 1001)?;
    assert_eq!(
        f.store.service(&f.admin, &view.id, 1001)?.approval,
        ServiceApprovalState::Invalidated
    );
    Ok(())
}
#[test]
fn ownership_is_not_admin_flag_and_browser_endpoints_cannot_be_service_exits() -> Result {
    let mut f = Fixture::new()?;
    let view = f.create()?;
    let mut forged = f.member.clone();
    forged.is_admin = true;
    assert!(f.store.service(&forged, &view.id, 1001).is_err());
    assert!(f.store.revoke_service(&forged, &view.id, 1, 1001).is_err());
    assert!(
        f.store
            .create_service(
                &forged,
                ServiceCreate {
                    id: random_id(),
                    definition: f.definition()
                },
                1001
            )
            .is_err()
    );
    let browser = enroll(
        &mut f.store,
        &f.admin,
        &InstallationIdentity::generate(),
        true,
    )?;
    let mut definition = f.definition();
    definition.host_device_id = browser;
    assert!(
        f.store
            .create_service(
                &f.admin,
                ServiceCreate {
                    id: random_id(),
                    definition
                },
                1001
            )
            .is_err()
    );
    let relay = random_id();
    let relay_identity = NodeIdentity::generate();
    f.store.register_node(
        &f.admin,
        NodeRegistration {
            id: relay.clone(),
            name: "relay-only".into(),
            public_key: URL_SAFE_NO_PAD.encode(relay_identity.public_key()),
            roles: vec![NodeRole::NodeRelay as i32],
            max_connections: 16,
            bytes_per_second: 1024,
        },
    )?;
    let mut definition = f.definition();
    definition.edge_node_id = relay;
    assert!(
        f.store
            .create_service(
                &f.admin,
                ServiceCreate {
                    id: random_id(),
                    definition
                },
                1001
            )
            .is_err()
    );
    Ok(())
}
#[test]
fn sqlite_reopen_and_snapshot_keep_configuration_without_reviving_restored_approval() -> Result {
    let mut f = Fixture::new()?;
    f.allow()?;
    let view = f.create()?;
    let challenge = f.challenge(&view)?;
    let body = f.proof(&view, &challenge)?;
    let approved = f
        .store
        .approve_service_target(&f.admin, &view.id, body.clone(), 1001)?;
    let deployment = f.store.deployment_id()?;
    let mut reopened =
        Store::open_existing(&f.directory.path().join("services.sqlite3"), &deployment)?;
    assert_eq!(
        reopened.service(&f.admin, &view.id, 1001)?.approval,
        ServiceApprovalState::ApprovedTarget
    );
    assert!(
        reopened
            .approve_service_target(&f.admin, &view.id, body, 1001)
            .is_err()
    );
    let mut restored = Store::from_snapshot(&reopened.snapshot()?, &deployment)?;
    assert_eq!(
        restored.service(&f.admin, &view.id, 1001)?.definition,
        approved.definition
    );
    let epoch = restored.invalidate_after_restore()?;
    let actor = restored
        .login("admin", PASSWORD, None, 1002, &f.vault, &f.dummy)?
        .principal;
    let old = restored.service(&actor, &view.id, 1002)?;
    assert_eq!(old.definition, approved.definition);
    assert_eq!(old.approval, ServiceApprovalState::Invalidated);
    assert_ne!(epoch, challenge.security_epoch);
    assert!(
        restored
            .service_approval_challenge(&actor, &view.id, old.revision, 1002)
            .is_err()
    );
    let updated = restored.update_service(
        &actor,
        &view.id,
        ServiceUpdate {
            expected_revision: old.revision,
            definition: old.definition,
        },
        1002,
    )?;
    let fresh = restored.service_approval_challenge(&actor, &view.id, updated.revision, 1002)?;
    let body = proof(&f.identity, &updated, &fresh)?;
    assert_eq!(
        restored
            .approve_service_target(&actor, &view.id, body, 1002)?
            .approval,
        ServiceApprovalState::ApprovedTarget
    );
    Ok(())
}
#[test]
fn account_history_challenge_capacity_and_cursor_epoch_are_bounded_on_disk() -> Result {
    let mut f = Fixture::new()?;
    f.allow()?;
    let first = f.create()?;
    let count = f.store.audit_count()?;
    f.store.create_service(
        &f.admin,
        ServiceCreate {
            id: first.id.clone(),
            definition: first.definition.clone(),
        },
        1001,
    )?;
    assert_eq!(f.store.audit_count()?, count);
    for _ in 1..MAX_ACCOUNT_SERVICES {
        f.create()?;
    }
    assert!(matches!(
        f.store.create_service(
            &f.admin,
            ServiceCreate {
                id: random_id(),
                definition: f.definition()
            },
            1001
        ),
        Err(StorageError::RateLimited)
    ));
    let page = f.store.services(
        &f.admin,
        ServiceQuery {
            security_epoch: f.store.security_epoch()?,
            after_id: None,
            limit: 100,
        },
        1001,
    )?;
    assert!(page.more);
    assert_eq!(page.services.len(), 100);
    let last = f.store.services(
        &f.admin,
        ServiceQuery {
            security_epoch: page.security_epoch,
            after_id: page.next_id,
            limit: 100,
        },
        1001,
    )?;
    assert!(!last.more);
    assert_eq!(last.services.len(), 28);
    assert!(
        f.store
            .services(
                &f.admin,
                ServiceQuery {
                    security_epoch: page.security_epoch + 1,
                    after_id: None,
                    limit: 100
                },
                1001
            )
            .is_err()
    );
    f.store.revoke_service(&f.admin, &first.id, 1, 1001)?;
    assert!(f.create().is_err());
    let available = last.services.first().ok_or("missing service")?;
    for _ in 0..16 {
        f.store
            .service_approval_challenge(&f.admin, &available.id, available.revision, 1001)?;
    }
    assert!(matches!(
        f.store
            .service_approval_challenge(&f.admin, &available.id, available.revision, 1001),
        Err(StorageError::RateLimited)
    ));
    f.store
        .service_approval_challenge(&f.admin, &available.id, available.revision, 1061)?;
    Ok(())
}
#[test]
fn audit_exhaustion_rolls_back_creation_updates_consumption_and_revocation() -> Result {
    let mut f = Fixture::new()?;
    f.allow()?;
    let view = f.create()?;
    let challenge = f.challenge(&view)?;
    let body = f.proof(&view, &challenge)?;
    let watermark: u64 =
        f.raw()?
            .query_row("SELECT high_watermark FROM audit_settings", [], |r| {
                r.get(0)
            })?;
    f.raw()?.execute(
        "UPDATE audit_settings SET high_watermark=9223372036854775807",
        [],
    )?;
    let id = random_id();
    assert!(
        f.store
            .create_service(
                &f.admin,
                ServiceCreate {
                    id: id.clone(),
                    definition: f.definition()
                },
                1001
            )
            .is_err()
    );
    assert_eq!(
        f.raw()?
            .query_row("SELECT count(*) FROM services WHERE id=?1", [id], |r| r
                .get::<_, u64>(0))?,
        0
    );
    assert!(
        f.store
            .update_service(
                &f.admin,
                &view.id,
                ServiceUpdate {
                    expected_revision: 1,
                    definition: f.definition()
                },
                1001
            )
            .is_err()
    );
    assert!(f.store.revoke_service(&f.admin, &view.id, 1, 1001).is_err());
    assert!(
        f.store
            .approve_service_target(&f.admin, &view.id, body.clone(), 1001)
            .is_err()
    );
    assert_eq!(f.store.service(&f.admin, &view.id, 1001)?.revision, 1);
    assert!(!f.raw()?.query_row(
        "SELECT consumed FROM service_approval_challenges WHERE id=?1",
        [&challenge.id],
        |r| r.get::<_, bool>(0)
    )?);
    assert_eq!(
        f.raw()?
            .query_row("SELECT count(*) FROM service_target_approvals", [], |r| r
                .get::<_, u64>(
                0
            ))?,
        0
    );
    f.raw()?.execute(
        "UPDATE audit_settings SET high_watermark=?1",
        params![watermark],
    )?;
    f.store
        .approve_service_target(&f.admin, &view.id, body, 1001)?;
    Ok(())
}
