use crate::{Authentication, LocalHttpsBackendConfig, LocalServiceHostPreview, Snapshot};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_protocol::{
    api::{ServiceApprovalState, ServiceIngress, ServiceView},
    valid_id,
};
use std::{net::SocketAddr, time::Duration};
use tokio::time::Instant;

pub(super) const PREVIEW_LIFETIME: Duration = Duration::from_secs(45);
pub(super) const PREVIEW_LIFETIME_MS: u64 = 45_000;
pub(super) const SERVICE_HOST_CLEANUP_POLL: Duration = Duration::from_millis(100);

/// Every piece of identity that authorizes a local target is carried together.
/// The management session and access expiry bind authentication independently
/// of the UI generation; the service revision/digest bind the exact definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ServiceHostBinding {
    pub runtime_id: String,
    pub server_origin: String,
    pub deployment_id: String,
    pub account_id: String,
    pub management_session_id: String,
    pub auth_session_id: String,
    pub auth_expires: u64,
    pub generation: u64,
    pub service_id: String,
    pub service_revision: u64,
    pub definition_sha256: String,
    pub target_id: String,
    pub target_sha256: String,
    pub protocol: String,
    pub address: SocketAddr,
    pub backend_tls_server_name: Option<String>,
    pub backend_tls_sha256: Option<String>,
}

pub(super) struct PendingServiceHostPreview {
    pub public: LocalServiceHostPreview,
    pub binding: ServiceHostBinding,
    pub expires_at: Instant,
    pub consent: nestlink_sdk::services::LocalServiceTargetConsent,
}

pub(super) struct ServiceHostOwner {
    pub binding: ServiceHostBinding,
    pub approved_view: Option<ServiceView>,
    pub runtime: nestlink_sdk::services::LocalServiceRuntime,
    pub cleanup_requested: bool,
}

pub(super) fn parse_local_choice(
    protocol: &str,
    address: &str,
) -> Result<(String, SocketAddr), ()> {
    if !matches!(protocol, "tcp" | "udp" | "http" | "https")
        || address.is_empty()
        || address.len() > 64
    {
        return Err(());
    }
    // SocketAddr accepts only numeric IP literals and never performs DNS. Require
    // its canonical display form so the string shown to the user is exact.
    let parsed = address.parse::<SocketAddr>().map_err(|_| ())?;
    if parsed.to_string() != address
        || parsed.port() == 0
        || parsed.ip().is_unspecified()
        || parsed.ip().is_multicast()
        || matches!(parsed.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err(());
    }
    Ok((protocol.to_owned(), parsed))
}

pub(super) fn service_is_hostable(view: &ServiceView, device_id: &str) -> bool {
    valid_id(&view.id)
        && valid_id(&view.management_session_id)
        && view.definition.host_device_id == device_id
        && view.approval != ServiceApprovalState::Revoked
        && matches!(
            &view.definition.requested_ingress,
            ServiceIngress::Tcp { .. }
                | ServiceIngress::Udp { .. }
                | ServiceIngress::Http { .. }
                | ServiceIngress::Https { .. }
        )
}

pub(super) fn https_backend_sha256(config: &LocalHttpsBackendConfig) -> String {
    const DOMAIN: &[u8] = b"NestLink/v15/local-service-https-backend/v1\0";
    let mut binding = Vec::with_capacity(
        DOMAIN.len()
            + 8
            + config.server_name.len()
            + 8
            + config
                .ca_certificates_der
                .iter()
                .map(|root| 8 + root.len())
                .sum::<usize>(),
    );
    binding.extend_from_slice(DOMAIN);
    binding.extend_from_slice(&(config.server_name.len() as u64).to_be_bytes());
    binding.extend_from_slice(config.server_name.as_bytes());
    binding.extend_from_slice(&(config.ca_certificates_der.len() as u64).to_be_bytes());
    for root in &config.ca_certificates_der {
        binding.extend_from_slice(&(root.len() as u64).to_be_bytes());
        binding.extend_from_slice(root);
    }
    URL_SAFE_NO_PAD.encode(nestlink_identity::digest(&binding))
}

pub(super) fn local_service_host_cleanup_unconfirmed(snapshot: &Snapshot) -> bool {
    snapshot
        .local_service_host
        .as_ref()
        .is_some_and(|host| host.cleanup_failed)
}

pub(super) fn valid_https_backend_config(config: &LocalHttpsBackendConfig) -> bool {
    config.server_name.len() <= 253
        && (1..=8).contains(&config.ca_certificates_der.len())
        && config
            .ca_certificates_der
            .iter()
            .all(|root| (1..=16_384).contains(&root.len()))
}

pub(super) struct ServiceHostContext {
    pub runtime_id: String,
    pub server_origin: String,
    pub deployment_id: String,
    pub generation: u64,
}

pub(super) struct ServiceHostTarget {
    pub target_id: String,
    pub target_sha256: String,
    pub protocol: String,
    pub address: SocketAddr,
    pub backend_tls_server_name: Option<String>,
    pub backend_tls_sha256: Option<String>,
}

pub(super) fn binding_for(
    context: ServiceHostContext,
    principal: &nestlink_protocol::api::Principal,
    service: &ServiceView,
    target: ServiceHostTarget,
) -> ServiceHostBinding {
    ServiceHostBinding {
        runtime_id: context.runtime_id,
        server_origin: context.server_origin,
        deployment_id: context.deployment_id,
        account_id: principal.account_id.clone(),
        management_session_id: service.management_session_id.clone(),
        auth_session_id: principal.session_id.clone(),
        auth_expires: principal.access_expires,
        generation: context.generation,
        service_id: service.id.clone(),
        service_revision: service.revision,
        definition_sha256: service.definition_sha256.clone(),
        target_id: target.target_id,
        target_sha256: target.target_sha256,
        protocol: target.protocol,
        address: target.address,
        backend_tls_server_name: target.backend_tls_server_name,
        backend_tls_sha256: target.backend_tls_sha256,
    }
}

pub(super) fn snapshot_matches_binding(
    snapshot: &Snapshot,
    binding: &ServiceHostBinding,
    runtime_id: &str,
) -> bool {
    let Some(service) = snapshot.selected_service.data.as_ref() else {
        return false;
    };
    snapshot_context_matches_binding(snapshot, binding, runtime_id)
        && snapshot.authentication == Authentication::SignedIn
        && service.id == binding.service_id
        && service.account_id == binding.account_id
        && service.management_session_id == binding.management_session_id
        && service.revision == binding.service_revision
        && service.definition_sha256 == binding.definition_sha256
        && service.approval != ServiceApprovalState::Revoked
}

pub(super) fn snapshot_context_matches_binding(
    snapshot: &Snapshot,
    binding: &ServiceHostBinding,
    runtime_id: &str,
) -> bool {
    let server_matches = snapshot.server.as_ref().is_some_and(|server| {
        server.origin == binding.server_origin
            && server.deployment_id == binding.deployment_id
            && server.verified_health.is_some()
    });
    snapshot.lifecycle == crate::Lifecycle::Running
        && snapshot.authentication == Authentication::SignedIn
        && snapshot.generation == binding.generation
        && runtime_id == binding.runtime_id
        && server_matches
        && snapshot.principal.as_ref().is_some_and(|principal| {
            principal.account_id == binding.account_id
                && principal.session_id == binding.auth_session_id
                && principal.access_expires == binding.auth_expires
        })
}

pub(super) fn principal_matches_sdk(
    snapshot: &Snapshot,
    principal: &nestlink_protocol::api::Principal,
) -> bool {
    snapshot.principal.as_ref().is_some_and(|view| {
        view.account_id == principal.account_id
            && view.session_id == principal.session_id
            && view.access_expires == principal.access_expires
    })
}

pub(super) fn approved_service_matches(
    binding: &ServiceHostBinding,
    approved: &ServiceView,
) -> bool {
    approved.id == binding.service_id
        && approved.account_id == binding.account_id
        && approved.management_session_id == binding.management_session_id
        && Some(approved.revision) == binding.service_revision.checked_add(1)
        && approved.definition_sha256 == binding.definition_sha256
        && approved.target_id.as_deref() == Some(binding.target_id.as_str())
        && approved.target_sha256.as_deref() == Some(binding.target_sha256.as_str())
        && approved.approval == ServiceApprovalState::ApprovedTarget
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_protocol::api::{
        HealthResponse, Principal, ServiceDefinition, ServiceLimits, ServiceView,
    };

    fn test_service() -> ServiceView {
        ServiceView {
            id: "00000000-0000-4000-8000-000000000001".into(),
            account_id: "account".into(),
            management_session_id: "management-session".into(),
            revision: 7,
            definition: ServiceDefinition {
                name: "local".into(),
                host_device_id: "device".into(),
                edge_node_id: "edge".into(),
                requested_ingress: ServiceIngress::Tcp { port: 80 },
                allowed_sources: vec![],
                limits: ServiceLimits {
                    maximum_connections: 1,
                    bytes_per_second: 1,
                    maximum_bytes: 1,
                    idle_timeout_seconds: 1,
                },
            },
            definition_sha256: "definition-digest".into(),
            approval: ServiceApprovalState::Pending,
            target_id: None,
            target_sha256: None,
            approval_expires_at_unix_ms: None,
            publication: nestlink_protocol::api::ServicePublicationStatus::NotPublished,
        }
    }

    fn signed_in_snapshot(service: ServiceView) -> Snapshot {
        let mut snapshot = Snapshot {
            generation: 5,
            authentication: Authentication::SignedIn,
            server: Some(crate::ServerView {
                origin: "https://management.example".into(),
                deployment_id: "deployment".into(),
                approved_issuer: [0; 32],
                verified_health: Some(HealthResponse {
                    product: "NestLink".into(),
                    version: "test".into(),
                    api_base: "/api".into(),
                    alpn: "nestlink".into(),
                    deployment_id: "deployment".into(),
                    security_epoch: 1,
                    permit_issuer: "issuer".into(),
                    node_policy_issuer: "issuer".into(),
                }),
                error: None,
            }),
            principal: Some(nestlink_protocol::api::Principal {
                account_id: "account".into(),
                session_id: "auth-session".into(),
                name: "user".into(),
                is_admin: false,
                access_expires: 100,
            }),
            ..Snapshot::default()
        };
        snapshot.selected_service.data = Some(std::sync::Arc::new(service));
        snapshot
    }

    #[test]
    fn local_target_requires_canonical_numeric_socket_address() {
        assert!(parse_local_choice("tcp", "127.0.0.1:8080").is_ok());
        assert!(parse_local_choice("udp", "127.0.0.1:8080").is_ok());
        assert!(parse_local_choice("http", "[::1]:8080").is_ok());
        assert!(parse_local_choice("https", "127.0.0.1:443").is_ok());
        assert!(parse_local_choice("tcp", "localhost:8080").is_err());
        assert!(parse_local_choice("tcp", "127.0.0.1:08080").is_err());
        assert!(parse_local_choice("tcp", "0.0.0.0:8080").is_err());
        assert!(parse_local_choice("udp", "255.255.255.255:8080").is_err());
        assert!(parse_local_choice("udp", "127.0.0.1:0").is_err());
    }

    #[test]
    fn service_host_context_binds_management_session_revision_and_digest() {
        let principal = Principal {
            account_id: "account".into(),
            session_id: "session".into(),
            name: "user".into(),
            is_admin: false,
            access_expires: 10,
        };
        let service = ServiceView {
            id: "00000000-0000-4000-8000-000000000001".into(),
            account_id: "account".into(),
            management_session_id: "session".into(),
            revision: 7,
            definition: ServiceDefinition {
                name: "local".into(),
                host_device_id: "device".into(),
                edge_node_id: "edge".into(),
                requested_ingress: ServiceIngress::Tcp { port: 80 },
                allowed_sources: vec![],
                limits: ServiceLimits {
                    maximum_connections: 1,
                    bytes_per_second: 1,
                    maximum_bytes: 1,
                    idle_timeout_seconds: 1,
                },
            },
            definition_sha256: "digest".into(),
            approval: ServiceApprovalState::Pending,
            target_id: None,
            target_sha256: None,
            approval_expires_at_unix_ms: None,
            publication: nestlink_protocol::api::ServicePublicationStatus::NotPublished,
        };
        let binding = binding_for(
            ServiceHostContext {
                runtime_id: "runtime".into(),
                server_origin: "https://management.example".into(),
                deployment_id: "deployment".into(),
                generation: 5,
            },
            &principal,
            &service,
            ServiceHostTarget {
                target_id: "target".into(),
                target_sha256: "target-digest".into(),
                protocol: "tcp".into(),
                address: SocketAddr::from(([127, 0, 0, 1], 80)),
                backend_tls_server_name: None,
                backend_tls_sha256: None,
            },
        );
        assert_eq!(binding.generation, 5);
        assert_eq!(binding.auth_session_id, "session");
        assert_eq!(binding.management_session_id, "session");
        assert_eq!(binding.service_revision, 7);
        assert_eq!(binding.definition_sha256, "digest");
        assert!(PREVIEW_LIFETIME < Duration::from_secs(60));
    }

    #[test]
    fn preview_binding_is_invalidated_by_auth_generation_server_or_service_revision()
    -> std::io::Result<()> {
        let service = test_service();
        let mut snapshot = signed_in_snapshot(service.clone());
        let principal = snapshot
            .principal
            .as_ref()
            .ok_or_else(|| std::io::Error::other("missing signed-in principal"))?;
        let binding = binding_for(
            ServiceHostContext {
                runtime_id: "runtime".into(),
                server_origin: "https://management.example".into(),
                deployment_id: "deployment".into(),
                generation: snapshot.generation,
            },
            principal,
            &service,
            ServiceHostTarget {
                target_id: "target".into(),
                target_sha256: "target-digest".into(),
                protocol: "tcp".into(),
                address: SocketAddr::from(([127, 0, 0, 1], 80)),
                backend_tls_server_name: None,
                backend_tls_sha256: None,
            },
        );

        assert!(snapshot_matches_binding(&snapshot, &binding, "runtime"));

        snapshot.generation += 1;
        assert!(!snapshot_matches_binding(&snapshot, &binding, "runtime"));
        snapshot.generation = binding.generation;

        let mut changed = service.clone();
        changed.management_session_id.push_str("-other");
        snapshot.selected_service.data = Some(std::sync::Arc::new(changed));
        assert!(!snapshot_matches_binding(&snapshot, &binding, "runtime"));
        snapshot.selected_service.data = Some(std::sync::Arc::new(service.clone()));

        snapshot
            .server
            .as_mut()
            .ok_or_else(|| std::io::Error::other("missing verified server"))?
            .origin = "https://other.example".into();
        assert!(!snapshot_matches_binding(&snapshot, &binding, "runtime"));
        Ok(())
    }

    #[test]
    fn approval_must_be_the_exact_next_revision_and_target_choice() {
        let mut approved = test_service();
        let binding = binding_for(
            ServiceHostContext {
                runtime_id: "runtime".into(),
                server_origin: "https://management.example".into(),
                deployment_id: "deployment".into(),
                generation: 5,
            },
            &Principal {
                account_id: "account".into(),
                session_id: "auth-session".into(),
                name: "user".into(),
                is_admin: false,
                access_expires: 100,
            },
            &approved,
            ServiceHostTarget {
                target_id: "target".into(),
                target_sha256: "target-digest".into(),
                protocol: "tcp".into(),
                address: SocketAddr::from(([127, 0, 0, 1], 80)),
                backend_tls_server_name: None,
                backend_tls_sha256: None,
            },
        );
        approved.revision += 1;
        approved.approval = ServiceApprovalState::ApprovedTarget;
        approved.target_id = Some("target".into());
        approved.target_sha256 = Some("target-digest".into());
        assert!(approved_service_matches(&binding, &approved));

        let mut wrong_revision = approved.clone();
        wrong_revision.revision += 1;
        assert!(!approved_service_matches(&binding, &wrong_revision));
        let mut wrong_target = approved.clone();
        wrong_target.target_sha256 = Some("other-digest".into());
        assert!(!approved_service_matches(&binding, &wrong_target));
        let mut wrong_approval = approved;
        wrong_approval.approval = ServiceApprovalState::Invalidated;
        assert!(!approved_service_matches(&binding, &wrong_approval));
    }

    #[test]
    fn unconfirmed_cleanup_blocks_a_new_local_owner() {
        let mut snapshot = Snapshot::default();
        assert!(!local_service_host_cleanup_unconfirmed(&snapshot));
        snapshot.local_service_host = Some(crate::LocalServiceHostView {
            service_id: "00000000-0000-4000-8000-000000000001".into(),
            service_name: "local".into(),
            approved_from_revision: 7,
            approved_revision: Some(8),
            protocol: "tcp".into(),
            address: "127.0.0.1:80".into(),
            status: crate::LocalServiceHostStatus::Failed,
            cleanup_failed: true,
            failure: None,
        });
        assert!(local_service_host_cleanup_unconfirmed(&snapshot));
    }

    #[test]
    fn https_backend_trust_is_bounded_and_fingerprinted_with_name_and_root_order() {
        let config = LocalHttpsBackendConfig {
            server_name: "backend.example".into(),
            ca_certificates_der: vec![vec![1, 2, 3], vec![4, 5, 6]],
        };
        assert!(valid_https_backend_config(&config));
        assert_ne!(
            https_backend_sha256(&config),
            https_backend_sha256(&LocalHttpsBackendConfig {
                server_name: "other.example".into(),
                ..config.clone()
            })
        );
        assert_ne!(
            https_backend_sha256(&config),
            https_backend_sha256(&LocalHttpsBackendConfig {
                ca_certificates_der: vec![vec![4, 5, 6], vec![1, 2, 3]],
                ..config.clone()
            })
        );
        assert!(!valid_https_backend_config(&LocalHttpsBackendConfig {
            ca_certificates_der: vec![vec![0; 16_385]],
            ..config
        }));
    }
}
