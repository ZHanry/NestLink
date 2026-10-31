//! Exact two-step local review around the mature service target/exposure APIs.
use super::*;
use nestlink_sdk::services::HttpsBackendTls;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetReview {
    service_id: String,
    protocol: String,
    target: SocketAddr,
    approval_ms: u64,
    private_maximum_bytes: u64,
    public_maximum_bytes: u64,
    #[serde(default)]
    backend_server_name: Option<String>,
    #[serde(default)]
    backend_ca_der: Vec<PathBuf>,
}
pub(super) struct PendingTarget {
    request: TargetReview,
    view: nestlink_protocol::api::ServiceView,
    previous: Option<ServiceExposureView>,
    consent: LocalServiceTargetConsent,
}
impl PendingTarget {
    pub fn digest(&self) -> &str {
        self.consent.target_digest()
    }
    pub fn view(&self) -> serde_json::Value {
        serde_json::json!({"request":self.request,"original_service":self.view,"previous_exposure":self.previous,"target_digest":self.digest(),"notice":"Approve this exact digest locally. The target/exposure change invalidates old consumer ACLs and leases. Explicit consumers must be granted again before the offline draft."})
    }
    pub async fn review(
        sdk: &Sdk,
        identity: &DeviceIdentity,
        space: &str,
        request: TargetReview,
    ) -> Result<Self> {
        let view = sdk.service(&request.service_id).await?;
        let previous = sdk.service_exposure(&request.service_id).await?;
        if view.definition.host_device_id != identity.device_id
            || !["tcp", "http", "https"].contains(&request.protocol.as_str())
            || request.approval_ms == 0
            || request.approval_ms > 3_600_000
            || request.private_maximum_bytes == 0
            || request
                .private_maximum_bytes
                .checked_add(request.public_maximum_bytes)
                .is_none_or(|n| n > view.definition.limits.maximum_bytes)
            || request.public_maximum_bytes > 0 && view.definition.edge_node_id.is_empty()
            || previous.as_ref().is_some_and(|v| v.space_id != space)
        {
            return Err(invalid("target must belong to this host with a finite original service budget, valid TCP/HTTP/HTTPS protocol and matching space").into());
        }
        let https = request.protocol == "https";
        if https != request.backend_server_name.is_some()
            || https == request.backend_ca_der.is_empty()
            || request.backend_ca_der.len() > 8
        {
            return Err(invalid("HTTPS requires a local backend name and 1..8 DER CA files; other protocols must omit TLS options").into());
        }
        let mut consent =
            LocalServiceTargetConsent::from_local_choice(&view, &request.protocol, request.target)?;
        if let Some(name) = &request.backend_server_name {
            let mut roots = Vec::new();
            for path in &request.backend_ca_der {
                let metadata = std::fs::symlink_metadata(path)?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(
                        invalid("backend CA must be a local regular DER certificate file").into(),
                    );
                }
                let mut bytes = Vec::new();
                std::fs::File::open(path)?
                    .take(16385)
                    .read_to_end(&mut bytes)?;
                if bytes.is_empty() || bytes.len() > 16384 {
                    return Err(invalid("backend DER certificate exceeds its bounded size").into());
                }
                roots.push(bytes);
            }
            consent = consent.with_https_backend_tls(HttpsBackendTls::new(name.clone(), roots)?)?;
        }
        Ok(Self {
            request,
            view,
            previous,
            consent,
        })
    }
    pub async fn approve(
        self,
        sdk: &Sdk,
        identity: &DeviceIdentity,
        space: &str,
        guard: &LocalGuard,
    ) -> Result<LocalServiceTargetConsent> {
        let approved = sdk
            .approve_service_target(identity, &self.consent, self.request.approval_ms)
            .await?;
        guard.check()?;
        let exposure = sdk
            .set_service_exposure(
                &self.request.service_id,
                ServiceExposureUpdate {
                    expected_revision: self.previous.as_ref().map_or(0, |p| p.revision),
                    expected_service_revision: approved.revision,
                    space_id: space.into(),
                    mode: if self.request.public_maximum_bytes == 0 {
                        ServiceAccessMode::Private
                    } else {
                        ServiceAccessMode::Both
                    },
                    private_maximum_bytes: self.request.private_maximum_bytes,
                    public_maximum_bytes: self.request.public_maximum_bytes,
                },
            )
            .await?;
        emit(
            "target_approved",
            serde_json::json!({"service":approved,"exposure":exposure,"target_digest":self.consent.target_digest(),"consumer_acl_must_be_granted_again":true}),
        )?;
        Ok(self.consent)
    }
}
