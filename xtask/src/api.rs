use nestlink_protocol::api::*;
use nestlink_protocol::service_plane::{
    ServiceLeaseClaims, ServiceQuotaLimitUpdate, ServiceQuotaUsageQuery, ServiceQuotaUsageView,
    ServiceResourceSnapshot, SignedServiceLease, SignedServiceResourceQuery,
    SignedServiceResourceSnapshot, SignedServiceUsageReport, SignedServiceUsageReportAck,
    SignedServiceUsageRuntimeStop,
    publication::{
        ServiceEdgeNamespace, ServiceEdgeNamespaceUpdate, ServiceEdgeNamespaceView,
        ServiceIssuerDelegation, ServiceLeaseRenewal, ServicePublicationGrant,
        ServicePublicationRequest, ServiceResourceGrant, SignedServiceIssuerDelegation,
    },
};
use nestlink_protocol::services::private::*;
use nestlink_protocol::spaces::addressing::*;
use nestlink_protocol::spaces::service_publication::*;
use nestlink_protocol::spaces::*;
use nestlink_protocol::{
    SignedNodeResourceQuery, SignedNodeResourceSnapshot, SignedNodeUsage, SignedNodeUsageAck,
    SignedRelayClose, SignedRelayCloseAck, SignedTurnCredentials, SignedTurnResourceQuery,
    SignedTurnResourceSnapshot,
};
use schemars::JsonSchema;
use serde_json::{Map, Value, json};
use std::{fs, path::Path};

fn schema<T: JsonSchema>(
    schemas: &mut Map<String, Value>,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut value = serde_json::to_value(schemars::schema_for!(T))?;
    rewrite(&mut value);
    let object = value.as_object_mut().ok_or("schema is not an object")?;
    object.remove("$schema");
    if let Some(Value::Object(defs)) = object.remove("$defs") {
        for (key, value) in defs {
            schemas.insert(key, value);
        }
    }
    schemas.insert(name.into(), value);
    Ok(())
}
fn rewrite(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if key == "$ref" {
                    if let Value::String(reference) = value
                        && let Some(name) = reference.strip_prefix("#/$defs/")
                    {
                        *reference = format!("#/components/schemas/{name}");
                    }
                } else {
                    rewrite(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                rewrite(value);
            }
        }
        _ => {}
    }
}
pub fn document(root: &Path) -> Result<(Value, Value), Box<dyn std::error::Error>> {
    let mut schemas = Map::new();
    macro_rules! models {($($model:ident),*)=>{$(schema::<$model>(&mut schemas,stringify!($model))?;)*};}
    models!(
        DeviceDescriptor,
        DeviceRegistration,
        BrowserEndpointRegistration,
        BrowserEndpointLease,
        RemoteRequest,
        MediaAnnouncementSubmission,
        MediaRemoteRequest,
        MediaApprovalSubmission,
        BrowserHostReadiness,
        BrowserHostReadinessSubmission,
        ApprovalChoice,
        ApprovalSubmission,
        TrustChoice,
        TrustSubmission,
        TrustRevocation,
        TrustedDeviceView,
        TrustedDevicesResponse,
        RemotePasswordSettings,
        RemotePasswordChoice,
        RemotePasswordSetup,
        RemotePasswordAttempt,
        RemotePasswordSubmission,
        RemotePasswordRevocation,
        RemotePasswordView,
        RenewalSubmission,
        ReconnectionChoice,
        ReconnectionSubmission,
        ReconnectionOffer,
        ReconnectionApproval,
        ReconnectionResponse,
        ReconnectionState,
        Candidate,
        WebRtcDescription,
        SignalPayload,
        SignalSubmission,
        SignalView,
        SignalsResponse,
        RelayChallenge,
        RelayHello,
        RelayReady,
        NodeRelayChallenge,
        NodeRelayHello,
        RelayQuota,
        RelayQuotaLimits,
        RelayQuotaUpdate,
        RelayUsage,
        RelayAllocationRequest,
        RelayAllocationResponse,
        RelayReservationUsage,
        TurnCredentialRequest,
        SignedTurnCredentials,
        TurnEndpointConfig,
        TurnEndpointsUpdate,
        TurnEndpointsView,
        TurnPeerSubmission,
        TurnBindingState,
        NodeRegistration,
        NodeView,
        NodesResponse,
        NodeRelayAttributes,
        NodeRelayAttributesUpdate,
        NodeRelayAttributesView,
        NodeEndpoints,
        NodeEndpointsView,
        NodeEndpointsUpdate,
        NodeDiscoveryRequest,
        NodeDiscoveryResponse,
        NodeRelayCandidatesResponse,
        NativeDiscoveryConfig,
        NativePcpPolicy,
        NetworkAuthorityRequest,
        NetworkAuthorityChangeRequest,
        NetworkAuthorityView,
        NetworkMemberRequest,
        NetworkRevokeMemberRequest,
        NetworkIssueRequest,
        NetworkRevokeGrantRequest,
        NetworkPolicyView,
        NetworkMemberView,
        NetworkGrantView,
        NetworkAccessRequest,
        NetworkAccessStart,
        NetworkAccessView,
        NetworkRemotePathRequest,
        NetworkRemotePathView,
        NetworkRemoteRelayRequest,
        NetworkRemoteRelayChainRequest,
        NetworkRemoteRelayChainView,
        NetworkRemoteRouteSetRequest,
        NetworkRemoteRouteSetMemberRequest,
        NetworkRemoteRouteSetView,
        NetworkRemoteRouteSetMemberView,
        NetworkTopologyPublisherRequest,
        NetworkRouteExportRequest,
        NetworkTopologyQuery,
        NetworkTopologyEnvelope,
        NetworkRemoteRelayView,
        SpaceCreateRequest,
        SpaceRevisionRequest,
        SpaceMemberUpdate,
        SpaceMemberRemoval,
        SpaceDeviceJoin,
        SpaceDeviceRemoval,
        SpaceInvitationRequest,
        SpaceInvitationAcceptance,
        SpaceView,
        SpaceDetails,
        SpaceInvitationIssued,
        SpaceServiceBindingRequest,
        SpaceServiceRuleRequest,
        SpaceServicePolicyView,
        SpaceAddressIssue,
        SpaceAddressReservation,
        SpaceAddressRename,
        SpaceAddressRevocation,
        SpaceAddressView,
        SpaceAddressDirectory,
        NodeUsageQuery,
        NodeUsageView,
        NodeUsagePage,
        SignedNodeUsage,
        SignedNodeUsageAck,
        SignedRelayClose,
        SignedRelayCloseAck,
        SignedNodeResourceQuery,
        SignedNodeResourceSnapshot,
        SignedTurnResourceQuery,
        SignedTurnResourceSnapshot,
        Login,
        Refresh,
        PasswordChange,
        NewAccount,
        NetworkPolicy,
        PolicyUpdate,
        PathLimitUpdate,
        RevokeDevice,
        Principal,
        LoginResponse,
        RestoreLogin,
        MeResponse,
        AccountView,
        AccountsResponse,
        EnrollmentChallenge,
        DeviceView,
        DevicesResponse,
        RemoteView,
        RemoteRequestsResponse,
        RemotePeerKeys,
        PermitResponse,
        PolicyResponse,
        RevisionResponse,
        IdResponse,
        PathLimit,
        PathLimitsResponse,
        ServiceDefinition,
        ServiceIngress,
        ServiceSourceNetwork,
        ServiceLimits,
        ServiceCreate,
        ServiceUpdate,
        ServiceRevocation,
        ServiceQuery,
        ServiceView,
        ServicePage,
        ServiceApprovalState,
        ServicePublicationStatus,
        ServiceApprovalChallengeRequest,
        ServiceApprovalChallenge,
        ServiceTargetChoice,
        ServiceTargetApproval,
        ServiceEdgeNamespace,
        ServiceEdgeNamespaceUpdate,
        ServiceEdgeNamespaceView,
        ServicePublicationRequest,
        ServicePublicationGrant,
        ServiceResourceGrant,
        ServiceLeaseRenewal,
        SignedServiceResourceQuery,
        SignedServiceResourceSnapshot,
        ServiceIssuerDelegation,
        SignedServiceIssuerDelegation,
        ServiceLeaseClaims,
        SignedServiceLease,
        ServiceResourceSnapshot,
        SignedServiceUsageReport,
        SignedServiceUsageReportAck,
        SignedServiceUsageRuntimeStop,
        ServiceQuotaUsageQuery,
        ServiceQuotaLimitUpdate,
        ServiceQuotaUsageView,
        ServiceExposureUpdate,
        ServiceExposureView,
        PrivateServiceAclUpdate,
        PrivateServiceAclRevocation,
        PrivateServicePolicyView,
        PrivateServicePage,
        SignedPrivateServiceHost,
        SignedPrivateServiceHostWithdrawal,
        PrivateServiceAccessRequest,
        PrivateServiceGrant,
        PrivateServiceHostAccessPage,
        SignedPrivateServiceUsage,
        PrivateServiceUsageAck,
        HealthResponse,
        ServerIdentityChallenge,
        ServerIdentityClaims,
        ServerIdentityProof,
        ErrorResponse,
        AuditQuery,
        AuditEntry,
        AuditPage,
        AuditRetentionUpdate,
        AuditRetention
    );
    schema::<Option<nestlink_protocol::media_authority::MediaAnnouncement>>(
        &mut schemas,
        "MediaAnnouncementResponse",
    )?;
    schema::<Option<nestlink_protocol::media_authority::FrozenMediaScope>>(
        &mut schemas,
        "MediaScopeResponse",
    )?;
    schema::<Vec<SpaceView>>(&mut schemas, "SpacesResponse")?;
    schema::<bool>(&mut schemas, "NetworkAccessStartResponse")?;
    schema::<Option<ServiceExposureView>>(&mut schemas, "ServiceExposureResponse")?;
    schema::<Vec<SpaceAuditEntry>>(&mut schemas, "SpaceAuditResponse")?;
    let routes: Vec<Value> = serde_json::from_slice(&fs::read(
        root.join("protocol-spec/management-routes.json"),
    )?)?;
    let mut paths = Map::new();
    let control_implementation = fs::read_to_string(root.join("apps/server/src/lib.rs"))?;
    let relay_implementation = fs::read_to_string(root.join("apps/server/src/node_relay.rs"))?;
    for route in routes {
        let path = route["path"].as_str().ok_or("route path")?;
        let method = route["method"].as_str().ok_or("route method")?;
        let operation = route["operation"].as_str().ok_or("route operation")?;
        let (implementation, handler) = if route["role"] == "relay" {
            (
                &relay_implementation,
                operation
                    .strip_prefix("node_relay::")
                    .ok_or("relay handler namespace")?,
            )
        } else {
            (&control_implementation, operation)
        };
        if !implementation.contains(&format!("\"/api/v3{path}\""))
            || !implementation.contains(&format!("{method}({handler})"))
        {
            return Err(format!("implemented HTTP route missing: {method} {path}").into());
        }
        let mut item = json!({"operationId":operation,"responses":{},"security":if route["auth"]==true{json!([{"bearerAuth":[]},{"accessCookie":[]}])}else{json!([])}});
        item["x-server-role"] = json!(if route["role"] == "relay" {
            "relay"
        } else {
            "control"
        });
        let mut parameters = Vec::new();
        for part in path.split('/') {
            if let Some(name) = part.strip_prefix('{').and_then(|p| p.strip_suffix('}')) {
                parameters.push(json!({"in":"path","name":name,"required":true,"schema":{"type":"string","format":if name=="id"{"uuid"}else{"string"}}}));
            }
        }
        if let Some(model) = route["query"].as_str() {
            let query = schemas.get(model).ok_or("unknown API query model")?;
            let properties = query["properties"].as_object().ok_or("query properties")?;
            let required = query["required"].as_array();
            for (name, value) in properties {
                parameters.push(json!({"in":"query","name":name,"required":required.is_some_and(|items|items.iter().any(|v|v.as_str()==Some(name))),"schema":value}));
            }
        }
        if !parameters.is_empty() {
            item["parameters"] = json!(parameters);
        }
        if let Some(request) = route["request"].as_str() {
            if !schemas.contains_key(request) {
                return Err(format!("unknown API request {request}").into());
            }
            item["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{request}")}}}});
        }
        let status = route["status"]
            .as_u64()
            .ok_or("response status")?
            .to_string();
        let mut success = json!({"description":"Success"});
        if let Some(response) = route["response"].as_str() {
            if !schemas.contains_key(response) {
                return Err(format!("unknown API response {response}").into());
            }
            success["content"] = json!({"application/json":{"schema":{"$ref":format!("#/components/schemas/{response}")}}});
        }
        if route["websocket"] == true {
            item["x-websocket"] = json!(true);
        }
        if route["node_key_proof"] == true {
            item["x-node-key-proof"] = json!(
                "NodeChallenge/NodeProof signed with the registered node key before any policy lease is issued"
            );
        }
        if route["signed_node_usage"] == true {
            item["x-node-usage-proof"] = json!(
                "SignedNodeUsage signed with the registered node key, bound to the current runtime, security epoch and policy lease; bearer tokens do not authorize reports"
            );
        }
        if route["signed_node_resource_query"] == true {
            item["x-node-resource-proof"] = json!(
                "SignedNodeResourceQuery signed with the registered node key, bound to a live runtime/epoch/policy lease and a short request-specific expiry; bearer tokens cannot substitute for the signature"
            );
        }
        if route["signed_node_turn_resource_query"] == true {
            item["x-node-turn-resource-proof"] = json!(
                "SignedTurnResourceQuery signed with the registered node key, bound to a live runtime/epoch/policy lease and request-specific expiry; the response is signed with the independent node-policy key and peer bindings require both endpoint signatures"
            );
        }
        if route["signed_node_service_resource_query"] == true {
            item["x-node-service-resource-proof"] = json!(
                "SignedServiceResourceQuery signed with the registered node key, bound to the current runtime, security epoch, policy lease, monotonic query sequence and request-specific expiry; the independent node-policy key signs the service resource response. Management bearer tokens cannot replace this proof"
            );
        }
        if route["signed_node_service_usage_report"] == true {
            item["x-node-service-usage-proof"] = json!(
                "SignedServiceUsageReport signed with the registered node key and bound to the exact immutable service grant, node runtime, security epoch, cumulative counters and report sequence. The independent node-policy issuer signs an acknowledgement of the exact report digest; byte-identical retries are idempotent. Management bearer tokens cannot substitute for this proof"
            );
        }
        if route["signed_node_service_usage_stop"] == true {
            item["x-node-service-usage-stop-proof"] = json!(
                "SignedServiceUsageRuntimeStop signed with the allocated node key after the exact publication flows and attachment have drained, binding the final acknowledged report digest and exact cumulative counters. HTTP 204 follows a durable terminal seal; only remaining commitment is released and reported spend remains charged. Byte-identical retries are idempotent and bearer tokens do not authorize the seal"
            );
        }
        if route["administrator"] == true {
            item["x-required-role"] = json!("administrator");
        }
        if route["signed_relay_close"] == true {
            item["x-node-close-proof"] = json!(
                "SignedRelayClose signed by the allocated node key and bound to the exact allocation, runtime, security epoch and stable grant binding. Terminal cleanup facts release only that promise, without granting forwarding authority; exact retries return the immutable signed acknowledgement"
            );
        }
        if route["node_relay_proof"] == true {
            item["x-node-relay-proof"] = json!(
                "NodeRelayChallenge / NodeRelayHello prove the allocated endpoint key, original signed allocation, selected WSS transport and fresh socket challenge before pairing; no management bearer or plaintext media is sent to the node"
            );
        }
        item["responses"][status] = success;
        for status in ["400", "401", "403", "409", "429", "500"] {
            item["responses"][status] = json!({"description":"Structured NestLink error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/ErrorResponse"}}}});
        }
        let entry = paths.entry(path.to_string()).or_insert_with(|| json!({}));
        entry[method] = item;
    }
    // Every implementation route must appear in the authoritative route inventory.
    for part in [&control_implementation, &relay_implementation]
        .into_iter()
        .flat_map(|implementation| {
            implementation
                .split('"')
                .filter(|p| p.starts_with("/api/v3/"))
        })
    {
        if !paths.contains_key(part.trim_start_matches("/api/v3")) {
            return Err(format!("HTTP route lacks protocol definition: {part}").into());
        }
    }
    Ok((Value::Object(paths), Value::Object(schemas)))
}
