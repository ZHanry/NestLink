//! Explicit service publication rights. These are not consumer access grants.
use super::SpaceView;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpaceServiceProtocol {
    Http,
    Https,
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpaceServiceOperation {
    Publish,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SpaceServiceSubject {
    Account { account_id: String },
    Device { installation_id: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceServiceBindingRequest {
    pub expected_revision: u64,
    pub expected_service_revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceServiceRuleRequest {
    pub expected_revision: u64,
    pub expected_binding_epoch: u64,
    pub subject: SpaceServiceSubject,
    pub protocol: SpaceServiceProtocol,
    pub port: u16,
    pub operation: SpaceServiceOperation,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpaceServiceRuleView {
    pub rule_id: String,
    pub subject: SpaceServiceSubject,
    pub subject_epoch: u64,
    pub host_membership_epoch: u64,
    pub protocol: SpaceServiceProtocol,
    pub port: u16,
    pub operation: SpaceServiceOperation,
    pub expires_at_unix_ms: u64,
    pub revoked: bool,
    /// Current rule and approved-target facts; this does not claim ingress readiness.
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpaceServiceBindingView {
    pub service_id: String,
    pub account_id: String,
    pub host_device_id: String,
    pub service_revision: u64,
    pub binding_epoch: u64,
    pub protocol: SpaceServiceProtocol,
    pub port: u16,
    pub revoked: bool,
    pub rules: Vec<SpaceServiceRuleView>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpaceServicePolicyView {
    pub space: SpaceView,
    pub bindings: Vec<SpaceServiceBindingView>,
}
