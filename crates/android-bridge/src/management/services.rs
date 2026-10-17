//! Service metadata only. This module grants neither a local target nor a listener.
use super::AndroidManagementSession;
use nestlink_app_core::{Action, OperationResult, Section, Snapshot};
use nestlink_protocol::api::{ServiceCreate, ServicePage, ServiceUpdate, ServiceView};
use serde::{Deserialize, Serialize};

const MAX_SERVICE_ACTION_BYTES: usize = 24 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceContext {
    generation: u64,
    account_id: String,
    session_id: String,
}
impl ServiceContext {
    fn from_snapshot(snapshot: &Snapshot) -> Result<Self, String> {
        let principal = snapshot
            .principal
            .as_ref()
            .ok_or_else(|| "请重新登录后读取服务列表。".to_owned())?;
        Ok(Self {
            generation: snapshot.generation,
            account_id: principal.account_id.clone(),
            session_id: principal.session_id.clone(),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceRequest {
    context: Option<ServiceContext>,
    command: ServiceCommand,
}
#[derive(Deserialize)]
#[serde(
    tag = "action",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ServiceCommand {
    LoadServicesPage {
        after_id: Option<String>,
        limit: u16,
    },
    InspectService {
        service_id: String,
    },
    CreateService {
        create: ServiceCreate,
    },
    UpdateService {
        service_id: String,
        update: ServiceUpdate,
    },
    RevokeService {
        service_id: String,
        expected_revision: u64,
    },
}
impl ServiceCommand {
    fn requires_context(&self) -> bool {
        !matches!(self, Self::LoadServicesPage { after_id: None, .. })
    }
    fn into_action(self) -> Action {
        match self {
            Self::LoadServicesPage { after_id, limit } => {
                Action::LoadServicesPage { after_id, limit }
            }
            Self::InspectService { service_id } => Action::InspectService { service_id },
            Self::CreateService { create } => Action::CreateService { create },
            Self::UpdateService { service_id, update } => {
                Action::UpdateService { service_id, update }
            }
            Self::RevokeService {
                service_id,
                expected_revision,
            } => Action::RevokeService {
                service_id,
                expected_revision,
            },
        }
    }
}

fn parse_request(json: &str) -> Result<ServiceRequest, String> {
    if json.len() > MAX_SERVICE_ACTION_BYTES {
        return Err("服务配置超过大小限制。".to_owned());
    }
    let request: ServiceRequest =
        serde_json::from_str(json).map_err(|_| "服务配置格式无效。".to_owned())?;
    if request.context.is_none() && request.command.requires_context() {
        return Err("请先刷新服务列表，再提交配置。".to_owned());
    }
    Ok(request)
}

#[derive(Serialize)]
struct ServiceResponse<'a> {
    context: ServiceContext,
    snapshot_revision: u64,
    services: &'a Section<ServicePage>,
    selected_service: &'a Section<ServiceView>,
    operation: &'a OperationResult,
}

impl AndroidManagementSession {
    pub(crate) fn service_context_json(&self) -> Result<String, String> {
        let context = ServiceContext::from_snapshot(&self.handle.snapshot())?;
        serde_json::to_string(&context)
            .map_err(|_| "账号会话上下文无法读取，请重新登录。".to_owned())
    }

    pub(crate) fn service_action_json(&self, json: &str) -> Result<String, String> {
        let request = parse_request(json)?;
        let before = self.handle.snapshot();
        let context = ServiceContext::from_snapshot(&before)?;
        if request
            .context
            .as_ref()
            .is_some_and(|expected| *expected != context)
        {
            return Err("账号会话已变化，请刷新服务列表后重试。".to_owned());
        }
        let ticket = self
            .handle
            .submit_for_generation(context.generation, request.command.into_action())
            .map_err(|_| "Rust Core 未接受服务操作，请检查输入并刷新列表。".to_owned())?;
        let completion = self
            .runtime
            .block_on(ticket.wait())
            .map_err(|_| "服务操作尚未确认，请保留草稿并刷新列表。".to_owned())?;
        let snapshot = self.handle.snapshot();
        if !completion.is_current()
            || completion.result.generation != context.generation
            || ServiceContext::from_snapshot(&snapshot)? != context
        {
            return Err("账号会话已变化，请刷新服务列表后确认结果。".to_owned());
        }
        // A failed refresh can follow a committed mutation. Retain its actual
        // OperationResult, effect and selected record rather than inventing success.
        serde_json::to_string(&ServiceResponse {
            context,
            snapshot_revision: snapshot.revision,
            services: &snapshot.services,
            selected_service: &snapshot.selected_service,
            operation: &completion.result,
        })
        .map_err(|_| "服务响应无法读取，请刷新列表确认结果。".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT: &str = r#"{"generation":7,"account_id":"account-a","session_id":"session-a"}"#;

    #[test]
    fn only_a_first_page_can_bootstrap_without_context() {
        assert!(parse_request(r#"{"context":null,"command":{"action":"load_services_page","parameters":{"after_id":null,"limit":25}}}"#).is_ok());
        for command in [
            r#"{"action":"load_services_page","parameters":{"after_id":"cursor","limit":25}}"#,
            r#"{"action":"inspect_service","parameters":{"service_id":"svc"}}"#,
            r#"{"action":"revoke_service","parameters":{"service_id":"svc","expected_revision":1}}"#,
        ] {
            assert!(parse_request(&format!(r#"{{"context":null,"command":{command}}}"#)).is_err());
            assert!(
                parse_request(&format!(r#"{{"context":{CONTEXT},"command":{command}}}"#)).is_ok()
            );
        }
    }

    #[test]
    fn bridge_rejects_target_publication_account_and_unknown_commands() {
        for action in [
            "approve_service_target",
            "publish_service",
            "start_listener",
            "sign_in",
            "logout",
        ] {
            assert!(
                parse_request(&format!(
                    r#"{{"context":{CONTEXT},"command":{{"action":"{action}","parameters":{{}}}}}}"#
                ))
                .is_err()
            );
        }
        assert!(parse_request(r#"{"context":null,"command":{"action":"load_services_page","parameters":{"after_id":null,"limit":25,"target":"127.0.0.1:22"}}}"#).is_err());
        assert!(parse_request(&" ".repeat(MAX_SERVICE_ACTION_BYTES + 1)).is_err());
    }

    #[test]
    fn service_commands_preserve_exact_ids_and_revision_for_the_core() {
        let request = parse_request(&format!(r#"{{"context":{CONTEXT},"command":{{"action":"revoke_service","parameters":{{"service_id":"service-7","expected_revision":19}}}}}}"#))
            .unwrap_or_else(|error| panic!("valid request: {error}"));
        assert!(
            matches!(request.command.into_action(), Action::RevokeService { service_id, expected_revision: 19 } if service_id == "service-7")
        );
    }
}
