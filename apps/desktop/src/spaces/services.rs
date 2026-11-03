use super::*;
use nestlink_protocol::{api::ServiceApprovalState, spaces::service_publication::*};

pub(super) struct ServiceDraft {
    owned: String,
    after_service: Option<String>,
    after_rule: Option<String>,
    by_device: bool,
    minutes: u32,
}
impl Default for ServiceDraft {
    fn default() -> Self { Self { owned: String::new(), after_service: None, after_rule: None, by_device: false, minutes: 60 } }
}
impl ServiceDraft {
    pub(super) fn show(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot, details: &nestlink_app_core::SpaceDetailsPage, english: bool,
        action: &mut Option<SpaceAction>, confirmation: &mut Option<(String, SpaceAction)>) {
        let space = &details.space;
        let manager = matches!(space.role, SpaceRole::Owner | SpaceRole::Admin);
        egui::CollapsingHeader::new(t(english, "服务发布授权", "Service publication rights")).show(ui, |ui| {
            ui.label(t(english, "服务所有者先绑定获本机批准的目标，空间管理员再授权发布。成员身份不授予任意本机端口或服务访问权。", "The service owner first binds a locally approved target, then a space administrator permits publication. Membership does not grant access to arbitrary local ports or services."));
            if ui.button(t(english, "读取发布规则", "Read publication rules")).clicked() {
                self.after_service = None; self.after_rule = None;
                *action = Some(SpaceAction::Services { space_id: space.space_id.clone(), after_service: None, selected_service: None, after_rule: None });
            }
            widgets::section(ui, &snapshot.space_services, english);
            let Some(policy) = snapshot.space_services.data.as_ref().filter(|policy| policy.space.space_id == space.space_id) else { return; };
            if let Some(services) = &snapshot.services.data {
                egui::ComboBox::from_id_salt("space-owned-service").selected_text(services.services.iter().find(|service| service.id == self.owned).map(|service| service.definition.name.as_str()).unwrap_or(t(english, "选择已批准服务", "Choose an approved service"))).show_ui(ui, |ui| {
                    for service in services.services.iter().filter(|service| service.approval == ServiceApprovalState::ApprovedTarget) {
                        ui.selectable_value(&mut self.owned, service.id.clone(), &service.definition.name);
                    }
                });
                if let Some(service) = services.services.iter().find(|service| service.id == self.owned && service.approval == ServiceApprovalState::ApprovedTarget)
                    && ui.button(t(english, "绑定并等待发布授权", "Bind and await publication permission")).clicked() {
                    *action = Some(SpaceAction::BindService { space_id: space.space_id.clone(), service_id: service.id.clone(), request: SpaceServiceBindingRequest { expected_revision: policy.space.revision, expected_service_revision: service.revision } });
                }
                if services.next_id.is_some() {
                    ui.small(t(english, "此处显示当前服务页；请在内网穿透页面读取其他服务页后返回。", "This shows the current services page. Load another page in Tunnels to select additional services."));
                }
            }
            for binding in &policy.bindings {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("{:?}/{} · {}", binding.protocol, binding.port, if binding.revoked { "revoked" } else { "bound" }));
                    let name = snapshot.services.data.as_ref().and_then(|services| services.services.iter().find(|service| service.id == binding.service_id)).map(|service| service.definition.name.as_str()).unwrap_or(&binding.service_id);
                    if ui.button(format!("{} {name}", t(english, "查看", "Inspect"))).clicked() {
                        self.after_rule = None;
                        *action = Some(SpaceAction::Services { space_id: space.space_id.clone(), after_service: self.after_service.clone(), selected_service: Some(binding.service_id.clone()), after_rule: None });
                    }
                });
            }
            if let Some(next) = &policy.next_service
                && ui.button(t(english, "下一页绑定", "Next bindings")).clicked() {
                self.after_service = Some(next.clone()); self.after_rule = None;
                *action = Some(SpaceAction::Services { space_id: space.space_id.clone(), after_service: self.after_service.clone(), selected_service: None, after_rule: None });
            }
            if let Some(binding) = &policy.selected {
                ui.separator();
                ui.label(format!("{:?}/{} · {}", binding.protocol, binding.port, binding.service_id));
                if ui.add_enabled(!binding.revoked, egui::Button::new(t(english, "撤销绑定并停止发布", "Revoke binding and stop publication"))).clicked() {
                    *confirmation = Some((t(english, "撤销此服务绑定并停止发布？", "Revoke this binding and stop publication?").into(), SpaceAction::RevokeService { space_id: space.space_id.clone(), service_id: binding.service_id.clone(), request: SpaceRevisionRequest { expected_revision: policy.space.revision } }));
                }
                if manager && !binding.revoked {
                    ui.checkbox(&mut self.by_device, t(english, "仅授权该服务的精确宿主设备（否则为服务所有者账号）", "Authorize this service's exact host device (otherwise its owner account)"));
                    ui.add(egui::Slider::new(&mut self.minutes, 1..=10080).text(t(english, "发布授权分钟数", "publication minutes")));
                    if ui.button(t(english, "明确授权此协议与端口发布", "Allow publication on this protocol and port")).clicked()
                        && let Some(end) = policy.space.observed_at_unix_ms.checked_add(u64::from(self.minutes) * 60_000) {
                        let subject = if self.by_device { SpaceServiceSubject::Device { installation_id: binding.host_device_id.clone() } } else { SpaceServiceSubject::Account { account_id: binding.account_id.clone() } };
                        *action = Some(SpaceAction::GrantServiceRule { space_id: space.space_id.clone(), service_id: binding.service_id.clone(), request: SpaceServiceRuleRequest { expected_revision: policy.space.revision, expected_binding_epoch: binding.binding_epoch, subject, protocol: binding.protocol, port: binding.port, operation: SpaceServiceOperation::Publish, expires_at_unix_ms: end } });
                    }
                }
                for rule in &binding.rules {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!("{:?}/{} · {} · {}", rule.protocol, rule.port, rule.expires_at_unix_ms, if rule.active { "active" } else { "inactive" }));
                        if manager && ui.add_enabled(!rule.revoked, egui::Button::new(t(english, "撤销规则并停止发布", "Revoke rule and stop publication"))).clicked() {
                            *action = Some(SpaceAction::RevokeServiceRule { space_id: space.space_id.clone(), service_id: binding.service_id.clone(), rule_id: rule.rule_id.clone(), request: SpaceRevisionRequest { expected_revision: policy.space.revision } });
                        }
                    });
                }
                if let Some(next) = &policy.next_rule
                    && ui.button(t(english, "下一页规则", "Next rules")).clicked() {
                    self.after_rule = Some(next.clone());
                    *action = Some(SpaceAction::Services { space_id: space.space_id.clone(), after_service: self.after_service.clone(), selected_service: Some(binding.service_id.clone()), after_rule: self.after_rule.clone() });
                }
            }
        });
    }
}
