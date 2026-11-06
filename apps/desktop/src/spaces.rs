//! A view over the daemon's sole account actor; this panel owns no SDK.
use crate::{DesktopApp, icons, widgets};
use eframe::egui;
use nestlink_app_core::{
    Action, OperationResult, OperationStatus, RemoteEffect, Snapshot, SpaceAction, SpacePageCursor,
};
use nestlink_app_ipc::wire::{Command, SensitiveReply};
use nestlink_auth::Secret;
use nestlink_protocol::{network::SpaceRole, spaces::*};
use zeroize::{Zeroize, Zeroizing};
mod network;
mod services;

struct Pending {
    submission: u64,
    generation: u64,
    runtime: String,
    context: String,
    invitation: bool,
}

pub(crate) struct SpacePanel {
    context: String,
    selected: Option<String>,
    tab: usize,
    create_dialog: u8,
    cursor: SpacePageCursor,
    name: String,
    account: String,
    installation: String,
    role: SpaceRole,
    invitation_target: String,
    invitation_minutes: u32,
    incoming: Zeroizing<String>,
    issued: Zeroizing<String>,
    pending: Option<Pending>,
    confirmation: Option<(String, SpaceAction)>,
    message: Option<String>,
    service: services::ServiceDraft,
    network: network::NetworkDraft,
}
impl Default for SpacePanel {
    fn default() -> Self {
        Self {
            context: String::new(),
            tab: 0,
            create_dialog: 0,
            selected: None,
            cursor: Default::default(),
            name: String::new(),
            account: String::new(),
            installation: String::new(),
            role: SpaceRole::Member,
            invitation_target: String::new(),
            invitation_minutes: 60,
            incoming: Zeroizing::new(String::new()),
            issued: Zeroizing::new(String::new()),
            pending: None,
            confirmation: None,
            message: None,
            service: Default::default(),
            network: Default::default(),
        }
    }
}

fn t(english: bool, zh: &'static str, en: &'static str) -> &'static str {
    if english { en } else { zh }
}
fn role_name(role: SpaceRole, english: bool) -> &'static str {
    match role {
        SpaceRole::Owner => t(english, "所有者", "Owner"),
        SpaceRole::Admin => t(english, "管理员", "Admin"),
        SpaceRole::Member => t(english, "成员", "Member"),
        SpaceRole::Guest => t(english, "访客", "Guest"),
    }
}

fn space_card(
    ui: &mut egui::Ui,
    space: &SpaceView,
    selected: bool,
    english: bool,
    width: f32,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 132.), egui::Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            ui.is_enabled(),
            selected,
            &space.name,
        )
    });
    let accent = ui.visuals().hyperlink_color;
    let highlighted = selected || response.hovered() || response.has_focus();
    ui.painter().rect(
        rect,
        12.,
        if highlighted {
            ui.visuals().selection.bg_fill.gamma_multiply(0.09)
        } else {
            ui.visuals().window_fill
        },
        egui::Stroke::new(
            1.,
            if highlighted {
                accent.gamma_multiply(0.4)
            } else {
                ui.visuals().widgets.noninteractive.bg_stroke.color
            },
        ),
        egui::StrokeKind::Inside,
    );
    let painter = ui.painter().with_clip_rect(rect.shrink(16.));
    icons::paint(
        ui,
        icons::Icon::Spaces,
        rect.min + egui::vec2(28., 30.),
        22.,
        accent,
    );
    painter.text(
        rect.min + egui::vec2(16., 66.),
        egui::Align2::LEFT_CENTER,
        &space.name,
        egui::FontId::proportional(14.),
        ui.visuals().text_color(),
    );
    painter.text(
        rect.min + egui::vec2(16., 104.),
        egui::Align2::LEFT_CENTER,
        role_name(space.role, english),
        egui::FontId::proportional(11.),
        accent,
    );
    response.on_hover_text(&space.name)
}
fn invitation_parts(value: &str) -> Option<(String, String, Secret)> {
    let (_, fragment) = value.trim().split_once("#space-invite=")?;
    let mut parts = fragment.split('.');
    let space = parts.next()?;
    let invitation = parts.next()?;
    let token = parts.next()?;
    if parts.next().is_some()
        || !nestlink_protocol::valid_id(space)
        || !nestlink_protocol::valid_id(invitation)
        || token.len() != 43
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return None;
    }
    Some((
        space.into(),
        invitation.into(),
        Secret::from_text(token.into()),
    ))
}

impl SpacePanel {
    #[cfg(test)]
    pub(crate) fn select_review_space(&mut self, snapshot: &Snapshot) {
        self.context = snapshot.space_context.clone();
        self.selected = snapshot
            .selected_space
            .data
            .as_ref()
            .map(|v| v.space.space_id.clone());
    }

    pub(crate) fn context_matches(&self, snapshot: &Snapshot) -> bool {
        self.context == snapshot.space_context
    }
    pub(crate) fn close(&mut self) {
        self.incoming.zeroize();
        self.issued.zeroize();
        self.confirmation = None;
        self.pending = None;
        self.network = Default::default();
    }

    pub(crate) fn disconnected(&mut self) {
        self.close();
        self.message = Some(
            "连接已中断，请重新读取空间。 / Connection interrupted; read the space again.".into(),
        );
    }

    pub(crate) fn rejected(&mut self, submission: Option<u64>) {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| Some(pending.submission) == submission)
        {
            self.disconnected();
        }
    }

    pub(crate) fn completed(
        &mut self,
        submission: Option<u64>,
        runtime: Option<&str>,
        result: &OperationResult,
        sensitive: Option<SensitiveReply>,
        origin: Option<&str>,
    ) {
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        if submission != Some(pending.submission)
            || result.generation != pending.generation
            || runtime != Some(pending.runtime.as_str())
            || pending.context != self.context
        {
            return;
        }
        if pending.invitation
            && result.remote_effect == RemoteEffect::Committed
            && let Some(origin) = origin
            && let Some(SensitiveReply::SpaceInvitation {
                space_id,
                invitation_id,
                token,
            }) = sensitive
            && self.selected.as_deref() == Some(space_id.as_str())
        {
            self.issued = Zeroizing::new(format!(
                "{}/#space-invite={space_id}.{invitation_id}.{}",
                origin.trim_end_matches('/'),
                token.expose()
            ));
        }
        self.pending = None;
        if result.status == OperationStatus::Succeeded {
            if let nestlink_app_core::PublicOutput::Created { id } = &result.output {
                self.selected = Some(id.clone());
                self.name.clear();
            }
            self.message = Some(
                "操作完成，已读取确认状态。 / Operation complete; confirmed state loaded.".into(),
            );
        } else {
            self.message = Some(widgets::operation_message(result, false));
        }
    }

    fn command(&mut self, action: SpaceAction) -> Command {
        if action.selects_space() {
            self.context = uuid::Uuid::new_v4().to_string();
            self.selected = action.space_id().map(str::to_owned);
            self.issued.zeroize();
            self.service = Default::default();
            self.network = Default::default();
        }
        if matches!(&action, SpaceAction::Accept { .. }) {
            self.incoming.zeroize();
        }
        Command::Submit {
            action: Action::Space {
                context: self.context.clone(),
                action,
            },
        }
    }

    fn show(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &Snapshot,
        english: bool,
        runtime: Option<&str>,
    ) -> Option<Command> {
        let mut action = None;
        let mut network_command = None;
        let mut confirmation = None;
        let busy = self.pending.is_some();
        ui.horizontal_top(|ui| {
            let heading_width = (ui.available_width() - 230.).max(180.);
            ui.allocate_ui_with_layout(egui::vec2(heading_width, 1.), egui::Layout::top_down(egui::Align::Min), |ui| {
                widgets::page_heading(
                    ui,
                    t(english, "网络空间", "Network spaces"),
                    t(
                        english,
                        "管理多设备的私有组网、空间成员与服务访问权限。",
                        "Manage private networking, space membership and service grants.",
                    ),
                );
            });
            ui.add_enabled_ui(!busy && self.confirmation.is_none(), |ui| {
                if ui.button(t(english, "加入空间", "Join space")).clicked() {
                    self.create_dialog = 2;
                }
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new(t(english, "创建空间", "Create space"))
                                .color(ui.visuals().selection.stroke.color),
                        )
                        .fill(ui.visuals().selection.bg_fill),
                    )
                    .clicked()
                {
                    self.create_dialog = 1;
                }
            });
        });
        widgets::notice(
            ui,
            t(
                english,
                "网络空间用于多设备组网和成员授权。当前账号的登录设备请在「设备管理」查看。",
                "Spaces organize private networks and member grants. Account logins are managed in Login devices.",
            ),
        );
        ui.add_space(16.);
        if let Some(message) = &self.message {
            ui.label(message);
        }
        ui.add_enabled_ui(!busy && self.confirmation.is_none(), |ui| {
            if self.create_dialog!=0 {
                let context=ui.ctx().clone();
                let response=egui::Modal::new(egui::Id::new("space-create-join")).frame(widgets::modal_frame(&context)).show(&context,|ui|{
                    ui.set_width(440_f32.min(context.content_rect().width()-64.));
                    ui.heading(match self.create_dialog { 1 => t(english,"创建空间","Create space"), 3 => t(english,"添加空间设备","Add a space device"), _ => t(english,"加入空间","Join space") });
                    let mut submission = None;
                    let mut submit_label = t(english, "创建空间", "Create space");
                    if self.create_dialog == 1 {
                        widgets::field(ui, t(english, "空间名称", "Space name"), &mut self.name, 80);
                        if !self.name.trim().is_empty() {
                            submission = Some(SpaceAction::Create { name: self.name.trim().into() });
                        }
                    } else if self.create_dialog == 2 {
                        submit_label = t(english, "接受邀请", "Accept invitation");
                        widgets::secret_field(ui, t(english, "一次性邀请链接", "One-use invitation link"), &mut self.incoming, "space-invitation", snapshot.generation, 2048);
                        if let Some((space_id, invitation_id, token)) = invitation_parts(&self.incoming) {
                            submission = Some(SpaceAction::Accept { space_id, invitation_id, token });
                        }
                    } else if let Some(details) = snapshot.selected_space.data.as_ref().filter(|details| self.context == snapshot.space_context && self.selected.as_deref() == Some(details.space.space_id.as_str()) && !details.space.archived) {
                        submit_label = t(english, "加入或重新加入设备", "Join or rejoin device");
                        ui.label(t(english, "选择已登记设备。加入空间不会自动授予远控或文件权限。", "Choose a registered device. Space membership does not grant desktop or file access."));
                        if let Some(devices) = &snapshot.devices.data {
                            egui::ComboBox::from_id_salt("space-join-device").selected_text(devices.iter().find(|device| device.device.id == self.installation).map(|device| device.device.name.as_str()).unwrap_or(t(english, "选择已登记设备", "Choose a registered device"))).show_ui(ui, |ui| {
                                for device in devices.iter().filter(|device| !device.revoked) { ui.selectable_value(&mut self.installation, device.device.id.clone(), &device.device.name); }
                            });
                            if devices.iter().any(|device| device.device.id == self.installation && !device.revoked) {
                                let epoch = details.devices.iter().find(|device| device.installation_id == self.installation).map_or(0, |device| device.membership_epoch);
                                submission = Some(SpaceAction::JoinDevice { space_id: details.space.space_id.clone(), request: SpaceDeviceJoin { expected_revision: details.space.revision, expected_membership_epoch: epoch, installation_id: self.installation.clone() } });
                            }
                        }
                    }
                    ui.add_space(18.);
                    ui.separator();
                    ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), 42.), egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if widgets::action_button(ui, submit_label, submission.is_some()).clicked() {
                            self.cursor = Default::default();
                            action = submission;
                            self.create_dialog = 0;
                            self.incoming.zeroize();
                        }
                        if ui.button(t(english, "取消", "Cancel")).clicked() { self.create_dialog = 0; self.incoming.zeroize(); }
                    });
                });if response.should_close(){self.create_dialog=0;self.incoming.zeroize();}
            }
            let sidebar_width=if ui.available_width()>900. {234.} else {156.};
            let detail_width=(ui.available_width()-sidebar_width-16.).max(260.);
            ui.horizontal_top(|ui|{
                ui.spacing_mut().item_spacing.x = 16.;
                ui.vertical(|ui|{
                    ui.set_width(sidebar_width);
                    ui.horizontal(|ui| {
                        ui.strong(t(english, "我的空间", "My spaces"));
                        if icons::tool_button(ui, icons::Icon::Refresh, t(english, "读取我的空间", "Read my spaces")).clicked() { self.cursor = Default::default(); action = Some(SpaceAction::List); }
                    });
                    if let Some(spaces)=&snapshot.spaces.data {
                        for space in spaces.iter(){
                            if space_card(ui, space, self.selected.as_deref()==Some(space.space_id.as_str()), english, sidebar_width).clicked(){self.cursor=Default::default();action=Some(SpaceAction::Read{space_id:space.space_id.clone(),cursor:self.cursor.clone()});}
                        }
                    }
                    widgets::section(ui, &snapshot.spaces, english);
                });
                ui.vertical(|ui|{ui.set_width(detail_width);widgets::surface(ui).show(ui,|ui|{
            ui.set_min_width(ui.available_width());
            let details = snapshot.selected_space.data.as_ref().filter(|details| self.context == snapshot.space_context
                && self.selected.as_deref() == Some(details.space.space_id.as_str()));
            if let Some(details) = details {
                let space = &details.space;
                let manager = matches!(space.role, SpaceRole::Owner | SpaceRole::Admin);
                ui.horizontal(|ui| {
                    let (badge, _) = ui.allocate_exact_size(egui::vec2(44., 44.), egui::Sense::hover());
                    ui.painter().rect_filled(badge, 10., ui.visuals().selection.bg_fill.gamma_multiply(0.1));
                    icons::paint(ui, icons::Icon::Spaces, badge.center(), 24., ui.visuals().hyperlink_color);
                    ui.allocate_ui_with_layout(egui::vec2((ui.available_width()-48.).max(100.), 44.), egui::Layout::top_down(egui::Align::Min), |ui| {
                        ui.add(egui::Label::new(egui::RichText::new(&space.name).size(20.).strong()).truncate()).on_hover_text(&space.name);
                        ui.small(role_name(space.role, english));
                    });
                    if icons::tool_button(ui, icons::Icon::Refresh, t(english, "重新读取当前空间", "Reload selected space")).clicked() {
                        self.cursor = Default::default(); action = Some(SpaceAction::Read { space_id: space.space_id.clone(), cursor: self.cursor.clone() });
                    }
                });
                ui.add_space(16.);
                ui.horizontal_wrapped(|ui|{for (index,zh,en) in [(0,"空间设备","Space devices"),(1,"空间成员","Members"),(2,"受管网络","Managed networks"),(3,"服务授权","Service grants")]{if widgets::tab(ui,self.tab==index,t(english,zh,en)).clicked(){self.tab=index;}}});
                ui.separator();
                ui.add_enabled_ui(!space.archived, |ui| {
                    if self.tab==2 { network_command = self.network.show(ui, snapshot, details, english, runtime); }
                    if self.tab==0 {
                        ui.horizontal(|ui| {
                            ui.strong(format!("{}  {}", t(english,"空间设备","Space devices"), details.devices.len()));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button(t(english,"添加设备","Add device")).clicked(){ self.create_dialog = 3; }
                            });
                        });
                        ui.add_space(10.);
                        for device in &details.devices {
                            ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), 68.), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                ui.set_min_height(68.);
                                let (badge, _) = ui.allocate_exact_size(egui::vec2(40., 40.), egui::Sense::hover());
                                ui.painter().rect_filled(badge, 9., ui.visuals().faint_bg_color);
                                icons::paint(ui, icons::Icon::Monitor, badge.center(), 22., ui.visuals().weak_text_color());
                                ui.allocate_ui_with_layout(egui::vec2((ui.available_width()-140.).max(80.), 44.), egui::Layout::top_down(egui::Align::Min), |ui| {
                                    ui.add(egui::Label::new(egui::RichText::new(&device.name).strong()).truncate()).on_hover_text(&device.name);
                                    ui.small(format!("{} · {}", role_name(device.role, english), if device.active { t(english, "成员关系有效", "Active membership") } else { t(english, "已撤销", "Revoked") }));
                                });
                                if ui.add_enabled(device.active, egui::Button::new(t(english, "移除", "Remove"))).clicked() {
                                    confirmation = Some((format!("{} {}?", t(english, "从空间移除设备", "Remove device from this space"), device.name), SpaceAction::RemoveDevice { space_id: space.space_id.clone(), installation_id: device.installation_id.clone(), request: SpaceDeviceRemoval { expected_revision: space.revision, expected_membership_epoch: device.membership_epoch } }));
                                }
                            });
                            ui.separator();
                        }
                        if let Some(next) = &details.next_device
                            && ui.button(t(english, "下一页设备", "Next devices")).clicked() {
                            self.cursor.after_device = Some(next.clone()); action = Some(SpaceAction::Read { space_id: space.space_id.clone(), cursor: self.cursor.clone() });
                        }
                    }
                    if self.tab==1 { ui.strong(t(english,"空间成员","Members"));
                        for member in &details.members { ui.label(format!("{} · {} · {}", member.name, role_name(member.role, english), if member.active { t(english, "有效", "active") } else { t(english, "已移除", "removed") })); }
                        if manager {
                            egui::ComboBox::from_id_salt("space-member").selected_text(details.members.iter().find(|member| member.account_id == self.account).map(|member| member.name.as_str()).unwrap_or(t(english, "选择成员", "Choose member"))).show_ui(ui, |ui| {
                                for member in &details.members { ui.selectable_value(&mut self.account, member.account_id.clone(), &member.name); }
                            });
                            egui::ComboBox::from_id_salt("space-role").selected_text(role_name(self.role, english)).show_ui(ui, |ui| {
                                for role in [SpaceRole::Member, SpaceRole::Guest, SpaceRole::Admin, SpaceRole::Owner] {
                                    if space.role == SpaceRole::Owner || matches!(role, SpaceRole::Member | SpaceRole::Guest) { ui.selectable_value(&mut self.role, role, role_name(role, english)); }
                                }
                            });
                            if let Some(member) = details.members.iter().find(|member| member.account_id == self.account) {
                                if ui.button(t(english, "保存角色", "Save role")).clicked() {
                                    let operation = SpaceAction::UpdateMember { space_id: space.space_id.clone(), account_id: member.account_id.clone(), request: SpaceMemberUpdate { expected_revision: space.revision, expected_member_epoch: member.member_epoch, role: self.role } };
                                    confirmation = Some((format!("{} {} → {}?", t(english, "修改成员角色", "Change member role"), member.name, role_name(self.role, english)), operation));
                                }
                                if ui.add_enabled(member.active && member.role != SpaceRole::Owner, egui::Button::new(t(english, "移除成员及其空间设备", "Remove member and their space devices"))).clicked() {
                                    confirmation = Some((format!("{} {}?", t(english, "移除成员及其空间设备", "Remove member and their space devices"), member.name), SpaceAction::RemoveMember { space_id: space.space_id.clone(), account_id: member.account_id.clone(), request: SpaceMemberRemoval { expected_revision: space.revision, expected_member_epoch: member.member_epoch } }));
                                }
                            }
                        }
                        if let Some(next) = &details.next_member
                            && ui.button(t(english, "下一页成员", "Next members")).clicked() {
                            self.cursor.after_member = Some(next.clone()); action = Some(SpaceAction::Read { space_id: space.space_id.clone(), cursor: self.cursor.clone() });
                        }
                    }
                    if manager && self.tab==1 {
                        egui::CollapsingHeader::new(t(english, "一次性邀请", "One-use invitations")).show(ui, |ui| {
                            ui.label(t(english, "邀请使用上面选择的角色；所有者不能通过邀请授予。", "Invitations use the role selected above; ownership cannot be granted by invitation."));
                            widgets::field(ui, t(english, "限定账号编号（可选）", "Restrict to account ID (optional)"), &mut self.invitation_target, 36);
                            ui.add(egui::Slider::new(&mut self.invitation_minutes, 1..=1440).text(t(english, "有效分钟", "minutes")));
                            let valid_target = self.invitation_target.trim().is_empty() || nestlink_protocol::valid_id(self.invitation_target.trim());
                            if ui.add_enabled(valid_target && self.role != SpaceRole::Owner, egui::Button::new(t(english, "生成一次性邀请", "Create one-use invitation"))).clicked()
                                && let Some(end) = space.observed_at_unix_ms.checked_add(u64::from(self.invitation_minutes) * 60_000) {
                                action = Some(SpaceAction::Invite { space_id: space.space_id.clone(), request: SpaceInvitationRequest { expected_revision: space.revision, role: self.role, target_account_id: (!self.invitation_target.trim().is_empty()).then(|| self.invitation_target.trim().into()), expires_at_unix_ms: end } });
                            }
                            for invitation in &details.invitations {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(format!("{} · {} · {}", role_name(invitation.role, english), invitation.expires_at_unix_ms, if invitation.revoked { "revoked" } else if invitation.consumed { "consumed" } else { "pending" }));
                                    if ui.add_enabled(!invitation.revoked && !invitation.consumed, egui::Button::new(t(english, "撤销邀请", "Revoke invitation"))).clicked() {
                                        action = Some(SpaceAction::RevokeInvitation { space_id: space.space_id.clone(), invitation_id: invitation.invitation_id.clone(), request: SpaceRevisionRequest { expected_revision: space.revision } });
                                    }
                                });
                            }
                            if let Some(next) = &details.next_invitation
                                && ui.button(t(english, "下一页邀请", "Next invitations")).clicked() {
                                self.cursor.after_invitation = Some(next.clone()); action = Some(SpaceAction::Read { space_id: space.space_id.clone(), cursor: self.cursor.clone() });
                            }
                        });
                    }
                    if self.tab==3 { self.service.show(ui, snapshot, details, english, &mut action, &mut confirmation); }
                });
                ui.add_space(16.);
                egui::CollapsingHeader::new(t(english, "空间身份、管理与审计", "Space identity, administration and audit")).show(ui, |ui| {
                    ui.small(format!("revision {} · policy {}", space.revision, space.policy_epoch));
                    ui.label(format!("{}: {}", t(english, "部署", "Deployment"), space.deployment_id));
                    ui.label(format!("{}: {}", t(english, "空间", "Space"), space.space_id));
                    ui.label(format!("{}: {}", t(english, "空间公钥", "Space public key"), space.authority_public_key));
                    ui.small(t(english, "请与管理员通过可信渠道核验此公钥。读取目录不会修改本机批准的空间公钥或网络范围。", "Verify this key with the administrator through a trusted channel. Reading the directory does not change this device's approved space key or network scope."));
                    if ui.add_enabled(!space.archived && space.role == SpaceRole::Owner, egui::Button::new(t(english, "归档空间", "Archive space"))).clicked() {
                        confirmation = Some((t(english, "归档此空间并撤销全部空间设备和邀请？", "Archive this space and revoke all space devices and invitations?").into(), SpaceAction::Archive { space_id: space.space_id.clone(), request: SpaceRevisionRequest { expected_revision: space.revision } }));
                    }
                    if manager {
                    if ui.button(t(english, "读取最近 100 条空间审计", "Read latest 100 space audit entries")).clicked() { action = Some(SpaceAction::Audit { space_id: space.space_id.clone() }); }
                    widgets::section(ui, &snapshot.space_audit, english);
                    if let Some(audit) = &snapshot.space_audit.data { for entry in audit.iter() { ui.small(format!("{} · {} · {}", entry.sequence, entry.action, entry.at_unix_ms)); } }
                    }
                });
            }
            widgets::section(ui, &snapshot.selected_space, english);
                });});
            });
        });
        ui.add_space(12.);
        ui.small(t(
            english,
            "加入空间不会自动获得远控、文件或服务访问权限。",
            "Joining a space does not automatically grant desktop, file or service access.",
        ));
        if !self.issued.is_empty() {
            ui.separator();
            ui.label(t(english, "邀请已准备好。请复制并妥善交付；离开页面后无法再次读取令牌。", "Your invitation is ready. Copy and deliver it securely; its token cannot be read again after leaving this page."));
            ui.horizontal(|ui| {
                if ui
                    .button(t(english, "复制邀请链接", "Copy invitation link"))
                    .clicked()
                {
                    ui.ctx().copy_text(self.issued.as_str().to_owned());
                }
                if ui.button(t(english, "清除此链接", "Clear link")).clicked() {
                    self.issued.zeroize();
                }
            });
        }
        if let Some(value) = confirmation {
            self.confirmation = Some(value);
        }
        if let Some((message, _)) = &self.confirmation {
            let mut yes = false;
            let mut no = false;
            egui::Modal::new(egui::Id::new("space-confirmation")).frame(widgets::modal_frame(ui.ctx())).show(ui.ctx(), |ui| {
                ui.heading(t(english, "确认空间操作", "Confirm space operation"));
                ui.label(message);
                ui.horizontal(|ui| {
                    yes = ui.button(t(english, "确认", "Confirm")).clicked();
                    no = ui.button(t(english, "取消", "Cancel")).clicked();
                });
            });
            if yes {
                action = self.confirmation.take().map(|(_, action)| action);
            }
            if no || ui.ctx().input(|input| input.key_pressed(egui::Key::Escape)) {
                self.confirmation = None;
            }
        }
        network_command.or_else(|| action.map(|action| self.command(action)))
    }
}

impl DesktopApp {
    pub(crate) fn spaces_page(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        let runtime = self.bridge.runtime_id();
        if let Some(command) = self
            .space_panel
            .show(ui, snapshot, self.english, runtime.as_deref())
        {
            let invitation = matches!(
                &command,
                Command::Submit {
                    action: Action::Space {
                        action: SpaceAction::Invite { .. },
                        ..
                    }
                }
            );
            if let (Some(submission), Some(runtime)) = (
                self.bridge.submit_tracked(snapshot.generation, command),
                self.bridge.runtime_id(),
            ) {
                self.space_panel.pending = Some(Pending {
                    submission,
                    runtime,
                    generation: snapshot.generation,
                    context: self.space_panel.context.clone(),
                    invitation,
                });
            } else {
                self.space_panel.disconnected();
            }
        }
    }
}
