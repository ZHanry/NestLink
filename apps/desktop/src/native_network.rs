//! Local dialing consent, separate from administrator forwarding policy.
use eframe::egui;
use nestlink_app_core::{MediaRouteMode, NativeNetworkError, NativeNetworkSettings, Snapshot};
use nestlink_app_ipc::wire::Command;

#[derive(Default)]
pub(crate) struct NativeNetworkPanel {
    base: Option<(u64, u64)>,
    prefixes: String,
    use_deployment_stun: bool,
    media_route: MediaRouteMode,
    media_interface_index: u32,
    approved: bool,
    pending: bool,
    message: Option<NativeNetworkError>,
}

impl NativeNetworkPanel {
    pub(crate) fn complete(&mut self, result: Result<NativeNetworkSettings, NativeNetworkError>) {
        self.pending = false;
        self.message = result.err();
        if self.message.is_none() {
            self.base = None;
        }
    }

    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &Snapshot,
        english: bool,
    ) -> Option<Command> {
        if self.base.as_ref().is_none_or(|(generation, revision)| {
            *generation != snapshot.generation || *revision != snapshot.native_network_revision
        }) {
            self.base = Some((snapshot.generation, snapshot.native_network_revision));
            self.prefixes = snapshot.native_network.private_network_prefixes.join("\n");
            self.use_deployment_stun = snapshot.native_network.use_deployment_stun;
            self.media_route = snapshot.native_network.media_route;
            self.media_interface_index = snapshot.native_network.media_interface_index.unwrap_or(1);
            self.approved = false;
            self.pending = false;
        }
        let t = |zh, en| if english { en } else { zh };
        let mut command = None;
        egui::CollapsingHeader::new(t("本机直连网络", "Local direct connections"))
            .show(ui, |ui| {
                ui.label(t(
                    "STUN 地址由已核验的控制中心提供。只有下面明确批准的内网可作为本机直连目标；服务器和对方设备不能扩大此范围。",
                    "STUN endpoints come from your verified control center. Only the private networks approved below may be dialed locally; a server or peer cannot extend this consent.",
                ));
                if ui.checkbox(&mut self.use_deployment_stun, t("使用部署提供的 STUN 地址发现", "Use deployment STUN discovery")).changed() {
                    self.approved = false;
                }
                ui.label(t("媒体网络路径", "Media network route"));
                let previous = (self.media_route, self.media_interface_index);
                egui::ComboBox::from_id_salt("media-route-mode").selected_text(match self.media_route {
                    MediaRouteMode::System => t("跟随系统（默认）", "Follow system (default)"),
                    MediaRouteMode::Physical => t("优先物理网卡直连", "Prefer a physical interface"),
                    MediaRouteMode::Interface => t("指定接口", "Select an interface"),
                }).show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.media_route, MediaRouteMode::System, t("跟随系统（默认）", "Follow system (default)"));
                    if cfg!(windows) {
                        ui.selectable_value(&mut self.media_route, MediaRouteMode::Physical, t("优先物理网卡直连", "Prefer a physical interface"));
                        ui.selectable_value(&mut self.media_route, MediaRouteMode::Interface, t("指定接口", "Select an interface"));
                    }
                });
                if self.media_route == MediaRouteMode::Interface {
                    ui.horizontal(|ui| {
                        ui.label(t("接口索引", "Interface index"));
                        ui.add(egui::DragValue::new(&mut self.media_interface_index).range(1..=u32::MAX));
                    });
                }
                if previous != (self.media_route, self.media_interface_index) { self.approved = false; }
                ui.small(t("跟随系统保留现有 VPN 路由；直连选择只作用于本机新建的媒体连接。指定接口不可用时显示连接失败。", "System mode preserves VPN routing. Route selection applies to new local media sockets. An unavailable selected interface causes an explicit connection failure."));
                ui.label(t("批准的内网 CIDR（每行一个）", "Approved private CIDRs (one per line)"));
                if ui.add(egui::TextEdit::multiline(&mut self.prefixes).char_limit(4096).desired_rows(3)
                    .hint_text("192.168.1.0/24\nfd12:3456::/32")).changed() {
                    self.approved = false;
                }
                let settings = NativeNetworkSettings {
                    media_route: self.media_route,
                    media_interface_index: (self.media_route == MediaRouteMode::Interface).then_some(self.media_interface_index),
                    use_deployment_stun: self.use_deployment_stun,
                    private_network_prefixes: self.prefixes.lines().map(str::trim)
                        .filter(|line| !line.is_empty()).map(str::to_owned).collect(),
                };
                let valid = settings.validate().is_ok();
                if !valid {
                    ui.colored_label(ui.visuals().error_fg_color, t(
                        "请输入最多 32 个规范的私有网段，例如 192.168.1.0/24。回环、链路本地、公网和全地址范围不能在此批准。",
                        "Enter up to 32 canonical private subnets, such as 192.168.1.0/24. Loopback, link-local, public and all-address ranges cannot be approved here.",
                    ));
                }
                let changed = settings != snapshot.native_network || snapshot.native_network_durable == Some(false);
                ui.checkbox(&mut self.approved, t("我批准此设备连接上面列出的内网", "I approve this device dialing the private networks listed above"));
                ui.small(t("请先停止当前远控或共享。更改保存后用于后续会话。", "Stop current remote or sharing sessions first. Saved changes apply to subsequent sessions."));
                if ui.add_enabled(valid && changed && self.approved && !self.pending,
                    egui::Button::new(t("保存本机批准", "Save local consent"))).clicked() {
                    self.pending = true;
                    self.message = None;
                    command = Some(Command::ConfigureNativeNetwork { expected_revision: snapshot.native_network_revision, settings });
                }
                if snapshot.native_network_durable == Some(false) {
                    ui.colored_label(ui.visuals().warn_fg_color, t(
                        "更改已生效，但无法确认断电后仍能保留。请再次保存以确认。",
                        "Changes are active, but persistence after power loss is unconfirmed. Save again to confirm.",
                    ));
                }
                if let Some(error) = self.message {
                    let message = match error {
                        NativeNetworkError::Invalid => t("网络设置无效。", "Network settings are invalid."),
                        NativeNetworkError::Busy => t("请先停止当前会话及其清理。", "Stop the current session and wait for cleanup first."),
                        NativeNetworkError::StaleGeneration => t("当前页面已过期，请重新查看设置。", "This view is stale. Review the current settings again."),
                        NativeNetworkError::Unavailable => t("本机网络配置不可用。", "Local network configuration is unavailable."),
                        NativeNetworkError::Stopped => t("程序已停止。", "The application is stopped."),
                        NativeNetworkError::Persistence => t("未能保存，生效策略未改变。", "Could not save; the effective policy is unchanged."),
                    };
                    ui.colored_label(ui.visuals().error_fg_color, message);
                }
            });
        command
    }
}
