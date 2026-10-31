//! Local dialing consent, separate from administrator forwarding policy.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use eframe::egui;
use nestlink_app_core::{NativeNetworkError, NativeNetworkSettings, Snapshot};
use nestlink_app_ipc::wire::Command;

#[derive(Default)]
pub(crate) struct NativeNetworkPanel {
    base: Option<(u64, u64)>,
    prefixes: String,
    use_deployment_stun: bool,
    enable_pcp: bool,
    pcp_gateway: String,
    enable_route_set: bool,
    route_deployment: String,
    route_space: String,
    route_authority: String,
    route_controller_membership: String,
    route_host_membership: String,
    route_nodes: [String; 2],
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
            self.enable_pcp = snapshot.native_network.pcp_gateway.is_some();
            self.pcp_gateway = snapshot
                .native_network
                .pcp_gateway
                .map(|gateway| gateway.to_string())
                .unwrap_or_default();
            self.approved = false;
            self.enable_route_set = snapshot.native_network.route_set.is_some();
            if let Some(route) = &snapshot.native_network.route_set {
                self.route_deployment = route.deployment_id.clone();
                self.route_space = route.space_id.clone();
                self.route_authority = URL_SAFE_NO_PAD.encode(route.authority_key);
                self.route_controller_membership = route.controller_membership_grant_id.clone();
                self.route_host_membership = route.host_membership_grant_id.clone();
                self.route_nodes = route.node_ids.clone();
            }
            self.pending = false;
        }
        let t = |zh, en| if english { en } else { zh };
        let mut command = None;
        egui::CollapsingHeader::new(t("本机连接网络", "Local connection network"))
            .show(ui, |ui| {
                ui.label(t(
                    "STUN 地址由已核验的控制中心提供。只有下面明确批准的内网可作为本机直连目标；服务器和对方设备不能扩大此范围。",
                    "STUN endpoints come from your verified control center. Only the private networks approved below may be dialed locally; a server or peer cannot extend this consent.",
                ));
                if ui.checkbox(&mut self.use_deployment_stun, t("使用部署提供的 STUN 地址发现", "Use deployment STUN discovery")).changed() {
                    self.approved = false;
                }
                if ui.checkbox(&mut self.enable_pcp, t("允许此设备为当前会话申请 PCP UDP 端口映射", "Allow this device to request a PCP UDP mapping for the current session")).changed() {
                    self.approved = false;
                }
                if self.enable_pcp {
                    ui.label(t("明确批准的 PCP 网关 IPv4 地址", "Explicitly approved PCP gateway IPv4 address"));
                    if ui.add(egui::TextEdit::singleline(&mut self.pcp_gateway)
                        .char_limit(15).hint_text("192.168.1.1")).changed() {
                        self.approved = false;
                    }
                    ui.small(t(
                        "仅支持管理员允许的 PCP 网关和会话实际使用的 UDP 端口。映射最长租期为 120 秒，程序在会话内续期并在结束时释放；其他映射协议暂不可用。网关不支持或端口不匹配时保留合法回退路径。",
                        "Requires administrator permission and a PCP gateway. Only the session's actual UDP port is mapped. Leases last at most 120 seconds, renew during the session, and are released when it ends. Other mapping protocols are unavailable. Unsupported gateways or changed ports retain authorized fallback paths.",
                    ));
                }
                ui.label(t("批准的内网 CIDR（每行一个）", "Approved private CIDRs (one per line)"));
                if ui.add(egui::TextEdit::multiline(&mut self.prefixes).char_limit(4096).desired_rows(3)
                    .hint_text("192.168.1.0/24\nfd12:3456::/32")).changed() {
                    self.approved = false;
                }
                if let Some(path) = &snapshot.native_network.space_path {
                    ui.label(format!("{} {}", t("当前仅直连空间：", "Current direct-only space:"), path.space_id));
                    ui.small(t("由本机 daemon 的 --native-space-path 配置。直连失败或空间授权撤销时停止；不会回退到中继。", "Configured by the local daemon's --native-space-path. Direct failure or space revocation stops the session; no relay fallback is permitted."));
                }
                if ui.add_enabled(snapshot.native_network.space_path.is_none(), egui::Checkbox::new(&mut self.enable_route_set, t("使用空间内批准的双中继与安全恢复", "Use approved space relays and safe recovery"))).changed() {
                    self.approved = false;
                }
                if self.enable_route_set {
                    ui.small(t("当前候选功能的路径授权最多 30 秒，只支持一次安全恢复；期限届满后需建立新会话。", "This candidate feature has a fixed path lifetime of at most 30 seconds and supports one safe recovery. Start a new session after it expires."));
                    ui.label(t("在双方设备配置相同的空间、成员凭据和节点顺序。中继切换将清理旧输入和媒体后重新认证，恢复后重新选择共享屏幕。", "Configure the same space, memberships and node order on both devices. Recovery clears old input and media before fresh authentication. Select the shared screen again afterwards."));
                    for (label,value) in [
                        (t("部署 ID", "Deployment ID"), &mut self.route_deployment),
                        (t("空间 ID", "Space ID"), &mut self.route_space),
                        (t("空间公钥（base64url）", "Space public key (base64url)"), &mut self.route_authority),
                        (t("控制端成员凭据 ID", "Controller membership grant ID"), &mut self.route_controller_membership),
                        (t("被控端成员凭据 ID", "Host membership grant ID"), &mut self.route_host_membership),
                    ] {
                        ui.label(label);
                        if ui.add(egui::TextEdit::singleline(value).char_limit(64)).changed() { self.approved = false; }
                    }
                    for (index,value) in self.route_nodes.iter_mut().enumerate() {
                        ui.label(if index == 0 { t("主中继节点 ID", "Initial relay node ID") } else { t("备用中继节点 ID", "Standby relay node ID") });
                        if ui.add(egui::TextEdit::singleline(value).char_limit(64)).changed() { self.approved = false; }
                    }
                }
                let route_set = if self.enable_route_set {
                    URL_SAFE_NO_PAD.decode(self.route_authority.trim()).ok()
                        .and_then(|bytes| <[u8;32]>::try_from(bytes).ok())
                        .map(|authority_key| nestlink_app_core::NativeRouteSetSettings {
                            deployment_id: self.route_deployment.trim().into(), space_id:self.route_space.trim().into(), authority_key,
                            controller_membership_grant_id:self.route_controller_membership.trim().into(),
                            host_membership_grant_id:self.route_host_membership.trim().into(),
                            node_ids:self.route_nodes.clone().map(|id| id.trim().to_owned()),
                        })
                } else { None };
                let route_valid = !self.enable_route_set || route_set.as_ref().is_some_and(|route| route.validate().is_ok());
                let settings = NativeNetworkSettings {
                    space_path: snapshot.native_network.space_path.clone(),
                    route_set,
                    media_route: snapshot.native_network.media_route,
                    media_interface_index: snapshot.native_network.media_interface_index,
                    use_deployment_stun: self.use_deployment_stun,
                    pcp_gateway: if self.enable_pcp { self.pcp_gateway.parse().ok() } else { None },
                    private_network_prefixes: self.prefixes.lines().map(str::trim)
                        .filter(|line| !line.is_empty()).map(str::to_owned).collect(),
                };
                let pcp_valid = !self.enable_pcp
                    || settings.pcp_gateway.is_some_and(|gateway| gateway.is_private());
                let valid = settings.validate().is_ok() && pcp_valid && route_valid;
                if !route_valid || (self.enable_route_set && self.enable_pcp) {
                    ui.colored_label(ui.visuals().error_fg_color, t("双中继需要有效部署、空间、公钥、两个成员凭据及不同节点，并需关闭 PCP。", "Space relays require valid deployment, space, public key, two memberships and distinct nodes, with PCP disabled."));
                }
                if !valid {
                    ui.colored_label(ui.visuals().error_fg_color, if !pcp_valid {
                        t("请输入明确批准的私有 PCP 网关 IPv4 地址，例如 192.168.1.1。", "Enter the explicitly approved private PCP gateway IPv4 address, such as 192.168.1.1.")
                    } else {
                        t(
                            "请输入最多 32 个规范的私有网段，例如 192.168.1.0/24。回环、链路本地、公网和全地址范围不能在此批准。",
                            "Enter up to 32 canonical private subnets, such as 192.168.1.0/24. Loopback, link-local, public and all-address ranges cannot be approved here.",
                        )
                    });
                }
                let changed = settings != snapshot.native_network || snapshot.native_network_durable == Some(false);
                ui.checkbox(&mut self.approved, t("我批准此设备使用上面的网络设置", "I approve this device using the network settings above"));
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
