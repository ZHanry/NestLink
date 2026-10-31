//! Local dialing consent, separate from administrator forwarding policy.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use eframe::egui;
use nestlink_app_core::{
    NativeNetworkError, NativeNetworkSettings, NativeSpacePathSettings, Snapshot,
};
use nestlink_app_ipc::wire::Command;

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum SpacePathChoice {
    #[default]
    SessionPaths,
    Direct,
    Relays,
}

#[derive(Default)]
pub(crate) struct NativeNetworkPanel {
    base: Option<(u64, u64)>,
    prefixes: String,
    use_deployment_stun: bool,
    enable_pcp: bool,
    pcp_gateway: String,
    space_path: SpacePathChoice,
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
    fn edited_space(&self) -> Option<NativeSpacePathSettings> {
        let authority_key = URL_SAFE_NO_PAD
            .decode(self.route_authority.trim())
            .ok()?
            .try_into()
            .ok()?;
        Some(NativeSpacePathSettings {
            deployment_id: self.route_deployment.trim().into(),
            space_id: self.route_space.trim().into(),
            authority_key,
            controller_membership_grant_id: self.route_controller_membership.trim().into(),
            host_membership_grant_id: self.route_host_membership.trim().into(),
        })
    }

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
            self.space_path = if let Some(path) = &snapshot.native_network.space_path {
                self.route_deployment = path.deployment_id.clone();
                self.route_space = path.space_id.clone();
                self.route_authority = URL_SAFE_NO_PAD.encode(path.authority_key);
                self.route_controller_membership = path.controller_membership_grant_id.clone();
                self.route_host_membership = path.host_membership_grant_id.clone();
                self.route_nodes = Default::default();
                SpacePathChoice::Direct
            } else if let Some(route) = &snapshot.native_network.route_set {
                self.route_deployment = route.deployment_id.clone();
                self.route_space = route.space_id.clone();
                self.route_authority = URL_SAFE_NO_PAD.encode(route.authority_key);
                self.route_controller_membership = route.controller_membership_grant_id.clone();
                self.route_host_membership = route.host_membership_grant_id.clone();
                self.route_nodes = route.node_ids.clone();
                SpacePathChoice::Relays
            } else {
                self.route_deployment.clear();
                self.route_space.clear();
                self.route_authority.clear();
                self.route_controller_membership.clear();
                self.route_host_membership.clear();
                self.route_nodes = Default::default();
                SpacePathChoice::SessionPaths
            };
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
                ui.separator();
                ui.label(t("此设备的空间路径", "Space path for this device"));
                for (choice, label) in [
                    (SpacePathChoice::SessionPaths, t("禁用空间路径，使用原会话路径策略", "Disable space paths; use the session path policy")),
                    (SpacePathChoice::Direct, t("使用空间授权，仅允许直连", "Use space authorization for direct connections only")),
                    (SpacePathChoice::Relays, t("使用空间内批准的双中继与安全恢复", "Use approved space relays and safe recovery")),
                ] {
                    if ui.radio_value(&mut self.space_path, choice, label).changed() {
                        self.approved = false;
                    }
                }
                match self.space_path {
                    SpacePathChoice::SessionPaths => {
                        ui.small(t("保存后清除此设备的空间直连和双中继配置。后续连接按原部署及会话许可选择路径，可能使用中继；远控批准与上面的内网批准仍独立生效。", "Saving clears this device's direct-space and relay-space settings. Future connections use the deployment and session path policy, which may allow relays. Remote-control approval and private-network consent remain separate."));
                    },
                    SpacePathChoice::Direct => {
                        ui.small(t("直连失败或空间授权撤销时停止，不会回退到中继。当前候选功能的路径授权最多 30 秒；期限届满后需建立新会话。", "Direct failure or space revocation stops the session without relay fallback. This candidate feature has a fixed path lifetime of at most 30 seconds; start a new session after it expires."));
                    },
                    SpacePathChoice::Relays => {
                    ui.small(t("当前候选功能的路径授权最多 30 秒，只支持一次安全恢复；期限届满后需建立新会话。", "This candidate feature has a fixed path lifetime of at most 30 seconds and supports one safe recovery. Start a new session after it expires."));
                    ui.label(t("在双方设备配置相同的空间、成员凭据和节点顺序。中继切换将清理旧输入和媒体后重新认证，恢复后重新选择共享屏幕。", "Configure the same space, memberships and node order on both devices. Recovery clears old input and media before fresh authentication. Select the shared screen again afterwards."));
                    },
                }
                if self.space_path != SpacePathChoice::SessionPaths {
                    ui.small(t("在双方设备填写相同的空间及成员凭据。请通过可信渠道向空间管理员核对公钥，再在本机批准；空间成员资格本身不授予屏幕、键鼠或文件访问。", "Configure the same space and membership grants on both devices. Verify the public key with the space administrator through a trusted channel before approving it locally. Space membership alone does not grant screen, input or file access."));
                    for (label,value) in [
                        (t("部署 ID", "Deployment ID"), &mut self.route_deployment),
                        (t("空间 ID", "Space ID"), &mut self.route_space),
                        (t("本机信任的空间公钥（base64url，无填充）", "Locally trusted space public key (base64url, no padding)"), &mut self.route_authority),
                        (t("控制端成员凭据 ID", "Controller membership grant ID"), &mut self.route_controller_membership),
                        (t("被控端成员凭据 ID", "Host membership grant ID"), &mut self.route_host_membership),
                    ] {
                        ui.label(label);
                        if ui.add(egui::TextEdit::singleline(value).char_limit(64)).changed() { self.approved = false; }
                    }
                }
                if self.space_path == SpacePathChoice::Relays {
                    for (index,value) in self.route_nodes.iter_mut().enumerate() {
                        ui.label(if index == 0 { t("主中继节点 ID", "Initial relay node ID") } else { t("备用中继节点 ID", "Standby relay node ID") });
                        if ui.add(egui::TextEdit::singleline(value).char_limit(64)).changed() { self.approved = false; }
                    }
                }
                let space = self.edited_space();
                let space_path = if self.space_path == SpacePathChoice::Direct { space.clone() } else { None };
                let route_set = if self.space_path == SpacePathChoice::Relays {
                    space.map(|space| nestlink_app_core::NativeRouteSetSettings {
                            deployment_id: space.deployment_id, space_id: space.space_id, authority_key: space.authority_key,
                            controller_membership_grant_id: space.controller_membership_grant_id,
                            host_membership_grant_id: space.host_membership_grant_id,
                            node_ids:self.route_nodes.clone().map(|id| id.trim().to_owned()),
                        })
                } else { None };
                let route_valid = self.space_path != SpacePathChoice::Relays || route_set.as_ref().is_some_and(|route| route.validate().is_ok());
                let direct_valid = self.space_path != SpacePathChoice::Direct || space_path.as_ref().is_some_and(|path| path.validate().is_ok());
                let settings = NativeNetworkSettings {
                    space_path,
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
                let valid = settings.validate().is_ok() && pcp_valid && route_valid && direct_valid;
                if !direct_valid {
                    ui.colored_label(ui.visuals().error_fg_color, t("空间直连需要有效部署 ID、空间 ID、32 字节的非零公钥，以及不同的控制端与被控端成员凭据 ID。", "Direct space connections require valid deployment and space IDs, a nonzero 32-byte public key, and distinct controller and host membership grant IDs."));
                }
                if !route_valid || (self.space_path == SpacePathChoice::Relays && self.enable_pcp) {
                    ui.colored_label(ui.visuals().error_fg_color, t("双中继需要有效部署、空间、公钥、两个成员凭据及不同节点，并需关闭 PCP。", "Space relays require valid deployment, space, public key, two memberships and distinct nodes, with PCP disabled."));
                }
                if !valid && direct_valid && route_valid && !(self.space_path == SpacePathChoice::Relays && self.enable_pcp) {
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
