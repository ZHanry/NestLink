use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_app_core::{NativeSpaceConfirmation, NativeSpaceMode, NativeSpacePreviewRequest};

pub(super) struct NetworkDraft {
    trusted_key: String,
    verified_key: bool,
    mode: NativeSpaceMode,
    nodes: [String; 2],
    nonce: String,
    approved: bool,
}
impl Default for NetworkDraft {
    fn default() -> Self { Self { trusted_key: String::new(), verified_key: false,
        mode: NativeSpaceMode::Direct, nodes: Default::default(), nonce: String::new(), approved: false } }
}
impl NetworkDraft {
    pub(super) fn show(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot,
        details: &nestlink_app_core::SpaceDetailsPage, english: bool, runtime: Option<&str>) -> Option<Command> {
        let mut command = None;
        egui::CollapsingHeader::new(t(english, "本机空间路径批准", "Approve this device's space path")).show(ui, |ui| {
            ui.label(t(english, "先在远程桌面选定并获得双方批准的请求，然后停止当前连接。此处仅准备该请求的精确双方成员，不开放其他成员目录。", "Select a mutually approved request in Remote desktop, then stop the current connection. This prepares only that request's exact pair of members."));
            ui.label(t(english, "输入从管理员可信渠道独立核验的空间公钥（base64url）", "Enter the space public key independently verified with the administrator through a trusted channel (base64url)"));
            if ui.add(egui::TextEdit::singleline(&mut self.trusted_key).char_limit(43)).changed() {
                self.verified_key = false; self.approved = false;
            }
            ui.checkbox(&mut self.verified_key, t(english, "我已通过独立可信渠道核验此空间公钥", "I verified this space key through an independent trusted channel"));
            for (mode, label) in [(NativeSpaceMode::Direct, t(english, "仅直连", "Direct only")),
                (NativeSpaceMode::Relays, t(english, "双中继及安全恢复", "Two relays with safe recovery"))] {
                if ui.radio_value(&mut self.mode, mode, label).changed() { self.approved = false; }
            }
            let key: Option<[u8; 32]> = URL_SAFE_NO_PAD.decode(self.trusted_key.trim()).ok().and_then(|key| key.try_into().ok());
            let key_matches = key.is_some_and(|key| key != [0; 32] && URL_SAFE_NO_PAD.encode(key) == details.space.authority_public_key);
            let remote = snapshot.selected_request.data.as_ref().filter(|remote| remote.status == "approved"
                && remote.connection_generation > 0 && snapshot.installation.as_ref().is_some_and(|local|
                    remote.controller_device_id == local.device_id || remote.host_device_id == local.device_id));
            if let Some(remote) = remote {
                ui.label(format!("{}: {} · generation {}", t(english, "已批准请求", "Approved request"), remote.id, remote.connection_generation));
                ui.small(format!("{} → {}", remote.controller_device_id, remote.host_device_id));
            } else { ui.label(t(english, "请先选择当前设备参与的已批准远控请求。", "First select an approved remote request involving this device.")); }
            if ui.add_enabled(self.verified_key && key_matches && remote.is_some() && runtime.is_some(),
                egui::Button::new(t(english, "读取一次性路径预览", "Read one-use path preview"))).clicked()
                && let (Some(key), Some(remote), Some(runtime)) = (key, remote, runtime) {
                self.approved = false;
                command = Some(Command::Submit { action: Action::PreviewNativeSpace { request: NativeSpacePreviewRequest {
                    runtime_id: runtime.into(), context: snapshot.space_context.clone(), space_id: details.space.space_id.clone(),
                    request_id: remote.id.clone(), expected_connection_generation: remote.connection_generation,
                    expected_space_revision: details.space.revision, expected_policy_epoch: details.space.policy_epoch,
                    expected_network_revision: snapshot.native_network_revision, trusted_authority_key: key, mode: self.mode,
                } } });
            }
            widgets::section(ui, &snapshot.native_space_preview, english);
            let Some(preview) = snapshot.native_space_preview.data.as_ref().filter(|preview|
                preview.context == snapshot.space_context && preview.space_id == details.space.space_id
                    && preview.mode == self.mode && key == Some(preview.authority_key) && self.verified_key) else { return; };
            if self.nonce != preview.nonce {
                self.nonce = preview.nonce.clone(); self.approved = false;
                self.nodes = std::array::from_fn(|index| preview.relay_choices.get(index).map(|node| node.node_id.clone()).unwrap_or_default());
            }
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()
                .and_then(|value| u64::try_from(value.as_millis()).ok()).unwrap_or(u64::MAX);
            let current = now < preview.expires_at_unix_ms && preview.expected_network_revision == snapshot.native_network_revision;
            ui.label(format!("{}: {} · generation {}", t(english, "请求", "Request"), preview.request_id, preview.connection_generation));
            for index in 0..2 { ui.small(format!("{} · {} · epoch {}", preview.installation_ids[index], role_name(preview.roles[index], english), preview.membership_epochs[index])); }
            ui.small(format!("permit {}", URL_SAFE_NO_PAD.encode(preview.permit_sha256)));
            ui.small(format!("{}: {}", t(english, "剩余秒数", "Seconds remaining"), preview.expires_at_unix_ms.saturating_sub(now) / 1000));
            if preview.mode == NativeSpaceMode::Relays {
                ui.small(t(english, "节点来自原远控许可的签名发现，预览最多有效 5 秒。过期后必须重新读取。", "Nodes come from discovery signed for the original remote permit. This preview lasts at most 5 seconds; read it again after expiry."));
                for index in 0..2 {
                    egui::ComboBox::from_id_salt(("space-path-node", index)).selected_text(self.nodes[index].as_str()).show_ui(ui, |ui| {
                        for node in &preview.relay_choices {
                            if ui.selectable_value(&mut self.nodes[index], node.node_id.clone(), format!("{} · runtime {}", node.node_id, node.runtime_generation)).changed() { self.approved = false; }
                        }
                    });
                }
            }
            ui.checkbox(&mut self.approved, t(english, "我批准本机使用以上精确空间、请求、双方成员和节点", "I approve this device using the exact space, request, members and nodes above"));
            let nodes_valid = preview.mode == NativeSpaceMode::Direct || (self.nodes[0] != self.nodes[1]
                && self.nodes.iter().all(|id| preview.relay_choices.iter().any(|node| node.node_id == *id && node.expires_at_unix_ms > now)));
            if ui.add_enabled(current && self.approved && nodes_valid && runtime.is_some(),
                egui::Button::new(t(english, "一次确认并保存本机批准", "Confirm once and save local consent"))).clicked()
                && let Some(runtime) = runtime {
                self.approved = false;
                command = Some(Command::Submit { action: Action::ConfirmNativeSpace { confirmation: NativeSpaceConfirmation {
                    runtime_id: runtime.into(), context: snapshot.space_context.clone(), nonce: preview.nonce.clone(),
                    node_ids: (preview.mode == NativeSpaceMode::Relays).then(|| self.nodes.clone()),
                } } });
            }
            if !current { ui.label(t(english, "此预览已过期或本机设置已变化，请重新读取。", "This preview expired or local settings changed. Read it again.")); }
            ui.small(t(english, "保存使用原本机设置代次比较、空闲检查和落盘确认。授权到期、撤销或业务代次变化后需重新准备，不会自动续期。", "Saving uses the original local revision comparison, idle checks and persistence. Expiry, revocation or a changed business generation requires fresh preparation; authority is never renewed automatically."));
        });
        command
    }
}
