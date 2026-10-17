use eframe::egui;
use nestlink_app_core::{
    Failure, FailureKind, OperationResult, OperationStatus, RemoteEffect, Section,
};
use nestlink_app_ipc::wire::Rejection;
use nestlink_auth::Secret;
use std::ops::Range;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy)]
pub enum NavIcon {
    Monitor,
    Devices,
    Share,
    Network,
    Account,
    List,
    Settings,
}

pub fn nav_button(ui: &mut egui::Ui, icon: NavIcon, text: &str, selected: bool) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 42.), egui::Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            ui.is_enabled(),
            selected,
            text,
        )
    });
    let visuals = ui.style().interact_selectable(&response, selected);
    if selected || response.hovered() || response.has_focus() {
        let fill = if selected {
            ui.visuals().selection.bg_fill.gamma_multiply(0.12)
        } else {
            visuals.weak_bg_fill
        };
        ui.painter().rect_filled(rect, 7., fill);
    }
    if selected {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(rect.min + egui::vec2(0., 11.), egui::vec2(3., 20.)),
            2.,
            ui.visuals().selection.bg_fill,
        );
    }
    if response.has_focus() {
        ui.painter().rect_stroke(
            rect.shrink(1.),
            7.,
            egui::Stroke::new(1.5, ui.visuals().selection.bg_fill),
            egui::StrokeKind::Inside,
        );
    }
    let color = if selected {
        ui.visuals().hyperlink_color
    } else {
        visuals.text_color()
    };
    let center = rect.left_center() + egui::vec2(24., 0.);
    let p = |x, y| center + egui::vec2(x, y);
    let stroke = egui::Stroke::new(1.6, color);
    let line = |a, b| ui.painter().line_segment([a, b], stroke);
    match icon {
        NavIcon::Monitor | NavIcon::Devices => {
            let screen =
                egui::Rect::from_center_size(center + egui::vec2(0., -2.), egui::vec2(18., 12.));
            ui.painter()
                .rect_stroke(screen, 2., stroke, egui::StrokeKind::Inside);
            line(p(0., 4.), p(0., 8.));
            line(p(-5., 8.), p(5., 8.));
            if matches!(icon, NavIcon::Devices) {
                ui.painter().rect_filled(
                    egui::Rect::from_min_size(p(3., -1.), egui::vec2(7., 11.)),
                    1.,
                    ui.visuals().panel_fill,
                );
                ui.painter().rect_stroke(
                    egui::Rect::from_min_size(p(3., -1.), egui::vec2(7., 11.)),
                    1.,
                    stroke,
                    egui::StrokeKind::Inside,
                );
            }
        }
        NavIcon::Share | NavIcon::Network => {
            for (x, y) in [(0., -7.), (-7., 6.), (7., 6.)] {
                ui.painter().circle_stroke(p(x, y), 3., stroke);
            }
            line(p(-1.5, -4.), p(-5.5, 3.));
            line(p(1.5, -4.), p(5.5, 3.));
            if matches!(icon, NavIcon::Network) {
                line(p(-4., 6.), p(4., 6.));
            }
        }
        NavIcon::Account => {
            ui.painter().circle_stroke(p(0., -5.), 4., stroke);
            ui.painter().rect_stroke(
                egui::Rect::from_min_max(p(-7., 2.), p(7., 10.)),
                5.,
                stroke,
                egui::StrokeKind::Inside,
            );
        }
        NavIcon::List => {
            for y in [-6., 0., 6.] {
                ui.painter().circle_filled(p(-7., y), 1.3, color);
                line(p(-2., y), p(8., y));
            }
        }
        NavIcon::Settings => {
            ui.painter().circle_stroke(center, 7., stroke);
            ui.painter().circle_stroke(center, 2.5, stroke);
            for (x, y) in [(0., -10.), (0., 10.), (-10., 0.), (10., 0.)] {
                line(p(x * 0.7, y * 0.7), p(x, y));
            }
        }
    }
    ui.painter().text(
        rect.left_center() + egui::vec2(45., 0.),
        egui::Align2::LEFT_CENTER,
        text,
        egui::FontId::proportional(14.),
        color,
    );
    response
}

pub fn primary_button(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new((
            egui::Atom::grow(),
            egui::RichText::new(text).color(ui.visuals().selection.stroke.color),
            egui::Atom::grow(),
        ))
        .fill(ui.visuals().selection.bg_fill)
        .min_size(egui::vec2(ui.available_width(), 42.)),
    )
}

pub fn field(ui: &mut egui::Ui, label: &str, value: &mut String, limit: usize) {
    ui.label(label);
    ui.add(
        egui::TextEdit::singleline(value)
            .desired_width(ui.available_width().min(540.))
            .margin(egui::vec2(12., 10.))
            .char_limit(limit),
    );
}
const SECRET_FIELDS: &[&str] = &[
    "password",
    "new-password",
    "account-password",
    "remote-password",
    "remote-password-host",
    "remote-password-host-confirm",
    "remote-password-attempt",
];
pub fn secret_field(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut Zeroizing<String>,
    name: &str,
    generation: u64,
    limit: usize,
) {
    ui.label(label);
    let id = egui::Id::new(("secret", generation, name));
    let mut buffer = MaskedSecret::new(value, limit);
    let mut output = egui::TextEdit::singleline(&mut buffer)
        .password(true)
        .id(id)
        .desired_width(ui.available_width().min(540.))
        .margin(egui::vec2(12., 10.))
        .char_limit(limit)
        .show(ui);
    // egui's normal TextEdit undoer copies TextBuffer::as_str even for password
    // fields. Our buffer exposes only masks, and undo cannot replace the secret.
    output.state.clear_undoer();
    output.state.store(ui.ctx(), id);
}
struct MaskedSecret<'a> {
    secret: &'a mut Zeroizing<String>,
    mask: String,
    bytes: usize,
}
impl<'a> MaskedSecret<'a> {
    fn new(secret: &'a mut Zeroizing<String>, bytes: usize) -> Self {
        Self {
            mask: "*".repeat(secret.chars().count()),
            secret,
            bytes,
        }
    }
    fn byte_at(&self, index: usize) -> usize {
        self.secret
            .char_indices()
            .nth(index)
            .map_or(self.secret.len(), |(byte, _)| byte)
    }
    fn replace_range(&mut self, range: Range<usize>, text: &str) {
        let mut next = Zeroizing::new(String::with_capacity(self.bytes));
        next.push_str(&self.secret[..range.start]);
        next.push_str(text);
        next.push_str(&self.secret[range.end..]);
        std::mem::swap(self.secret, &mut next);
        self.mask = "*".repeat(self.secret.chars().count());
    }
}
impl egui::TextBuffer for MaskedSecret<'_> {
    fn is_mutable(&self) -> bool {
        true
    }
    fn as_str(&self) -> &str {
        &self.mask
    }
    fn insert_text(&mut self, text: &str, char_index: usize) -> usize {
        let available = self.bytes.saturating_sub(self.secret.len());
        let end = text
            .char_indices()
            .find_map(|(byte, ch)| (byte + ch.len_utf8() > available).then_some(byte))
            .unwrap_or(text.len());
        let text = &text[..end];
        let byte = self.byte_at(char_index);
        self.replace_range(byte..byte, text);
        text.chars().count()
    }
    fn delete_char_range(&mut self, range: Range<usize>) {
        if range.start <= range.end {
            let start = self.byte_at(range.start);
            let end = self.byte_at(range.end);
            self.replace_range(start..end, "");
        }
    }
    fn clear(&mut self) {
        self.secret.zeroize();
        self.mask.clear();
    }
    // Undo text is deliberately a mask. It cannot reconstruct a password.
    fn replace_with(&mut self, _text: &str) {}
    fn type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<MaskedSecret<'static>>()
    }
}
pub fn clear_secret_widgets(context: &egui::Context, generation: u64) {
    context.data_mut(|data| {
        for name in SECRET_FIELDS {
            data.remove::<egui::text_edit::TextEditState>(egui::Id::new((
                "secret", generation, *name,
            )));
        }
    });
}
pub fn take_secret(value: &mut Zeroizing<String>) -> Secret {
    Secret::from_text(std::mem::take(&mut **value))
}
pub fn failure(error: &Failure, english: bool) -> String {
    let (zh, en) = match error.kind {
        FailureKind::Transport => (
            "网络请求失败，请刷新查看状态。",
            "The network request failed; refresh to check its state.",
        ),
        FailureKind::Timeout => (
            "请求超时，请刷新查看状态。",
            "The request timed out; refresh to check its state.",
        ),
        FailureKind::Rejected => (
            "服务器拒绝了操作。请检查权限、密码或当前版本。",
            "The server rejected the operation. Check permissions, credentials or the current revision.",
        ),
        FailureKind::SignInRequired => (
            "登录已失效，请重新登录。",
            "Sign in again; the session is no longer valid.",
        ),
        FailureKind::Trust => (
            "服务器身份核验失败，请向管理员核对地址和公钥。",
            "Server identity verification failed. Check the origin and key with your administrator.",
        ),
        FailureKind::Invalid => ("输入无效。", "The input is invalid."),
        FailureKind::Capacity => (
            "操作已达到容量上限，请稍后重试。",
            "The operation budget is full. Try again later.",
        ),
        FailureKind::NativeSessionUnavailable => (
            "本机原生会话未配置网络监视或连接策略。",
            "Native session networking or policy is not configured on this device.",
        ),
        FailureKind::NativeSessionCancelled => (
            "原生会话连接已取消。",
            "The native session connection was cancelled.",
        ),
        FailureKind::NetworkChanged => (
            "网络已变化，原生会话已停止。",
            "The network changed and the native session stopped.",
        ),
        FailureKind::PermitExpired => ("会话许可已到期。", "The session permit expired."),
        FailureKind::LocalIdentityRequired => (
            "此操作需要本机安装身份。",
            "This operation requires a local installation identity.",
        ),
        FailureKind::CoreStopped => ("本用户内核已停止。", "The user core has stopped."),
        FailureKind::StaleGeneration | FailureKind::Superseded => (
            "账号或服务器已变化，此旧操作已失效。",
            "The account or server changed; this old operation is no longer valid.",
        ),
    };
    let mut message = if english { en } else { zh }.to_owned();
    if let Some(status) = error.status {
        message.push_str(&format!(" (HTTP {status})"));
    }
    message
}
pub fn rejection(reason: Rejection, english: bool) -> &'static str {
    let pair = match reason {
        Rejection::StaleGeneration => (
            "操作未送出：账号或服务器已变化，请查看当前页面后重试。",
            "Not sent: the account or server changed. Review the current page first.",
        ),
        Rejection::Capacity => (
            "操作未送出：正在处理的请求过多。",
            "Not sent: too many requests are pending.",
        ),
        Rejection::Invalid => ("操作未送出：输入无效。", "Not sent: invalid input."),
        Rejection::Stopped => ("内核已停止。", "The core has stopped."),
        Rejection::UnknownOperation => (
            "此连接已无法读取该操作。请刷新实际状态。",
            "This connection cannot retrieve the operation. Refresh its actual state.",
        ),
    };
    if english { pair.1 } else { pair.0 }
}
pub fn operation_message(result: &OperationResult, english: bool) -> String {
    let pair = match result.status {
        OperationStatus::Succeeded => ("操作完成。", "Operation completed."),
        OperationStatus::Cancelled => ("操作已取消。", "Operation cancelled."),
        OperationStatus::Superseded => (
            "账号或服务器已变化，旧操作已结束。",
            "The account or server changed; the old operation ended.",
        ),
        OperationStatus::Failed => ("操作失败。", "Operation failed."),
        _ => ("操作正在处理中。", "Operation is pending."),
    };
    let mut message = if english { pair.1 } else { pair.0 }.to_owned();
    if let Some(failure) = &result.failure {
        message.push(' ');
        message.push_str(&self::failure(failure, english));
    }
    if result.status != OperationStatus::Succeeded {
        match result.remote_effect {
            RemoteEffect::Committed => message.push_str(if english {
                " The server committed the change; refresh its state."
            } else {
                " 服务器已提交变更，请刷新查看。"
            }),
            RemoteEffect::Unknown => message.push_str(if english {
                " The server result is unknown. Refresh before repeating a write."
            } else {
                " 服务器结果尚不确定。重复写入前请先刷新。"
            }),
            RemoteEffect::None => {}
        }
    }
    message
}
pub fn section<T>(ui: &mut egui::Ui, section: &Section<T>, english: bool) {
    if section.loading.is_some() {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(if english {
                "Loading…"
            } else {
                "正在加载…"
            });
        });
    }
    if let Some(error) = &section.error {
        ui.colored_label(ui.visuals().error_fg_color, failure(error, english));
    }
    if section.data.is_none() && section.loading.is_none() && section.error.is_none() {
        ui.label(if english {
            "Load this page to see actual records."
        } else {
            "请加载页面以查看实际记录。"
        });
    }
}
pub fn permissions(values: &[i32], english: bool) -> String {
    values
        .iter()
        .map(|value| match (value, english) {
            (1, false) => "画面",
            (1, true) => "View",
            (2, false) => "输入",
            (2, true) => "Input",
            (3, false) => "音频",
            (3, true) => "Audio",
            (4, false) => "读取文件",
            (4, true) => "Read files",
            (5, false) => "写入文件",
            (5, true) => "Write files",
            (6, false) => "读取剪贴板",
            (6, true) => "Read clipboard",
            (7, false) => "写入剪贴板",
            (7, true) => "Write clipboard",
            _ => "?",
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::TextBuffer;
    #[test]
    fn masked_buffer_exposes_only_masked_text_and_ignores_undo_replacements() {
        let mut secret = Zeroizing::new("中文🔐".to_owned());
        let mut buffer = MaskedSecret::new(&mut secret, 32);
        assert_eq!(buffer.as_str(), "***");
        assert_eq!(buffer.insert_text("pass", 2), 4);
        assert_eq!(buffer.as_str(), "*******");
        buffer.delete_char_range(1..3);
        assert_eq!(&**buffer.secret, "中ass🔐");
        buffer.replace_with("*****");
        assert_eq!(&**buffer.secret, "中ass🔐");
        buffer.clear();
        assert!(buffer.secret.is_empty());
        assert!(buffer.as_str().is_empty());
    }
    #[test]
    fn password_limits_count_utf8_bytes_and_keep_char_boundaries() {
        let mut secret = Zeroizing::new(String::new());
        let mut buffer = MaskedSecret::new(&mut secret, 8);
        assert_eq!(buffer.insert_text("中文🔐", 0), 2);
        assert_eq!(&**buffer.secret, "中文");
        assert_eq!(buffer.insert_text("🔐", 2), 0);
        assert_eq!(buffer.insert_text("ab", 2), 2);
        assert_eq!(&**buffer.secret, "中文ab");
        buffer.delete_char_range(0..1);
        assert_eq!(&**buffer.secret, "文ab");
    }
    #[test]
    fn real_egui_password_edit_masks_accessibility_and_clears_undo_history() -> std::io::Result<()>
    {
        let context = egui::Context::default();
        context.enable_accesskit();
        crate::theme::fonts(&context)?;
        let id = egui::Id::new(("secret", 9_u64, "password"));
        let mut value = Zeroizing::new(String::new());
        context.memory_mut(|memory| memory.request_focus(id));
        let output = context.run_ui(
            egui::RawInput {
                events: vec![egui::Event::Text("中文-test-secret".into())],
                ..Default::default()
            },
            |parent| {
                egui::CentralPanel::default().show_inside(parent, |ui| {
                    secret_field(ui, "Password", &mut value, "password", 9, 1024);
                });
            },
        );
        assert_eq!(&**value, "中文-test-secret");
        let Some(accessible) = output.platform_output.accesskit_update else {
            panic!("accessibility tree was not produced")
        };
        let values: Vec<_> = accessible
            .nodes
            .iter()
            .filter_map(|(_, node)| node.value())
            .collect();
        assert!(
            !values.is_empty(),
            "password edit has no accessible value to inspect"
        );
        assert!(
            values
                .iter()
                .all(|value| !value.contains("中文-test-secret"))
        );
        assert!(
            values
                .iter()
                .any(|value| !value.is_empty() && value.chars().all(|character| character == '•')),
            "the accessible password value should contain only password mask characters"
        );
        if let Some(state) = egui::text_edit::TextEditState::load(&context, id) {
            assert!(
                !state
                    .undoer()
                    .has_undo(&(egui::text::CCursorRange::default(), String::new()))
            );
        } else {
            panic!("password widget state was not stored");
        }
        clear_secret_widgets(&context, 9);
        assert!(egui::text_edit::TextEditState::load(&context, id).is_none());
        Ok(())
    }
}
