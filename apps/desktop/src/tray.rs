use eframe::egui;
use std::sync::Arc;
pub enum TrayAction {
    Open,
    Exit,
}
pub struct Tray {
    inner: nestlink_platform_tray::Tray,
}
impl Tray {
    pub fn create(
        context: egui::Context,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let pixels = super::theme::icon(32);
        let inner = nestlink_platform_tray::Tray::create(
            nestlink_platform_tray::Icon {
                width: pixels.width,
                height: pixels.height,
                rgba: pixels.rgba,
            },
            nestlink_platform_tray::Labels {
                open: "打开 NestLink".into(),
                exit: "退出程序".into(),
            },
            Arc::new(move || context.request_repaint()),
        )?;
        Ok(Self { inner })
    }
    pub fn available(&self) -> bool {
        self.inner.available()
    }
    pub fn actions(&self) -> Vec<TrayAction> {
        self.inner
            .actions()
            .map(|action| match action {
                nestlink_platform_tray::Action::Open => TrayAction::Open,
                nestlink_platform_tray::Action::Exit => TrayAction::Exit,
            })
            .collect()
    }
}
pub fn restore(context: &egui::Context) {
    context.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    context.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
    context.send_viewport_cmd(egui::ViewportCommand::Focus);
}
