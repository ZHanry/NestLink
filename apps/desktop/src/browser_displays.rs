use crate::DesktopApp;
use eframe::egui;
use nestlink_app_core::{BrowserHostStatus, Snapshot};

impl DesktopApp {
    pub(crate) fn browser_display_panel(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        let Some(host) = snapshot.browser_host.data.as_ref() else {
            return;
        };
        if !matches!(
            host.status,
            BrowserHostStatus::Establishing | BrowserHostStatus::Connected
        ) {
            return;
        }
        if host.displays.catalog.is_none() {
            ui.small(self.t("正在准备本机屏幕…", "Preparing local displays…"));
            return;
        }
        ui.separator();
        ui.label(self.t("本次共享的屏幕", "Screens shared in this session"));
        for display in &host.displays.displays {
            if host.displays.approved_sources.contains(&display.source) {
                ui.label(format!(
                    "{}{} · {} × {}",
                    if host.displays.initial_source == Some(display.source) {
                        "● "
                    } else {
                        ""
                    },
                    display.label,
                    display.width,
                    display.height
                ));
            }
        }
    }
}
