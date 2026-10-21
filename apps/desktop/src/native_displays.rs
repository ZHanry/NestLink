use crate::DesktopApp;
use eframe::egui;
use nestlink_app_core::{NativeSessionStatus, Snapshot};

impl DesktopApp {
    pub(crate) fn native_display_panel(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        let Some(_session) = snapshot
            .native_session
            .data
            .as_ref()
            .filter(|s| s.status == NativeSessionStatus::Connected)
        else {
            return;
        };
        let Some(state) = self.bridge.native_displays() else {
            ui.small(self.t(
                "正在准备屏幕或等待系统屏幕授权…",
                "Preparing displays or waiting for system consent…",
            ));
            return;
        };
        if state.catalog.is_none() {
            return;
        }
        if state.is_host {
            ui.label(self.t("本次共享的屏幕", "Screens shared in this session"));
            for display in &state.displays {
                let selected = state
                    .selected
                    .as_ref()
                    .is_some_and(|s| s.source == display.source);
                ui.label(format!(
                    "{}{} · {} × {}",
                    if selected { "● " } else { "" },
                    display.label,
                    display.width,
                    display.height
                ));
            }
            if !state.catalog_acknowledged {
                ui.small(self.t(
                    "正在等待对方确认屏幕列表…",
                    "Waiting for the other device to acknowledge the screen list…",
                ));
            }
        } else {
            ui.horizontal_wrapped(|ui| {
                ui.label(self.t("远端屏幕", "Remote screen"));
                for display in &state.displays {
                    let selected = state
                        .selected
                        .as_ref()
                        .is_some_and(|s| s.source == display.source);
                    if ui
                        .add_enabled(
                            state.pending.is_none() && state.selected.is_some(),
                            egui::Button::new(format!(
                                "{} · {} × {}",
                                display.label, display.width, display.height
                            ))
                            .selected(selected),
                        )
                        .clicked()
                        && !selected
                        && !self
                            .bridge
                            .select_native_display(snapshot.generation, display.source)
                    {
                        ui.colored_label(
                            ui.visuals().error_fg_color,
                            self.t(
                                "切屏未能排队，请重试。",
                                "The display switch could not be queued. Try again.",
                            ),
                        );
                    }
                }
                if state.pending.is_some() {
                    ui.spinner();
                    ui.label(self.t("正在切换屏幕…", "Switching display…"));
                }
            });
        }
    }
}
