use crate::DesktopApp;
use eframe::egui;
use nestlink_app_core::{NativeSessionBinding, NativeSessionStatus, Snapshot};
use nestlink_app_ipc::wire::Command;

impl DesktopApp {
    pub(crate) fn native_display_panel(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        let Some(session) = snapshot
            .native_session
            .data
            .as_ref()
            .filter(|s| s.status == NativeSessionStatus::Connected)
        else {
            return;
        };
        let Some(state) = self.bridge.native_displays() else {
            ui.small(self.t(
                "正在等待本机选屏或系统屏幕授权…",
                "Waiting for local display selection or system consent…",
            ));
            return;
        };
        let Some(catalog) = state.catalog.clone() else {
            return;
        };
        let binding = NativeSessionBinding {
            request_id: session.request_id.clone(),
            connection_generation: session.connection_generation,
        };
        if state.is_host {
            if state.local_approval_required {
                ui.label(self.t(
                    "选择本次允许对方查看和控制的屏幕",
                    "Choose screens this session may view and control",
                ));
                let id = egui::Id::new("native-local-display-consent")
                    .with(&catalog.request_id)
                    .with(catalog.sha256);
                let (mut sources, mut initial) = ui
                    .ctx()
                    .data_mut(|data| data.get_temp::<(Vec<u32>, Option<u32>)>(id))
                    .unwrap_or_default();
                for display in &state.displays {
                    let mut checked = sources.contains(&display.source);
                    ui.horizontal(|ui| {
                        if ui
                            .checkbox(
                                &mut checked,
                                format!(
                                    "{} · {} × {}",
                                    display.label, display.width, display.height
                                ),
                            )
                            .changed()
                        {
                            if checked {
                                sources.push(display.source);
                                if initial.is_none() {
                                    initial = Some(display.source);
                                }
                            } else {
                                sources.retain(|source| *source != display.source);
                                if initial == Some(display.source) {
                                    initial = None;
                                }
                            }
                        }
                        if checked
                            && ui
                                .selectable_label(
                                    initial == Some(display.source),
                                    self.t("初始屏幕", "Initial screen"),
                                )
                                .clicked()
                        {
                            initial = Some(display.source);
                        }
                    });
                }
                sources.sort_unstable();
                sources.dedup();
                let bytes = state
                    .displays
                    .iter()
                    .filter(|d| sources.contains(&d.source))
                    .map(|d| u64::from(d.width) * u64::from(d.height) * 4)
                    .sum::<u64>();
                let valid = initial.is_some_and(|source| sources.contains(&source))
                    && bytes <= 128 * 1024 * 1024;
                if bytes > 128 * 1024 * 1024 {
                    ui.colored_label(
                        ui.visuals().error_fg_color,
                        self.t(
                            "所选屏幕过多，请减少数量。",
                            "The selected screens exceed the capture budget. Select fewer screens.",
                        ),
                    );
                }
                if ui
                    .add_enabled(
                        valid,
                        egui::Button::new(self.t("分享所选屏幕", "Share selected screens")),
                    )
                    .clicked()
                    && let Some(initial_source) = initial
                {
                    self.send(
                        snapshot,
                        Command::ApproveNativeDisplays {
                            binding,
                            catalog,
                            sources: sources.clone(),
                            initial_source,
                        },
                    );
                }
                ui.ctx()
                    .data_mut(|data| data.insert_temp(id, (sources, initial)));
                ui.small(self.t("对方只能在本次允许的屏幕之间切换。结束会话会停止分享。","The other device can switch only between these approved screens. Ending this session stops sharing."));
            } else {
                ui.label(self.t("本次允许分享的屏幕", "Screens approved for this session"));
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
