use crate::DesktopApp;
use eframe::egui;
use nestlink_app_core::{BrowserHostStatus, Snapshot};
use nestlink_app_ipc::wire::Command;

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
        let Some(catalog) = host.displays.catalog.clone() else {
            if host.status == BrowserHostStatus::Establishing {
                ui.small(self.t(
                    "正在枚举本机屏幕；尚未开始画面采集。",
                    "Enumerating local displays; capture has not started.",
                ));
            }
            return;
        };
        if host.displays.approval_required {
            let Some(binding) = host.binding.clone() else {
                ui.small(self.t("正在准备本机屏幕批准…", "Preparing local display approval…"));
                return;
            };
            ui.separator();
            ui.label(
                egui::RichText::new(self.t(
                    "选择允许浏览器查看的屏幕",
                    "Choose screens this browser may view",
                ))
                .strong(),
            );
            ui.small(self.t(
                "画面会在你批准来源子集和初始屏幕后开始采集。",
                "Capture starts after you approve the source set and initial screen.",
            ));
            let id = egui::Id::new("browser-host-display-consent")
                .with(&catalog.request_id)
                .with(catalog.connection_generation)
                .with(catalog.sha256);
            let (mut sources, mut initial) = ui
                .ctx()
                .data_mut(|data| data.get_temp::<(Vec<u32>, Option<u32>)>(id))
                .unwrap_or_default();
            for display in &host.displays.displays {
                let mut checked = sources.contains(&display.source);
                ui.horizontal(|ui| {
                    if ui
                        .checkbox(
                            &mut checked,
                            format!("{} · {} × {}", display.label, display.width, display.height),
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
            let bytes = host
                .displays
                .displays
                .iter()
                .filter(|display| sources.contains(&display.source))
                .map(|display| u64::from(display.width) * u64::from(display.height) * 4)
                .sum::<u64>();
            let valid = !sources.is_empty()
                && initial.is_some_and(|source| sources.contains(&source))
                && bytes <= 128 * 1024 * 1024;
            if bytes > 128 * 1024 * 1024 {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    self.t(
                        "所选屏幕超过采集预算，请减少数量。",
                        "The selected screens exceed the capture budget. Select fewer screens.",
                    ),
                );
            }
            if ui
                .add_enabled(
                    valid,
                    egui::Button::new(self.t("批准并开始共享", "Approve and start sharing")),
                )
                .clicked()
                && let Some(initial_source) = initial
                && !self.send(
                    snapshot,
                    Command::ApproveBrowserHostDisplays {
                        binding,
                        catalog,
                        sources: sources.clone(),
                        initial_source,
                    },
                )
            {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    self.t(
                        "批准未能送出，请检查守护进程。",
                        "Approval could not be sent. Check the daemon.",
                    ),
                );
            }
            ui.ctx()
                .data_mut(|data| data.insert_temp(id, (sources, initial)));
        } else if host.displays.approved_sources.len() > 1 {
            ui.separator();
            ui.label(self.t("本次批准的屏幕", "Screens approved for this session"));
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
}
