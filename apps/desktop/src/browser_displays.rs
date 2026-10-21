use crate::DesktopApp;
use eframe::egui;
use nestlink_app_core::{BrowserHostStatus, DisplayCatalogKey, Snapshot};
use nestlink_app_ipc::wire::Command;

fn selection_id(catalog: &DisplayCatalogKey) -> egui::Id {
    egui::Id::new("browser-host-display-consent")
        .with(&catalog.request_id)
        .with(catalog.connection_generation)
        .with(catalog.sha256)
}

/// The fixed footer reads the selection after the scrolling screen list has
/// rendered. Only the exact currently offered catalog can authorize capture.
pub(super) fn approval_button(
    ui: &mut egui::Ui,
    snapshot: &Snapshot,
    english: bool,
) -> Option<Command> {
    let command = snapshot.browser_host.data.as_ref().and_then(|host| {
        if !host.displays.approval_required
            || !matches!(
                host.status,
                BrowserHostStatus::Establishing | BrowserHostStatus::Connected
            )
        {
            return None;
        }
        let catalog = host.displays.catalog.as_ref()?;
        let binding = host.binding.as_ref()?;
        if catalog.request_id != host.request_id
            || catalog.connection_generation != host.connection_generation
            || binding.request_id != host.request_id
            || binding.connection_generation != host.connection_generation
        {
            return None;
        }
        let (sources, initial) = ui
            .ctx()
            .data_mut(|data| data.get_temp::<(Vec<u32>, Option<u32>)>(selection_id(catalog)))?;
        let initial_source = initial.filter(|source| sources.contains(source))?;
        if sources.is_empty()
            || sources.iter().any(|source| {
                !host
                    .displays
                    .displays
                    .iter()
                    .any(|display| display.source == *source)
            })
        {
            return None;
        }
        let bytes: u64 = host
            .displays
            .displays
            .iter()
            .filter(|display| sources.contains(&display.source))
            .map(|display| u64::from(display.width) * u64::from(display.height) * 4)
            .sum();
        (bytes <= 128 * 1024 * 1024).then(|| Command::ApproveBrowserHostDisplays {
            binding: binding.clone(),
            catalog: catalog.clone(),
            sources,
            initial_source,
        })
    });
    ui.add_enabled(
        command.is_some(),
        egui::Button::new(if english {
            "Approve and share"
        } else {
            "批准并开始共享"
        })
        .min_size(egui::vec2(176., 40.)),
    )
    .clicked()
    .then_some(command)
    .flatten()
}

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
            if host.binding.is_none() {
                ui.small(self.t("正在准备本机屏幕批准…", "Preparing local display approval…"));
                return;
            }
            ui.separator();
            ui.label(
                egui::RichText::new(self.t(
                    "选择允许浏览器查看的屏幕",
                    "Choose screens this browser may view",
                ))
                .strong(),
            );
            ui.small(self.t(
                "选择本次允许共享的屏幕。批准后将自动连接，身份核验完成后开始共享。",
                "Choose the screens to share. Connection continues automatically after approval; sharing begins after identity verification.",
            ));
            let id = selection_id(&catalog);
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
            if bytes > 128 * 1024 * 1024 {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    self.t(
                        "所选屏幕超过采集预算，请减少数量。",
                        "The selected screens exceed the capture budget. Select fewer screens.",
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use nestlink_app_core::{BrowserHostBinding, BrowserHostView, DisplayDescriptor};
    use std::sync::Arc;

    #[test]
    fn replacing_the_catalog_during_a_click_cannot_approve_new_screens() {
        let context = egui::Context::default();
        context.enable_accesskit();
        let request_id = "00000000-0000-4000-8000-000000000010".to_owned();
        let catalog = DisplayCatalogKey {
            request_id: request_id.clone(),
            connection_generation: 1,
            revision: 1,
            sha256: [1; 32],
        };
        let mut snapshot = Snapshot::default();
        snapshot.browser_host.data = Some(Arc::new(BrowserHostView {
            request_id: request_id.clone(),
            connection_generation: 1,
            lease_sequence: 0,
            status: BrowserHostStatus::Establishing,
            host_view_authorized: false,
            binding: Some(BrowserHostBinding {
                request_id,
                session_id: "session".into(),
                controller_device_id: "controller".into(),
                host_device_id: "host".into(),
                controller_key_sha256: [1; 32],
                host_key_sha256: [2; 32],
                permit_sha256: [3; 32],
                connection_generation: 1,
            }),
            displays: nestlink_app_core::BrowserHostDisplayView {
                approval_required: true,
                catalog: Some(catalog.clone()),
                displays: vec![DisplayDescriptor {
                    source: 1,
                    left: 0,
                    top: 0,
                    width: 1920,
                    height: 1080,
                    label: "Display 1".into(),
                }],
                ..Default::default()
            },
            data: Default::default(),
            path: None,
            stop_reason: None,
            stop_effects: None,
            cleanup: None,
            failure: None,
        }));
        context
            .data_mut(|data| data.insert_temp(selection_id(&catalog), (vec![1_u32], Some(1_u32))));
        let mut position = egui::Pos2::ZERO;
        let mut button_bounds = None;
        let mut approved = 0;
        for frame in 0..12 {
            if frame == 6 || frame == 8 {
                let host = Arc::make_mut(snapshot.browser_host.data.as_mut().expect("host"));
                let current = host.displays.catalog.as_mut().expect("catalog");
                current.sha256 = if frame == 6 { [2; 32] } else { catalog.sha256 };
                current.revision = if frame == 6 { 2 } else { 1 };
            }
            let events = if [5, 7, 9, 10].contains(&frame) {
                vec![
                    egui::Event::PointerMoved(position),
                    egui::Event::PointerButton {
                        pos: position,
                        button: egui::PointerButton::Primary,
                        pressed: frame == 5 || frame == 9,
                        modifiers: Default::default(),
                    },
                ]
            } else {
                Vec::new()
            };
            let mut command = None;
            let output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(760., 560.),
                    )),
                    events,
                    ..Default::default()
                },
                |ui| {
                    command = approval_button(ui, &snapshot, true);
                },
            );
            if let Some(bounds) = output
                .platform_output
                .accesskit_update
                .expect("tree")
                .nodes
                .into_iter()
                .find_map(|(_, node)| {
                    (node.label() == Some("Approve and share"))
                        .then(|| node.bounds())
                        .flatten()
                })
            {
                button_bounds = Some(bounds);
            }
            if frame == 4 {
                let bounds = button_bounds.expect("approval button");
                position = egui::pos2(
                    ((bounds.x0 + bounds.x1) / 2.) as f32,
                    ((bounds.y0 + bounds.y1) / 2.) as f32,
                );
            }
            if let Some(Command::ApproveBrowserHostDisplays {
                catalog: approved_catalog,
                sources,
                initial_source,
                ..
            }) = command
            {
                assert_eq!(
                    frame, 10,
                    "capture approval escaped without a click on the current catalog"
                );
                assert_eq!(approved_catalog, catalog);
                assert_eq!(sources, vec![1]);
                assert_eq!(initial_source, 1);
                approved += 1;
            }
        }
        assert_eq!(approved, 1);
    }
}
