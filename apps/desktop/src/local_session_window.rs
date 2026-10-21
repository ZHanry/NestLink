//! Geometry for the local sharing dialog, independent of polling contents.
use eframe::egui;

pub(super) fn show<R>(
    context: &egui::Context,
    title: &str,
    open: &mut bool,
    contents: impl FnOnce(&mut egui::Ui) -> R,
) -> Option<egui::InnerResponse<Option<R>>> {
    // This is an egui window inside the main viewport. Its initial content
    // measurement must never choose its size again after a polling update.
    let available = context.content_rect().size();
    let size =
        egui::vec2(560., 480.).min((available - egui::vec2(48., 100.)).max(egui::vec2(320., 220.)));
    egui::Window::new(title)
        .id(egui::Id::new("browser-host-details"))
        .fixed_size(size)
        .collapsible(false)
        .open(open)
        .show(context, contents)
}

pub(super) fn body(ui: &mut egui::Ui, contents: impl FnOnce(&mut egui::Ui)) {
    // Reserve the separator (one point), its surrounding spacing and a 44px
    // action row even when there is no session, a short error or a long list.
    let height = (ui.available_height() - 45. - 2. * ui.spacing().item_spacing.y).max(0.);
    egui::ScrollArea::vertical()
        .id_salt("browser-host-details-scroll")
        .max_height(height)
        .auto_shrink([false, false])
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
        .show(ui, contents);
}

pub(super) fn footer<R>(ui: &mut egui::Ui, contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.add(egui::Separator::default().spacing(1.));
    // A persistent subtree also keeps widget IDs stable between pointer down
    // and up when the number of widgets in the scrolling contents changes.
    ui.push_id("local-session-footer", |ui| {
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), 44.),
            egui::Layout::right_to_left(egui::Align::Center),
            contents,
        )
        .inner
    })
    .inner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_and_long_diagnostics_cannot_resize_dialog_or_move_footer() {
        let context = egui::Context::default();
        for size in [egui::vec2(1200., 800.), egui::vec2(760., 560.)] {
            let mut baseline = None;
            for frame in 0..24 {
                let mut geometry = None;
                let _ = context.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        ..Default::default()
                    },
                    |ui| {
                        let mut open = true;
                        if let Some(window) = show(ui.ctx(), "Local sessions", &mut open, |ui| {
                            body(ui, |ui| {
                                if frame > 4 && frame % 2 == 0 {
                                    ui.colored_label(egui::Color32::RED, "Network request failed.");
                                    for _ in 0..16 {
                                        ui.label("Connection diagnostics and display details");
                                    }
                                } else {
                                    ui.label("Waiting for local screen approval");
                                }
                            });
                            footer(ui, |ui| {
                                ui.add_sized([120., 40.], egui::Button::new("Close")).rect
                            })
                        }) {
                            geometry = window.inner.map(|button| (window.response.rect, button));
                        }
                    },
                );
                if frame == 4 {
                    baseline = geometry;
                } else if frame > 4 {
                    assert_eq!(
                        geometry, baseline,
                        "polling moved the dialog at {size:?}, frame {frame}"
                    );
                    if let Some((window, _)) = geometry {
                        assert!(
                            egui::Rect::from_min_size(egui::Pos2::ZERO, size).contains_rect(window)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn footer_click_survives_content_changing_between_pointer_down_and_up() {
        let context = egui::Context::default();
        let size = egui::vec2(760., 560.);
        let mut position = egui::Pos2::ZERO;
        let mut clicks = 0;
        for frame in 0..10 {
            let events = if frame == 5 || frame == 7 {
                vec![
                    egui::Event::PointerMoved(position),
                    egui::Event::PointerButton {
                        pos: position,
                        button: egui::PointerButton::Primary,
                        pressed: frame == 5,
                        modifiers: Default::default(),
                    },
                ]
            } else {
                Vec::new()
            };
            let _ = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    events,
                    ..Default::default()
                },
                |ui| {
                    show(ui.ctx(), "Local sessions", &mut true, |ui| {
                        body(ui, |ui| {
                            for _ in 0..if frame >= 6 { 20 } else { 1 } {
                                ui.label("The refreshed error and diagnostics are longer");
                            }
                        });
                        footer(ui, |ui| {
                            let button = ui.add_sized([120., 40.], egui::Button::new("Close"));
                            if frame == 4 {
                                position = button.rect.center();
                            }
                            if button.clicked() {
                                clicks += 1;
                            }
                        });
                    });
                },
            );
        }
        assert_eq!(clicks, 1, "a polling update swallowed the footer click");
    }
}
