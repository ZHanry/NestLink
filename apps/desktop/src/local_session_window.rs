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
        .show(context, |ui| {
            // Resize::fixed_size sets the layout limit, but egui still measures
            // the child's minimum size. Keep that measurement independent of
            // polling widgets (including nested native-session panels).
            let rect = egui::Rect::from_min_size(ui.available_rect_before_wrap().min, size);
            let mut fixed = ui.new_child(
                egui::UiBuilder::new()
                    .id_salt("local-session-fixed-content")
                    .max_rect(rect),
            );
            fixed.set_clip_rect(rect.intersect(ui.clip_rect()));
            let bounds_id = fixed.id().with("local-session-bounds");
            fixed.data_mut(|data| data.insert_temp(bounds_id, rect));
            let result = contents(&mut fixed);
            ui.advance_cursor_after_rect(rect);
            result
        })
}

fn bounds(ui: &egui::Ui) -> egui::Rect {
    // Ui::max_rect itself expands when a child raises its minimum size. Save
    // the original budget before rendering any state-dependent widgets.
    ui.data(|data| data.get_temp(ui.id().with("local-session-bounds")))
        .unwrap_or_else(|| ui.max_rect())
}

pub(super) fn body(ui: &mut egui::Ui, contents: impl FnOnce(&mut egui::Ui)) {
    // Reserve the separator (one point), its surrounding spacing and a 44px
    // action row even when there is no session, a short error or a long list.
    let bounds = bounds(ui);
    let height = (bounds.height() - 45. - 2. * ui.spacing().item_spacing.y).max(0.);
    let rect = egui::Rect::from_min_size(bounds.min, egui::vec2(bounds.width(), height));
    // A vertical-only ScrollArea expands horizontally to an unwrapped child,
    // even inside Window::fixed_size. Never propagate that child's measured
    // minimum size to the window or to the persistent action row.
    let mut body = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("local-session-body")
            .max_rect(rect),
    );
    body.set_clip_rect(rect.intersect(ui.clip_rect()));
    egui::ScrollArea::both()
        .id_salt("browser-host-details-scroll")
        .max_height(height)
        .auto_shrink([false, false])
        .show(&mut body, contents);
    ui.advance_cursor_after_rect(rect);
}

pub(super) fn footer<R>(ui: &mut egui::Ui, contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    // Position actions from the fixed container, never from the preceding
    // cursor/minimum size. Clip overflow as well as isolating measurement.
    let bounds = bounds(ui);
    let rect =
        egui::Rect::from_min_max(egui::pos2(bounds.left(), bounds.bottom() - 44.), bounds.max);
    let separator_y = rect.top() - ui.spacing().item_spacing.y;
    ui.painter().hline(
        rect.x_range(),
        separator_y,
        ui.visuals().widgets.noninteractive.bg_stroke,
    );
    let mut actions = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("local-session-footer")
            .max_rect(rect)
            .layout(egui::Layout::right_to_left(egui::Align::Center)),
    );
    actions.set_clip_rect(rect.intersect(ui.clip_rect()));
    let result = contents(&mut actions);
    ui.advance_cursor_after_rect(rect);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_stay_at_the_bottom_when_preceding_minimum_size_changes() {
        let context = egui::Context::default();
        let mut baseline = None;
        for frame in 0..20 {
            let mut geometry = None;
            let _ = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900., 680.),
                    )),
                    ..Default::default()
                },
                |ui| {
                    if let Some(window) = show(ui.ctx(), "Local sessions", &mut true, |ui| {
                        body(ui, |ui| {
                            ui.label("Session state");
                        });
                        // egui minimums and cursor movement are advisory. Even
                        // a refreshed subtree that exceeds its budget cannot
                        // move the persistent actions or expand the window.
                        if frame > 4 && frame % 2 == 0 {
                            ui.set_min_size(egui::vec2(1800., 2000.));
                            ui.add_space(400.);
                        }
                        footer(ui, |ui| {
                            ui.add_sized([84., 40.], egui::Button::new("Close")).rect
                        })
                    }) {
                        geometry = window.inner.map(|button| (window.response.rect, button));
                    }
                },
            );
            if frame == 4 {
                baseline = geometry;
            }
            if frame > 4 {
                assert_eq!(geometry, baseline, "minimum moved actions at frame {frame}");
            }
        }
    }

    #[test]
    fn unwrapped_details_cannot_expand_the_dialog_or_move_its_actions() {
        let context = egui::Context::default();
        context.global_style_mut(|style| {
            style.spacing.interact_size = egui::vec2(40., 40.);
            style.spacing.item_spacing = egui::vec2(10., 9.);
            style.spacing.button_padding = egui::vec2(12., 9.);
        });
        let size = egui::vec2(760., 560.);
        let mut baseline = None;
        for frame in 0..16 {
            let mut geometry = None;
            let _ = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    ..Default::default()
                },
                |ui| {
                    if let Some(window) = show(ui.ctx(), "Local sessions", &mut true, |ui| {
                        body(ui, |ui| {
                            egui::Frame::group(ui.style()).show(ui, |ui| {
                                if frame > 4 && frame % 2 == 0 {
                                    ui.horizontal(|ui| {
                                        ui.monospace("Unwrapped diagnostic values ".repeat(12));
                                    });
                                } else {
                                    ui.label("Preparing local displays");
                                }
                            });
                        });
                        footer(ui, |ui| {
                            ui.add_sized([84., 40.], egui::Button::new("Close")).rect
                        })
                    }) {
                        geometry = window.inner.map(|button| (window.response.rect, button));
                    }
                },
            );
            if frame == 4 {
                baseline = geometry;
            } else if frame > 4 {
                assert_eq!(geometry, baseline, "details moved actions at frame {frame}");
            }
        }
    }

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
        for scale in [1., 1.25, 1.5, 2.] {
            for stop in [false, true] {
                refreshed_footer_click(scale, stop);
            }
        }
    }

    fn refreshed_footer_click(scale: f32, stop: bool) {
        let context = egui::Context::default();
        context.set_pixels_per_point(scale);
        let size = egui::vec2(1140., 840.) / scale;
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
                                ui.horizontal(|ui| {
                                    ui.monospace(if frame >= 6 {
                                        "Unwrapped refreshed diagnostic ".repeat(12)
                                    } else {
                                        "Preparing".into()
                                    });
                                });
                            }
                        });
                        footer(ui, |ui| {
                            let close = ui.add_sized([84., 40.], egui::Button::new("Close"));
                            let stop_button = ui.add_sized([84., 40.], egui::Button::new("Stop"));
                            let button = if stop { stop_button } else { close };
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
        assert_eq!(clicks, 1, "missed click at scale {scale}, stop {stop}");
    }
}
