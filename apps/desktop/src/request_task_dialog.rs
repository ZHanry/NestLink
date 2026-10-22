//! Request/approval task layout. Body measurement cannot resize the modal.
use eframe::egui;

pub(super) fn show<R>(
    context: &egui::Context,
    title: &str,
    contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::ModalResponse<R> {
    let viewport = context.content_rect();
    let frame = egui::Frame::popup(&context.global_style()).inner_margin(16);
    let available = (viewport.size() - egui::vec2(32., 32.)).max(egui::vec2(1., 1.));
    let size =
        egui::vec2(620., 560.).min((available - frame.total_margin().sum()).max(egui::Vec2::ZERO));
    let outer = size + frame.total_margin().sum();
    let id = egui::Id::new("remote-request-task");
    egui::Modal::new(id)
        // Anchor a known rectangle, rather than last frame's measured body.
        .area(
            egui::Modal::default_area(id)
                .anchor(egui::Align2::LEFT_TOP, (viewport.size() - outer) * 0.5),
        )
        .frame(frame)
        .show(context, |ui| {
            let rect = egui::Rect::from_min_size(ui.available_rect_before_wrap().min, size);
            let mut fixed = ui.new_child(
                egui::UiBuilder::new()
                    .id_salt("request-task-fixed")
                    .max_rect(rect),
            );
            fixed.set_clip_rect(rect.intersect(ui.clip_rect()));
            let key = fixed.id().with("request-task-bounds");
            fixed.data_mut(|data| data.insert_temp(key, rect));
            let heading = fixed.heading(title);
            let body_top = heading.rect.bottom() + fixed.spacing().item_spacing.y;
            let key = fixed.id().with("request-task-body-top");
            fixed.data_mut(|data| data.insert_temp(key, body_top));
            let result = contents(&mut fixed);
            ui.advance_cursor_after_rect(rect);
            result
        })
}

pub(super) fn bounds(ui: &egui::Ui) -> egui::Rect {
    ui.data(|data| data.get_temp(ui.id().with("request-task-bounds")))
        .unwrap_or_else(|| ui.max_rect())
}

pub(super) fn body(ui: &mut egui::Ui, contents: impl FnOnce(&mut egui::Ui)) {
    let bounds = bounds(ui);
    let top = ui
        .data(|data| data.get_temp(ui.id().with("request-task-body-top")))
        .unwrap_or(bounds.top());
    let bottom = (bounds.bottom() - 44. - 2. * ui.spacing().item_spacing.y - 1.).max(top);
    let rect = egui::Rect::from_min_max(
        egui::pos2(bounds.left(), top),
        egui::pos2(bounds.right(), bottom),
    );
    let mut body = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("request-task-body")
            .max_rect(rect),
    );
    body.set_clip_rect(rect.intersect(ui.clip_rect()));
    egui::ScrollArea::both()
        .id_salt("request-task-scroll")
        .max_height(rect.height())
        .auto_shrink([false, false])
        .show(&mut body, contents);
    ui.advance_cursor_after_rect(rect);
}

pub(super) fn footer<R>(ui: &mut egui::Ui, contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let bounds = bounds(ui);
    let rect = egui::Rect::from_min_max(
        egui::pos2(bounds.left(), (bounds.bottom() - 44.).max(bounds.top())),
        bounds.max,
    );
    ui.painter().hline(
        rect.x_range(),
        rect.top() - ui.spacing().item_spacing.y,
        ui.visuals().widgets.noninteractive.bg_stroke,
    );
    let mut footer = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("request-task-footer")
            .max_rect(rect),
    );
    footer.set_clip_rect(rect.intersect(ui.clip_rect()));
    let key = footer.id().with("request-task-bounds");
    footer.data_mut(|data| data.insert_temp(key, rect));
    let result = contents(&mut footer);
    ui.advance_cursor_after_rect(rect);
    result
}

pub(super) fn action_rect(ui: &egui::Ui, close: bool) -> egui::Rect {
    let bounds = bounds(ui);
    let gap = ui.spacing().item_spacing.x;
    let width = ((bounds.width() - gap) * 0.5).clamp(0., 168.);
    let right = bounds.right() - if close { 0. } else { width + gap };
    egui::Rect::from_min_size(
        egui::pos2(right - width, bounds.top() + 2.),
        egui::vec2(width, bounds.height().min(40.)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_modal_remeasurement_reproduces_movement_prevented_by_fixed_budget() {
        let mut spread = Vec::new();
        for legacy in [true, false] {
            let context = egui::Context::default();
            let mut positions = Vec::new();
            for frame in 0..20 {
                let mut position = None;
                let _ = context.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1200., 800.),
                        )),
                        ..Default::default()
                    },
                    |parent| {
                        let context = parent.ctx().clone();
                        let contents = |ui: &mut egui::Ui| {
                            if frame > 4 && frame % 2 == 0 {
                                ui.horizontal(|ui| {
                                    ui.monospace("unwrapped diagnostic ".repeat(100));
                                });
                            } else {
                                ui.label("Waiting for approval");
                            }
                        };
                        if legacy {
                            let modal = egui::Modal::new(egui::Id::new("remote-request-task"))
                                .show(&context, |ui| {
                                    ui.set_width(
                                        (context.content_rect().width() - 48.).clamp(280., 620.),
                                    );
                                    ui.heading("Connection and approval");
                                    egui::ScrollArea::vertical()
                                        .max_height(
                                            (context.content_rect().height() - 180.)
                                                .clamp(180., 460.),
                                        )
                                        .auto_shrink([false, false])
                                        .id_salt("request-task-scroll")
                                        .show(ui, contents);
                                    ui.separator();
                                    ui.horizontal(|ui| ui.button("Close details").rect).inner
                                });
                            position = Some(modal.inner.min);
                        } else {
                            let modal = show(&context, "Connection and approval", |ui| {
                                body(ui, contents);
                                footer(ui, |ui| {
                                    ui.put(
                                        action_rect(ui, true),
                                        egui::Button::new("Close details"),
                                    )
                                    .rect
                                })
                            });
                            position = Some(modal.inner.min);
                        }
                    },
                );
                if frame > 4
                    && let Some(position) = position
                {
                    positions.push(position);
                }
            }
            let min = positions.iter().map(|p| p.x).fold(f32::INFINITY, f32::min);
            let max = positions
                .iter()
                .map(|p| p.x)
                .fold(f32::NEG_INFINITY, f32::max);
            spread.push(max - min);
        }
        assert!(
            spread[0] > 1.,
            "legacy body measurement did not reproduce movement"
        );
        assert_eq!(spread[1], 0., "body measurement moved the repaired task");
    }

    #[test]
    fn body_overflow_cannot_resize_the_task_or_shift_its_actions() {
        for scale in [1., 1.25, 1.5, 2.] {
            for size in [egui::vec2(1200., 800.), egui::vec2(760., 560.)] {
                let context = egui::Context::default();
                context.set_pixels_per_point(scale);
                let mut baseline = None;
                for frame in 0..24 {
                    let mut actual = None;
                    let _ = context.run_ui(
                        egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                            ..Default::default()
                        },
                        |ui| {
                            let modal = show(ui.ctx(), "Connection and approval", |ui| {
                                body(ui, |ui| {
                                    if frame > 4 && frame % 2 == 0 {
                                        ui.horizontal(|ui| {
                                            ui.monospace("diagnostic ".repeat(200));
                                        });
                                        ui.set_min_size(egui::vec2(2000., 3000.));
                                    } else {
                                        ui.label("Awaiting approval");
                                    }
                                });
                                footer(ui, |ui| {
                                    let cancel = ui.put(
                                        action_rect(ui, false),
                                        egui::Button::new("Cancel connection"),
                                    );
                                    let close = ui
                                        .add_enabled_ui(frame % 2 == 0, |ui| {
                                            ui.put(
                                                action_rect(ui, true),
                                                egui::Button::new("Close details"),
                                            )
                                        })
                                        .inner;
                                    (cancel.id, cancel.rect, close.id, close.rect)
                                })
                            });
                            actual = Some((modal.response.rect, modal.inner));
                        },
                    );
                    if frame == 4 {
                        baseline = actual;
                    }
                    if frame > 4 {
                        assert_eq!(
                            actual, baseline,
                            "frame {frame}, scale {scale}, size {size}"
                        );
                    }
                }
            }
        }
    }
}
