//! One 24-unit outline vocabulary, rendered without platform-dependent glyphs.
use eframe::egui::{self, Color32, Pos2, Stroke};

#[derive(Clone, Copy)]
pub enum Icon {
    Monitor,
    Devices,
    Share,
    Account,
    Settings,
    Refresh,
    Audio,
    Close,
    Spaces,
    Network,
    Server,
    Audit,
    Shield,
    Bell,
    Help,
    Theme,
    Minimize,
    Maximize,
}

pub fn tool_button(ui: &mut egui::Ui, icon: Icon, label: &str) -> egui::Response {
    let response = ui.add(
        egui::Button::new("")
            .frame(false)
            .min_size(egui::vec2(34., 28.)),
    );
    paint(
        ui,
        icon,
        response.rect.center(),
        16.,
        ui.style().interact(&response).text_color(),
    );
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, ui.is_enabled(), label)
    });
    response.on_hover_text(label)
}

/// Display the original PNG asset, shared with the window and tray icon.
pub fn brand(ui: &egui::Ui, rect: egui::Rect) {
    let id = egui::Id::new("nestlink-original-brand-texture");
    let texture = ui
        .ctx()
        .data(|data| data.get_temp::<egui::TextureHandle>(id));
    let texture = texture.or_else(|| {
        let icon = crate::theme::icon(64).ok()?;
        let image = egui::ColorImage::from_rgba_unmultiplied(
            [icon.width as usize, icon.height as usize],
            &icon.rgba,
        );
        let texture = ui
            .ctx()
            .load_texture("NestLink logo", image, egui::TextureOptions::LINEAR);
        ui.ctx()
            .data_mut(|data| data.insert_temp(id, texture.clone()));
        Some(texture)
    });
    if let Some(texture) = texture {
        ui.painter().image(
            texture.id(),
            rect,
            egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1., 1.)),
            Color32::WHITE,
        );
    }
}

pub fn paint(ui: &egui::Ui, icon: Icon, center: Pos2, size: f32, color: Color32) {
    let scale = size / 24.;
    let p = |x: f32, y: f32| center + egui::vec2(x - 12., y - 12.) * scale;
    let stroke = Stroke::new(1.7 * scale, color);
    let line = |a: (f32, f32), b: (f32, f32)| {
        ui.painter()
            .line_segment([p(a.0, a.1), p(b.0, b.1)], stroke)
    };
    let rect = |a: (f32, f32), b: (f32, f32), radius: f32| {
        ui.painter().rect_stroke(
            egui::Rect::from_min_max(p(a.0, a.1), p(b.0, b.1)),
            radius * scale,
            stroke,
            egui::StrokeKind::Inside,
        )
    };
    match icon {
        Icon::Monitor | Icon::Devices => {
            rect((3., 3.), (21., 16.), 2.);
            line((12., 16.), (12., 21.));
            line((7., 21.), (17., 21.));
            if matches!(icon, Icon::Devices) {
                let monitor = egui::Rect::from_min_max(p(12., 10.), p(24., 20.));
                ui.painter()
                    .rect_filled(monitor, 1.5 * scale, ui.visuals().window_fill);
                rect((12., 10.), (24., 20.), 1.5);
                line((18., 20.), (18., 23.));
                line((15., 23.), (21., 23.));
            }
        }
        Icon::Share => {
            for (x, y) in [(12., 4.), (4., 19.), (20., 19.)] {
                ui.painter().circle_stroke(p(x, y), 2.5 * scale, stroke);
            }
            line((10.8, 6.5), (5.2, 16.5));
            line((13.2, 6.5), (18.8, 16.5));
        }
        Icon::Account => {
            ui.painter().circle_stroke(p(12., 7.), 4. * scale, stroke);
            rect((4., 14.), (20., 23.), 4.);
        }
        Icon::Settings => {
            ui.painter().circle_stroke(center, 7. * scale, stroke);
            ui.painter().circle_stroke(center, 2.5 * scale, stroke);
            for (x, y) in [(0., -10.), (0., 10.), (-10., 0.), (10., 0.)] {
                line((12. + x * 0.7, 12. + y * 0.7), (12. + x, 12. + y));
            }
        }
        Icon::Refresh => {
            ui.painter().add(egui::Shape::line(
                vec![
                    p(20., 8.),
                    p(16., 4.),
                    p(8., 4.),
                    p(4., 8.),
                    p(4., 16.),
                    p(8., 20.),
                    p(16., 20.),
                    p(20., 16.),
                ],
                stroke,
            ));
            line((20., 3.), (20., 9.));
            line((14., 9.), (20., 9.));
        }
        Icon::Audio => {
            line((3., 9.), (7., 9.));
            line((7., 9.), (13., 4.));
            line((13., 4.), (13., 20.));
            line((13., 20.), (7., 15.));
            line((7., 15.), (3., 15.));
            line((3., 15.), (3., 9.));
            line((18., 7.), (21., 12.));
            line((21., 12.), (18., 17.));
        }
        Icon::Minimize => {
            line((5., 12.), (19., 12.));
        }
        Icon::Maximize => {
            rect((5., 5.), (19., 19.), 1.);
        }
        Icon::Spaces | Icon::Network => {
            rect((8., 2.), (16., 8.), 1.);
            rect((2., 16.), (9., 22.), 1.);
            rect((15., 16.), (22., 22.), 1.);
            line((12., 8.), (12., 12.));
            line((5., 12.), (19., 12.));
            line((5., 12.), (5., 16.));
            line((19., 12.), (19., 16.));
        }
        Icon::Server => {
            rect((3., 3.), (21., 10.), 2.);
            rect((3., 14.), (21., 21.), 2.);
            line((6., 6.), (8., 6.));
            line((6., 17.), (8., 17.));
        }
        Icon::Audit => {
            rect((5., 2.), (20., 22.), 2.);
            for y in [7., 12., 17.] {
                line((9., y), (16., y));
            }
        }
        Icon::Shield => {
            ui.painter().add(egui::Shape::closed_line(
                vec![
                    p(12., 2.),
                    p(21., 6.),
                    p(19., 16.),
                    p(12., 22.),
                    p(5., 16.),
                    p(3., 6.),
                ],
                stroke,
            ));
            line((8., 12.), (11., 15.));
            line((11., 15.), (16., 9.));
        }
        Icon::Bell => {
            ui.painter().add(egui::Shape::line(
                vec![
                    p(5., 17.),
                    p(7., 14.),
                    p(7., 7.),
                    p(10., 4.),
                    p(14., 4.),
                    p(17., 7.),
                    p(17., 14.),
                    p(19., 17.),
                    p(5., 17.),
                ],
                stroke,
            ));
            line((10., 21.), (14., 21.));
        }
        Icon::Help => {
            ui.painter().circle_stroke(center, 9. * scale, stroke);
            line((9., 8.), (12., 6.));
            line((12., 6.), (15., 9.));
            line((15., 9.), (12., 12.));
            line((12., 12.), (12., 14.));
            ui.painter().circle_filled(p(12., 18.), scale, color);
        }
        Icon::Theme => {
            ui.painter().circle_stroke(center, 5. * scale, stroke);
            for (x, y) in [(12., 1.), (12., 23.), (1., 12.), (23., 12.)] {
                let v = p(x, y) - center;
                ui.painter()
                    .line_segment([center + v * 0.75, center + v], stroke);
            }
        }
        Icon::Close => {
            line((6., 6.), (18., 18.));
            line((6., 18.), (18., 6.));
        }
    }
}

pub fn button(ui: &mut egui::Ui, icon: Icon, label: &str) -> egui::Response {
    let response = ui.button(format!("     {label}"));
    button_icon(ui, icon, &response);
    response
}

pub fn button_at(ui: &mut egui::Ui, rect: egui::Rect, icon: Icon, label: &str) -> egui::Response {
    let response = ui.put(rect, egui::Button::new(format!("     {label}")));
    button_icon(ui, icon, &response);
    response
}

fn button_icon(ui: &egui::Ui, icon: Icon, response: &egui::Response) {
    let color = ui.style().interact(response).text_color();
    paint(
        ui,
        icon,
        response.rect.left_center() + egui::vec2(17., 0.),
        18.,
        color,
    );
}

pub fn badge(ui: &mut egui::Ui, icon: Icon, size: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    ui.painter().rect_filled(
        rect,
        10.,
        ui.visuals().selection.bg_fill.gamma_multiply(0.10),
    );
    paint(
        ui,
        icon,
        rect.center(),
        size * 0.52,
        ui.visuals().hyperlink_color,
    );
}
