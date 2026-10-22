//! One 24-unit outline vocabulary, rendered without platform-dependent glyphs.
use eframe::egui::{self, Color32, Pos2, Stroke};

#[derive(Clone, Copy)]
pub enum Icon {
    Monitor,
    Devices,
    Share,
    Network,
    Account,
    List,
    Settings,
    Refresh,
    Keyboard,
    Audio,
    Close,
    Copy,
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
                let phone = egui::Rect::from_min_max(p(15., 9.), p(23., 23.));
                ui.painter()
                    .rect_filled(phone, 1.5 * scale, ui.visuals().window_fill);
                rect((15., 9.), (23., 23.), 1.5);
                line((18., 20.), (20., 20.));
            }
        }
        Icon::Share | Icon::Network => {
            for (x, y) in [(12., 4.), (4., 19.), (20., 19.)] {
                ui.painter().circle_stroke(p(x, y), 2.5 * scale, stroke);
            }
            line((10.8, 6.5), (5.2, 16.5));
            line((13.2, 6.5), (18.8, 16.5));
            if matches!(icon, Icon::Network) {
                line((6.5, 19.), (17.5, 19.));
            }
        }
        Icon::Account => {
            ui.painter().circle_stroke(p(12., 7.), 4. * scale, stroke);
            rect((4., 14.), (20., 23.), 4.);
        }
        Icon::List => {
            for y in [5., 12., 19.] {
                line((3., y), (5., y));
                line((9., y), (21., y));
            }
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
        Icon::Keyboard => {
            rect((2., 5.), (22., 19.), 2.);
            for x in [6., 10., 14., 18.] {
                line((x, 9.), (x, 10.));
            }
            line((7., 15.), (17., 15.));
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
        Icon::Close => {
            line((6., 6.), (18., 18.));
            line((6., 18.), (18., 6.));
        }
        Icon::Copy => {
            rect((8., 8.), (22., 22.), 2.);
            line((4., 16.), (2., 16.));
            line((2., 16.), (2., 2.));
            line((2., 2.), (16., 2.));
            line((16., 2.), (16., 4.));
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
    let color = ui.style().interact(&response).text_color();
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
