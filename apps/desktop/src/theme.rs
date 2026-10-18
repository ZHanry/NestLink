use eframe::egui::{self, Color32, FontData, FontDefinitions, FontFamily, FontId, TextStyle};
use serde::Deserialize;
use std::{collections::BTreeMap, io, path::PathBuf, sync::Arc};

#[derive(Deserialize)]
pub struct Tokens {
    pub light: Palette,
    pub dark: Palette,
    pub layout: Layout,
    pub spacing: Spacing,
    pub shape: Shape,
    pub state: StateColors,
    pub media: MediaColors,
    #[serde(rename = "type")]
    pub typography: Typography,
}
#[derive(Deserialize)]
pub struct Palette {
    pub primary: String,
    pub primary_text: String,
    pub canvas: String,
    pub sidebar: String,
    pub surface: String,
    pub text: String,
    pub muted: String,
    pub border: String,
    pub danger: String,
}
#[derive(Deserialize)]
pub struct Layout {
    pub desktop_width: f32,
    pub desktop_height: f32,
    pub minimum_width: f32,
    pub minimum_height: f32,
    pub sidebar_width: f32,
    pub sidebar_width_compact: f32,
    pub content_padding: f32,
    pub row_height: f32,
    pub control_height: f32,
}
#[derive(Deserialize)]
pub struct Typography {
    pub body: f32,
    pub small: f32,
    pub title: f32,
    pub section: f32,
}
#[derive(Deserialize)]
pub struct Spacing {
    pub egui_item_horizontal: f32,
    pub egui_item_vertical: f32,
    pub egui_button_horizontal: f32,
    pub egui_button_vertical: f32,
}
#[derive(Deserialize)]
pub struct Shape {
    pub control: u8,
    pub panel: u8,
    pub window: u8,
    pub sheet: u8,
}
#[derive(Deserialize)]
pub struct StateColors {
    pub primary_action_text: ColorPair,
    pub focus: ColorPair,
    pub warning: ColorPair,
    pub success: ColorPair,
    pub danger_action: ColorPair,
    pub danger_action_text: ColorPair,
}
#[derive(Deserialize)]
pub struct MediaColors {
    pub canvas: String,
    pub foreground: String,
}
#[derive(Deserialize)]
pub struct ColorPair {
    pub light: String,
    pub dark: String,
}
pub fn tokens() -> Result<Tokens, serde_json::Error> {
    serde_json::from_str(include_str!("../../../config/ui-tokens.json"))
}
pub fn color(value: &str) -> Color32 {
    u32::from_str_radix(value.trim_start_matches('#'), 16)
        .map(|rgb| Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8))
        .unwrap_or(Color32::GRAY)
}
pub fn apply(context: &egui::Context, tokens: &Tokens, dark: bool) {
    context.set_theme(if dark {
        egui::Theme::Dark
    } else {
        egui::Theme::Light
    });
    let palette = if dark { &tokens.dark } else { &tokens.light };
    let primary_action_text = if dark {
        &tokens.state.primary_action_text.dark
    } else {
        &tokens.state.primary_action_text.light
    };
    let focus = if dark {
        &tokens.state.focus.dark
    } else {
        &tokens.state.focus.light
    };
    let warning = if dark {
        &tokens.state.warning.dark
    } else {
        &tokens.state.warning.light
    };
    let mut visuals = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    visuals.override_text_color = Some(color(&palette.text));
    visuals.panel_fill = color(&palette.canvas);
    visuals.window_fill = color(&palette.surface);
    visuals.selection.bg_fill = color(&palette.primary);
    visuals.selection.stroke.color = color(primary_action_text);
    visuals.hyperlink_color = color(&palette.primary_text);
    visuals.error_fg_color = color(&palette.danger);
    visuals.warn_fg_color = color(warning);
    visuals.window_corner_radius = egui::CornerRadius::same(tokens.shape.window);
    visuals.menu_corner_radius = egui::CornerRadius::same(tokens.shape.sheet);
    visuals.widgets.noninteractive.bg_fill = color(&palette.surface);
    visuals.widgets.noninteractive.bg_stroke.color = color(&palette.border);
    visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(tokens.shape.panel);
    visuals.widgets.inactive.bg_fill = color(&palette.surface);
    visuals.widgets.inactive.bg_stroke.color = color(&palette.border);
    visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(tokens.shape.control);
    visuals.widgets.hovered.bg_stroke.color = color(focus);
    visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(tokens.shape.control);
    visuals.widgets.active.bg_stroke.color = color(focus);
    visuals.widgets.active.corner_radius = egui::CornerRadius::same(tokens.shape.control);
    visuals.widgets.hovered.weak_bg_fill = color(&palette.primary).gamma_multiply(0.08);
    visuals.widgets.active.weak_bg_fill = color(&palette.primary).gamma_multiply(0.14);
    visuals.widgets.noninteractive.fg_stroke.color = color(&palette.muted);
    visuals.extreme_bg_color = color(&palette.surface);
    visuals.faint_bg_color = color(&palette.sidebar);
    context.set_visuals(visuals);
    context.global_style_mut(|style| {
        style.spacing.interact_size = egui::vec2(40., tokens.layout.control_height);
        style.spacing.icon_width = 18.;
        style.spacing.icon_spacing = 8.;
        style.spacing.text_edit_width = 420.;
        style.spacing.scroll.bar_width = 7.;
        style.spacing.item_spacing = egui::vec2(
            tokens.spacing.egui_item_horizontal,
            tokens.spacing.egui_item_vertical,
        );
        style.spacing.button_padding = egui::vec2(
            tokens.spacing.egui_button_horizontal,
            tokens.spacing.egui_button_vertical,
        );
        style.text_styles = BTreeMap::from([
            (
                TextStyle::Heading,
                FontId::new(tokens.typography.title, FontFamily::Proportional),
            ),
            (
                TextStyle::Body,
                FontId::new(tokens.typography.body, FontFamily::Proportional),
            ),
            (
                TextStyle::Button,
                FontId::new(tokens.typography.body, FontFamily::Proportional),
            ),
            (
                TextStyle::Small,
                FontId::new(tokens.typography.small, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(tokens.typography.small, FontFamily::Monospace),
            ),
        ]);
    });
}
/// Use fonts already supplied/licensed by the OS. No Microsoft or unreviewed
/// font binaries are embedded, extracted into artifacts or redistributed.
pub fn fonts(context: &egui::Context) -> io::Result<bool> {
    let mut definition = FontDefinitions::default();
    #[cfg(windows)]
    let paths = {
        let windows = PathBuf::from(
            std::env::var_os("WINDIR")
                .ok_or_else(|| io::Error::other("Windows font location unavailable"))?,
        )
        .join("Fonts");
        vec![
            (windows.join("segoeuivf.ttf"), false),
            (windows.join("segoeui.ttf"), false),
            (windows.join("msyh.ttc"), true),
        ]
    };
    #[cfg(not(windows))]
    let paths = vec![
        (
            PathBuf::from("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            false,
        ),
        (
            PathBuf::from("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
            true,
        ),
        (
            PathBuf::from("/usr/share/fonts/truetype/wqy/wqy-microhei.ttc"),
            true,
        ),
    ];
    let mut cjk = false;
    let mut names = Vec::new();
    for (index, (path, chinese)) in paths.into_iter().enumerate() {
        if std::fs::metadata(&path).map_or(true, |metadata| {
            !metadata.is_file() || metadata.len() > 64 * 1024 * 1024
        }) {
            continue;
        }
        if let Ok(data) = std::fs::read(path) {
            if data.len() > 64 * 1024 * 1024 {
                continue;
            }
            let name = format!("system-{index}");
            definition
                .font_data
                .insert(name.clone(), Arc::new(FontData::from_owned(data)));
            names.push(name);
            cjk |= chinese;
        }
    }
    if names.is_empty() {
        return Err(io::Error::other("system UI fonts unavailable"));
    }
    definition
        .families
        .insert(FontFamily::Proportional, names.clone());
    definition
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .extend(names);
    context.set_fonts(definition);
    Ok(cjk)
}
pub fn icon(size: u32) -> egui::IconData {
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    let segments = [
        [154., 342., 154., 196.],
        [154., 196., 200., 150.],
        [358., 170., 358., 316.],
        [358., 316., 312., 362.],
        [190., 190., 322., 322.],
    ];
    for y in 0..size {
        for x in 0..size {
            let point = egui::pos2(
                (x as f32 + 0.5) * 512. / size as f32,
                (y as f32 + 0.5) * 512. / size as f32,
            );
            let white = segments.iter().any(|segment| {
                let first = egui::pos2(segment[0], segment[1]);
                let last = egui::pos2(segment[2], segment[3]);
                let delta = last - first;
                let fraction = ((point - first).dot(delta) / delta.length_sq()).clamp(0., 1.);
                (point - (first + delta * fraction)).length() <= 22.
            });
            rgba.extend_from_slice(if white {
                &[255, 255, 255, 255]
            } else {
                &[36, 107, 206, 255]
            });
        }
    }
    egui::IconData {
        rgba,
        width: size,
        height: size,
    }
}
