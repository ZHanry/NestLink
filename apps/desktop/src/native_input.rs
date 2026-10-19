use eframe::egui::{self, Pos2, Rect};
use nestlink_app_core::NativeInputLayout;

pub(crate) fn pointer_to_logical(
    position: Pos2,
    image: Rect,
    layout: &NativeInputLayout,
) -> Option<(i32, i32)> {
    if !image.is_positive()
        || !image.contains(position)
        || position.x >= image.right()
        || position.y >= image.bottom()
        || layout.width == 0
        || layout.height == 0
    {
        return None;
    }
    let x = ((position.x - image.left()) / image.width() * layout.width as f32).floor();
    let y = ((position.y - image.top()) / image.height() * layout.height as f32).floor();
    let x = (x as i64).clamp(0, i64::from(layout.width) - 1);
    let y = (y as i64).clamp(0, i64::from(layout.height) - 1);
    Some((
        i32::try_from(i64::from(layout.left) + x).ok()?,
        i32::try_from(i64::from(layout.top) + y).ok()?,
    ))
}

pub(crate) fn pointer_button(button: egui::PointerButton) -> u8 {
    match button {
        egui::PointerButton::Primary => 1,
        egui::PointerButton::Secondary => 2,
        egui::PointerButton::Middle => 3,
        egui::PointerButton::Extra1 => 4,
        egui::PointerButton::Extra2 => 5,
    }
}

pub(crate) fn key_usage(key: egui::Key) -> Option<u16> {
    let name = format!("{key:?}");
    let bytes = name.as_bytes();
    if bytes.len() == 1 && bytes[0].is_ascii_uppercase() {
        return Some(4 + u16::from(bytes[0] - b'A'));
    }
    if let Some(digit) = name.strip_prefix("Num")
        && let Ok(digit) = digit.parse::<u8>()
    {
        return Some(match digit {
            1..=9 => 0x1d + u16::from(digit),
            0 => 0x27,
            _ => return None,
        });
    }
    if let Some(function) = name.strip_prefix('F')
        && let Ok(function) = function.parse::<u8>()
    {
        return match function {
            1..=12 => Some(0x39 + u16::from(function)),
            13..=24 => Some(0x68 + u16::from(function - 13)),
            _ => None,
        };
    }
    Some(match name.as_str() {
        "Enter" => 0x28,
        "Escape" => 0x29,
        "Backspace" => 0x2a,
        "Tab" => 0x2b,
        "Space" => 0x2c,
        "Minus" => 0x2d,
        "Equals" => 0x2e,
        "OpenBracket" => 0x2f,
        "CloseBracket" => 0x30,
        "Backslash" => 0x31,
        "Semicolon" => 0x33,
        "Quote" => 0x34,
        "Backtick" => 0x35,
        "Comma" => 0x36,
        "Period" => 0x37,
        "Slash" => 0x38,
        "CapsLock" => 0x39,
        "PrintScreen" => 0x46,
        "ScrollLock" => 0x47,
        "Pause" => 0x48,
        "Insert" => 0x49,
        "Home" => 0x4a,
        "PageUp" => 0x4b,
        "Delete" => 0x4c,
        "End" => 0x4d,
        "PageDown" => 0x4e,
        "ArrowRight" => 0x4f,
        "ArrowLeft" => 0x50,
        "ArrowDown" => 0x51,
        "ArrowUp" => 0x52,
        _ => return None,
    })
}

pub(crate) fn key_produces_text(key: egui::Key) -> bool {
    use egui::Key::*;

    matches!(
        key,
        Space
            | Colon
            | Comma
            | Backslash
            | Slash
            | Pipe
            | Questionmark
            | Exclamationmark
            | OpenBracket
            | CloseBracket
            | OpenCurlyBracket
            | CloseCurlyBracket
            | Backtick
            | Minus
            | Period
            | Plus
            | Equals
            | Semicolon
            | Quote
            | Num0
            | Num1
            | Num2
            | Num3
            | Num4
            | Num5
            | Num6
            | Num7
            | Num8
            | Num9
            | A
            | B
            | C
            | D
            | E
            | F
            | G
            | H
            | I
            | J
            | K
            | L
            | M
            | N
            | O
            | P
            | Q
            | R
            | S
            | T
            | U
            | V
            | W
            | X
            | Y
            | Z
    )
}

pub(crate) fn has_shortcut_modifier(modifiers: egui::Modifiers) -> bool {
    modifiers.ctrl || modifiers.alt || modifiers.command || modifiers.mac_cmd
}

pub(crate) fn modifier_usages(modifiers: egui::Modifiers) -> [bool; 4] {
    [
        modifiers.ctrl,
        modifiers.shift,
        modifiers.alt,
        modifiers.mac_cmd,
    ]
}

pub(crate) fn clamp_text(text: &str) -> Option<String> {
    if text.is_empty() || text.len() > 1_800 {
        return None;
    }
    (!text
        .chars()
        .any(|character| character.is_control() && character != '\n' && character != '\t'))
    .then(|| text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> NativeInputLayout {
        NativeInputLayout {
            binding: nestlink_app_core::NativeInputBinding {
                request_id: "00000000-0000-4000-8000-000000000001".into(),
                connection_generation: 2,
                source: 0,
                input_epoch: 3,
                layout_epoch: 4,
            },
            left: -100,
            top: 20,
            width: 200,
            height: 100,
            scroll_supported: true,
        }
    }

    #[test]
    fn maps_contained_points_into_negative_origin_layout() {
        let image = Rect::from_min_max(Pos2::new(10.0, 20.0), Pos2::new(210.0, 120.0));
        assert_eq!(
            pointer_to_logical(Pos2::new(10.0, 20.0), image, &layout()),
            Some((-100, 20))
        );
        assert_eq!(
            pointer_to_logical(Pos2::new(209.9, 119.9), image, &layout()),
            Some((99, 119))
        );
        assert_eq!(
            pointer_to_logical(Pos2::new(210.0, 20.0), image, &layout()),
            None
        );
        assert_eq!(
            pointer_to_logical(Pos2::new(10.0, 120.0), image, &layout()),
            None
        );
        assert_eq!(
            pointer_to_logical(Pos2::new(210.0, 120.0), image, &layout()),
            None
        );
    }

    #[test]
    fn maps_standard_keys_and_rejects_unmapped_commands() {
        assert_eq!(key_usage(egui::Key::A), Some(4));
        assert_eq!(key_usage(egui::Key::Num1), Some(0x1e));
        assert_eq!(key_usage(egui::Key::Enter), Some(0x28));
        assert_eq!(key_usage(egui::Key::ArrowUp), Some(0x52));
        assert_eq!(key_usage(egui::Key::Copy), None);
    }

    #[test]
    fn identifies_text_keys_and_shortcut_modifiers() {
        assert!(key_produces_text(egui::Key::A));
        assert!(key_produces_text(egui::Key::Space));
        assert!(key_produces_text(egui::Key::Questionmark));
        assert!(!key_produces_text(egui::Key::Enter));
        assert!(!key_produces_text(egui::Key::ArrowLeft));
        assert!(!has_shortcut_modifier(egui::Modifiers::NONE));
        assert!(has_shortcut_modifier(egui::Modifiers::CTRL));
        assert!(has_shortcut_modifier(egui::Modifiers::ALT));
    }
}
