"""Generate the Web and Compose token adapters from config/ui-tokens.json."""
import argparse
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
CONFIG = Path("config/ui-tokens.json")
CSS = Path("apps/web/static/nestlink-tokens.css")
HEX = re.compile(r"#[0-9A-Fa-f]{6}\Z")
CSS_FONT_FAMILY = re.compile(r"[A-Za-z0-9 ,.\"'_-]{1,160}\Z")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate UI token: {key}")
        result[key] = value
    return result


def bounded_number(value, name, minimum=0, maximum=512):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"invalid UI token {name}")
    return value


def color_value(value, name):
    if not isinstance(value, str) or HEX.fullmatch(value) is None:
        raise ValueError(f"invalid UI color {name}")
    return value.lower()


def object_value(value, name):
    if not isinstance(value, dict):
        raise ValueError(f"invalid UI token object {name}")
    return value


def read_tokens(path):
    tokens = object_value(
        json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object), "document"
    )
    if type(tokens.get("schema_version")) is not int or tokens["schema_version"] != 1 or tokens.get("product") != "NestLink":
        raise ValueError("unsupported UI token schema or product")
    for mode in ("light", "dark"):
        palette = object_value(tokens.get(mode), mode)
        for key in ("primary", "primary_text", "canvas", "sidebar", "surface", "text", "muted", "border", "danger"):
            color_value(palette.get(key), f"{mode}.{key}")
    state = object_value(tokens.get("state"), "state")
    for key in ("primary_action_text", "focus", "warning", "success", "danger_action", "danger_action_text"):
        pair = object_value(state.get(key), f"state.{key}")
        for mode in ("light", "dark"):
            color_value(pair.get(mode), f"state.{key}.{mode}")
    media = object_value(tokens.get("media"), "media")
    for key in ("canvas", "foreground"):
        color_value(media.get(key), f"media.{key}")
    typography = object_value(tokens.get("type"), "type")
    for key in ("body", "small", "title", "section"):
        bounded_number(typography.get(key), f"type.{key}", 8, 64)
    for key in ("css_family", "css_code_family"):
        value = typography.get(key)
        if not isinstance(value, str) or CSS_FONT_FAMILY.fullmatch(value) is None:
            raise ValueError(f"invalid CSS font family type.{key}")
    layout = object_value(tokens.get("layout"), "layout")
    for key in ("desktop_width", "desktop_height", "minimum_width", "minimum_height", "sidebar_width",
                "sidebar_width_compact", "content_padding", "row_height", "control_height"):
        bounded_number(layout.get(key), f"layout.{key}", 1, 4096)
    spacing = object_value(tokens.get("spacing"), "spacing")
    for key in ("egui_item_horizontal", "egui_item_vertical", "egui_button_horizontal",
                "egui_button_vertical", "mobile_screen_padding", "web_mobile_padding"):
        bounded_number(spacing.get(key), f"spacing.{key}", 0, 256)
    shape = object_value(tokens.get("shape"), "shape")
    for key in ("control", "panel", "window", "sheet"):
        bounded_number(shape.get(key), f"shape.{key}", 0, 64)
    return tokens


def css_value(tokens, mode, key):
    if key == "plum":
        return tokens[mode]["primary"]
    if key == "plum-ink":
        return tokens[mode]["primary_text"]
    if key == "lavender":
        return tokens[mode]["sidebar"]
    if key == "paper":
        return tokens[mode]["surface"]
    if key == "canvas":
        return tokens[mode]["canvas"]
    if key == "ink":
        return tokens[mode]["text"]
    if key == "subtle":
        return tokens[mode]["muted"]
    if key == "line":
        return tokens[mode]["border"]
    if key == "danger-text":
        return tokens[mode]["danger"]
    if key == "media-canvas":
        return color_value(tokens["media"]["canvas"], "media.canvas")
    if key == "media-foreground":
        return color_value(tokens["media"]["foreground"], "media.foreground")
    if key in ("primary-action-text", "focus", "warning", "success", "danger-action-bg", "danger-action-text"):
        state_key = key.replace("danger-action-bg", "danger_action").replace("danger-action-text", "danger_action_text").replace("-", "_")
        return tokens["state"][state_key][mode]
    if key == "text-body":
        return f"{tokens['type']['body']}px"
    if key == "text-small":
        return f"{tokens['type']['small']}px"
    if key == "text-title":
        return f"{tokens['type']['title']}px"
    if key == "text-section":
        return f"{tokens['type']['section']}px"
    if key == "control-height":
        return f"{tokens['layout']['control_height']}px"
    if key == "row-height":
        return f"{tokens['layout']['row_height']}px"
    if key == "content-padding":
        return f"{tokens['layout']['content_padding']}px"
    if key == "sidebar-width":
        return f"{tokens['layout']['sidebar_width']}px"
    if key == "sidebar-width-compact":
        return f"{tokens['layout']['sidebar_width_compact']}px"
    if key == "mobile-padding":
        return f"{tokens['spacing']['web_mobile_padding']}px"
    if key == "font-ui":
        return tokens["type"]["css_family"]
    if key == "font-mono":
        return tokens["type"]["css_code_family"]
    if key.startswith("radius-"):
        return f"{tokens['shape'][key.removeprefix('radius-')]}px"
    raise ValueError(f"unknown CSS UI token {key}")


CSS_COLORS = (
    "plum", "plum-ink", "lavender", "canvas", "paper", "ink", "subtle", "line", "danger-text",
    "primary-action-text", "focus", "warning", "success", "danger-action-bg", "danger-action-text",
    "media-canvas", "media-foreground",
)
CSS_SIZES = (
    "text-body", "text-small", "text-title", "text-section", "control-height", "row-height",
    "content-padding", "sidebar-width", "sidebar-width-compact", "mobile-padding", "radius-control", "radius-panel", "radius-window", "radius-sheet",
)
CSS_FONTS = ("font-ui", "font-mono")


def css_variables(tokens, mode):
    items = []
    for key in CSS_COLORS + CSS_SIZES + CSS_FONTS:
        items.append(f"  --{key}: {css_value(tokens, mode, key)};")
    return items


def render_css(tokens):
    light = "\n".join(css_variables(tokens, "light"))
    dark = "\n".join(css_variables(tokens, "dark"))
    return (
        "/* Generated by scripts/refactor-ui-tokens.py from config/ui-tokens.json. */\n"
        ":root {\n" + light + "\n}\n\n"
        "@media (prefers-color-scheme: dark) {\n  :root {\n"
        + "\n".join("  " + line for line in css_variables(tokens, "dark"))
        + "\n  }\n}\n"
    )






def outputs(tokens):
    return {CSS: render_css(tokens)}


def write_outputs(tokens, check):
    stale = []
    for relative, expected in outputs(tokens).items():
        path = ROOT / relative
        if not path.resolve().is_relative_to(ROOT.resolve()) or path.is_symlink():
            raise ValueError(f"generated path escapes or links outside the workspace: {relative}")
        if check:
            if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                stale.append(relative.as_posix())
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected, encoding="utf-8", newline="\n")
            print(f"generated {relative.as_posix()}")
    if stale:
        raise ValueError("generated UI tokens are stale: " + ", ".join(stale))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if generated platform tokens are stale")
    args = parser.parse_args()
    try:
        write_outputs(read_tokens(ROOT / CONFIG), args.check)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
