"""Regression tests for the shared UI-token source and generated adapters."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "refactor-ui-tokens.py"
SPEC = importlib.util.spec_from_file_location("refactor_ui_tokens", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
TOKENS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOKENS)


class UiTokenTests(unittest.TestCase):
    def setUp(self):
        self.tokens = TOKENS.read_tokens(ROOT / "config" / "ui-tokens.json")

    def test_checked_in_adapters_match_the_source(self):
        TOKENS.write_outputs(self.tokens, check=True)

    def test_palette_spacing_and_shape_changes_reach_platform_adapters(self):
        changed = deepcopy(self.tokens)
        changed["light"]["primary"] = "#123456"
        changed["state"]["primary_action_text"]["dark"] = "#654321"
        changed["spacing"]["mobile_screen_padding"] = 31
        changed["shape"]["control"] = 11
        changed["media"]["canvas"] = "#abcdef"

        css = TOKENS.render_css(changed)
        kotlin = TOKENS.render_android(changed)

        self.assertIn("--plum: #123456;", css)
        self.assertIn("--primary-action-text: #654321;", css)
        self.assertIn("--media-canvas: #abcdef;", css)
        self.assertIn("--font-ui: system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif;", css)
        self.assertIn("--sidebar-width: 216px;", css)
        self.assertIn("--sidebar-width-compact: 194px;", css)
        self.assertIn("val lightPrimary = Color(0xFF123456)", kotlin)
        self.assertIn("val darkPrimaryActionText = Color(0xFF654321)", kotlin)
        self.assertIn("val mediaCanvas = Color(0xFFABCDEF)", kotlin)
        self.assertIn("val lightWarning = Color(0xFF966313)", kotlin)
        self.assertIn("val darkSuccess = Color(0xFF91D8A8)", kotlin)
        self.assertIn("RoundedCornerShape(11.dp)", kotlin)
        self.assertIn("mobileScreenPadding = 31.dp", kotlin)

    def test_platform_surfaces_consume_generated_ui_tokens(self):
        web_css = (ROOT / "apps" / "web" / "static" / "nestlink.css").read_text(encoding="utf-8")
        android_activity = (ROOT / "apps" / "android" / "app" / "src" / "main" / "java" / "com" / "zhanry" / "nestlink" / "MainActivity.kt").read_text(encoding="utf-8")
        android_canvas = (ROOT / "apps" / "android" / "app" / "src" / "main" / "java" / "com" / "zhanry" / "nestlink" / "RemoteVideoCanvas.kt").read_text(encoding="utf-8")
        desktop = (ROOT / "apps" / "desktop" / "src" / "lib.rs").read_text(encoding="utf-8")

        self.assertIn("font-size: var(--text-small)", web_css)
        self.assertIn("NestLinkUiTokens.mobileScreenPadding", android_activity)
        self.assertIn("NestLinkUiTokens.mediaCanvas", android_canvas)
        self.assertIn("NestLinkUiTokens.mediaForeground", android_canvas)
        self.assertIn("NestLinkUiTokens.lightFocus", android_canvas)
        self.assertIn("self.tokens.media.canvas", desktop)
        self.assertIn("self.tokens.layout.row_height", (ROOT / "apps" / "desktop" / "src" / "remote.rs").read_text(encoding="utf-8"))

    def test_duplicate_keys_and_invalid_numeric_tokens_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            duplicate = Path(temporary) / "duplicate.json"
            duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate UI token"):
                TOKENS.read_tokens(duplicate)

            non_object = Path(temporary) / "non-object.json"
            non_object.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid UI token object document"):
                TOKENS.read_tokens(non_object)

            invalid = deepcopy(self.tokens)
            invalid["spacing"]["egui_item_horizontal"] = True
            malformed = Path(temporary) / "invalid.json"
            malformed.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid UI token spacing.egui_item_horizontal"):
                TOKENS.read_tokens(malformed)

            invalid["spacing"]["egui_item_horizontal"] = 10
            invalid["type"]["css_family"] = "sans-serif; color: red"
            malformed.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid CSS font family type.css_family"):
                TOKENS.read_tokens(malformed)


if __name__ == "__main__":
    unittest.main()
