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
        changed["spacing"]["web_mobile_padding"] = 31
        changed["shape"]["control"] = 11
        changed["media"]["canvas"] = "#abcdef"
        changed["layout"]["sidebar_width"] = 240
        changed["layout"]["sidebar_width_compact"] = 190

        css = TOKENS.render_css(changed)

        self.assertIn("--plum: #123456;", css)
        self.assertIn("--primary-action-text: #654321;", css)
        self.assertIn("--media-canvas: #abcdef;", css)
        self.assertIn("--font-ui: " + changed["type"]["css_family"] + ";", css)
        self.assertIn("--mobile-padding: 31px;", css)
        self.assertIn("--radius-control: 11px;", css)
        self.assertIn("--sidebar-width: 240px;", css)
        self.assertIn("--sidebar-width-compact: 190px;", css)

    def test_platform_surfaces_consume_generated_ui_tokens(self):
        web_css = (ROOT / "apps" / "web" / "static" / "nestlink.css").read_text(encoding="utf-8")
        desktop = (ROOT / "apps" / "desktop" / "src" / "lib.rs").read_text(encoding="utf-8")

        self.assertIn("font-size: var(--text-small)", web_css)
        self.assertIn("self.tokens.media.canvas", desktop)
        self.assertIn("tokens.layout.control_height", (ROOT / "apps" / "desktop" / "src" / "theme.rs").read_text(encoding="utf-8"))

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
