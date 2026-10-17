"""Development receipts cover actual selected inputs and detect source drift."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "refactor-run-check.py"
SPEC = importlib.util.spec_from_file_location("refactor_run_check", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class SourceReceiptTests(unittest.TestCase):
    def setUp(self):
        self.owned = tempfile.TemporaryDirectory(prefix="nestlink-check-receipt-")
        self.addCleanup(self.owned.cleanup)
        self.root = Path(self.owned.name).resolve()
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
            (self.root / name).write_text("fixture\n", encoding="utf-8")
        self.app = self.root / "apps" / "web"
        self.app.mkdir(parents=True)
        (self.app / "页面.rs").write_text("original\n", encoding="utf-8")
        subprocess.run(["git", "add", "--", "."], cwd=self.root, check=True)
        (self.root / ".gitignore").write_text("apps/web/build/\n", encoding="utf-8")
        (self.app / "build").mkdir()
        (self.app / "build" / "cache.bin").write_bytes(b"not a source input")

    def test_receipt_includes_new_sources_but_excludes_other_apps_and_ignored_cache(self):
        (self.app / "new.rs").write_text("new input\n", encoding="utf-8")
        other = self.root / "apps" / "other"
        other.mkdir()
        (other / "other.rs").write_text("unrelated owner\n", encoding="utf-8")
        paths = {item["path"] for item in CHECK.source_snapshot(self.root, ["apps/web"])}
        self.assertEqual(paths, {
            "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "apps/web/页面.rs", "apps/web/new.rs"
        })

    def test_real_content_change_invalidates_a_previous_receipt(self):
        before = CHECK.source_snapshot(self.root, ["apps/web"])
        (self.app / "页面.rs").write_text("changed during a command\n", encoding="utf-8")
        self.assertNotEqual(before, CHECK.source_snapshot(self.root, ["apps/web"]))

    def test_scope_cannot_follow_an_outside_path_or_git_option(self):
        for prefix in ("../outside", "--all"):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                CHECK.source_snapshot(self.root, [prefix])


if __name__ == "__main__":
    unittest.main()
