import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/refactor-candidate-source-readback.py"
SPEC = importlib.util.spec_from_file_location("source_readback", SCRIPT)
READBACK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READBACK)


class SourceReadbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Readback Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "core.autocrlf", "false")
        (self.root / "tracked.txt").write_bytes(b"original\n")
        self.git("add", "tracked.txt")
        self.git("commit", "--quiet", "-m", "fixture")

    def git(self, *arguments):
        return subprocess.run(["git", *arguments], cwd=self.root, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def capture_guard(self, command, timeout=10):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = READBACK.guarded(self.root, "fixture", command, self.root, timeout)
        return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_clean_and_exact_raw_status_hash(self):
        clean = READBACK.readback(self.root, "clean")
        self.assertFalse(clean["changed"])
        self.assertEqual(clean["status_raw_sha256"], hashlib.sha256(b"").hexdigest())
        (self.root / "untracked.txt").write_bytes(b"DO_NOT_PRINT_FILE_CONTENTS")
        value = READBACK.readback(self.root, "dirty")
        raw = self.git("status", "--porcelain=v1", "-z", "--untracked-files=all")
        self.assertEqual(value["status_raw_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(value["status_raw_bytes"], len(raw))
        self.assertEqual(value["entries"][0]["status"], "??")
        self.assertNotIn("DO_NOT_PRINT_FILE_CONTENTS", json.dumps(value))

    def test_modified_and_cli_fail_closed(self):
        (self.root / "tracked.txt").write_bytes(b"changed\n")
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--root", str(self.root),
                                 "--phase", "modified"], check=False, capture_output=True)
        self.assertEqual(result.returncode, 1)
        value = json.loads(result.stdout)
        self.assertEqual(value["entries"][0]["status"], " M")
        self.assertEqual(value["entries"][0]["path"], "tracked.txt")

    def test_rename_preserves_both_paths_and_status(self):
        self.git("mv", "tracked.txt", "renamed.txt")
        value = READBACK.readback(self.root, "rename")
        self.assertEqual(len(value["entries"]), 1)
        entry = value["entries"][0]
        self.assertEqual(entry["status"], "R ")
        self.assertEqual(entry["path"], "renamed.txt")
        self.assertEqual(entry["original"]["path"], "tracked.txt")

    def test_path_entry_and_raw_sample_limits_never_hide_dirty(self):
        for index in range(70):
            (self.root / (f"{index:03d}-" + "x" * 60)).write_bytes(b"fixture")
        value = READBACK.readback(self.root, "many")
        self.assertTrue(value["changed"])
        self.assertTrue(value["truncated"])
        self.assertEqual(len(value["entries"]), READBACK.MAX_ENTRIES)
        self.assertLess(len(json.dumps(value)), 128 * 1024)
        with patch.object(READBACK, "MAX_PATH", 12), patch.object(READBACK, "MAX_STATUS", 120):
            small = READBACK.readback(self.root, "bounded")
        self.assertTrue(small["changed"])
        self.assertTrue(small["truncated"])
        self.assertTrue(small["entries"][0]["path_truncated"])
        self.assertEqual(len(small["entries"][0]["path"]), 12)
        self.assertEqual(small["status_raw_sha256"], value["status_raw_sha256"])

    @unittest.skipIf(os.name == "nt", "Windows forbids newline file names")
    def test_control_characters_are_json_escaped(self):
        (self.root / "line\nbreak\tname").write_bytes(b"fixture")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(READBACK.emit(self.root, "escaped"), 1)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(output.getvalue())["entries"][0]["path"], "line\nbreak\tname")

    def test_finally_keeps_build_failure_even_when_build_dirties_source(self):
        command = [sys.executable, "-c", "from pathlib import Path; Path('new.txt').write_text('hidden'); raise SystemExit(23)"]
        code, values = self.capture_guard(command)
        self.assertEqual(code, 23)
        self.assertEqual([v["phase"] for v in values], ["fixture-before", "fixture-finally"])
        self.assertTrue(values[-1]["changed"])

    def test_successful_build_with_dirty_source_fails_and_initial_dirty_skips_build(self):
        command = [sys.executable, "-c", "from pathlib import Path; Path('new.txt').write_text('hidden')"]
        code, _ = self.capture_guard(command)
        self.assertEqual(code, 1)
        code, _ = self.capture_guard([sys.executable, "-c", "raise SystemExit(23)"])
        self.assertEqual(code, 1)  # refused before execution, not23

    def test_timeout_has_finally_readback_and_original_timeout_result(self):
        code, values = self.capture_guard([sys.executable, "-c", "import time; time.sleep(2)"], timeout=1)
        self.assertEqual(code, 124)
        self.assertEqual(values[-1]["phase"], "fixture-finally")

    def prepare_lock(self):
        (self.root / "Cargo.lock").write_bytes(b"# fixture\nversion = 3\n")
        self.git("add", "Cargo.lock")
        self.git("commit", "--quiet", "-m", "lock fixture")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_lock_evidence_preserves_bytes_diff_and_original_failure(self):
        directory = self.prepare_lock()
        original = (self.root / "Cargo.lock").read_bytes()
        command = [sys.executable, "-c", "from pathlib import Path; Path('Cargo.lock').write_bytes(b'changed\\n'); raise SystemExit(23)"]
        with contextlib.redirect_stdout(io.StringIO()):
            code = READBACK.guarded(self.root, "lock", command, self.root, 10, directory)
        self.assertEqual(code, 23)
        self.assertEqual((directory / "before.lock").read_bytes(), original)
        self.assertEqual((directory / "after.lock").read_bytes(), b"changed\n")
        evidence = json.loads((directory / "lock-evidence.json").read_text())
        for key, filename in (("before", "before.lock"), ("after", "after.lock"), ("diff", "Cargo.lock.diff")):
            data = (directory / filename).read_bytes()
            self.assertEqual(evidence[key]["bytes"], len(data))
            self.assertEqual(evidence[key]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual((directory / "Cargo.lock.diff").read_bytes(), self.git("diff", "--no-ext-diff", "--binary", "--", "Cargo.lock"))

    def test_metadata_failure_timeout_and_missing_cargo_continue_build(self):
        directory = self.prepare_lock()
        real_run = subprocess.run
        for failure, expected in ((subprocess.CompletedProcess([], 42), 42),
                                  (subprocess.TimeoutExpired("cargo", 120), 124),
                                  (FileNotFoundError("cargo"), 127)):
            builds = []
            def fake_run(command, **kwargs):
                if command[0] == "cargo":
                    if isinstance(failure, Exception):
                        raise failure
                    return failure
                if command[0] == "fake-build":
                    builds.append(command)
                    return subprocess.CompletedProcess(command, 23)
                return real_run(command, **kwargs)
            with self.subTest(expected=expected), patch.object(READBACK.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(io.StringIO()):
                code = READBACK.guarded(self.root, "metadata", ["fake-build"], self.root, 10, directory, True)
            self.assertEqual(code, 23)
            self.assertEqual(len(builds), 1)
            evidence = json.loads((directory / "lock-evidence.json").read_text())
            self.assertEqual(evidence["locked_metadata_no_deps_exit_code"], expected)
            self.assertEqual(evidence["before"], evidence["after_metadata"])

    def test_cli_rejects_lock_evidence_inside_source(self):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--root", str(self.root),
                                 "--phase", "lock", "--lock-evidence-dir", str(self.root / "evidence"),
                                 "--", sys.executable, "-c", "raise SystemExit(23)"],
                                check=False, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"outside the source tree", result.stderr)
        self.assertFalse((self.root / "evidence").exists())


if __name__ == "__main__":
    unittest.main()
