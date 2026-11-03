"""Resident log collection regressions; executed on GitHub-hosted Actions."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "offline_resident_check",
    Path(__file__).resolve().parents[2] / "scripts/refactor-offline-resident-check.py",
)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def transcript(name="resident", status="ok", summary="1 passed; 0 failed; 0 ignored;"):
    return f"running 1 test\ntest {name} ... {status}\n\ntest result: ok. {summary}\n"


class ResidentEvidenceTests(unittest.TestCase):
    def test_grandchild_stderr_cannot_split_the_harness_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout, stderr = root / "stdout.log", root / "stderr.log"
            child = (
                "import subprocess, sys; "
                "sys.stdout.write('running 1 test\\ntest resident ... '); sys.stdout.flush(); "
                "subprocess.run([sys.executable, '-c', "
                "\"import sys; sys.stderr.write('xkbcomp: platform warning\\\\n')\"], check=True); "
                "sys.stdout.write('ok\\n\\ntest result: ok. 1 passed; 0 failed; 0 ignored;\\n')"
            )
            code = RUNNER.run_logged([sys.executable, "-c", child], stdout, stderr,
                                     cwd=root, timeout=10)
            self.assertEqual(code, 0)
            self.assertEqual(stdout.read_text(), transcript())
            self.assertEqual(stderr.read_text(), "xkbcomp: platform warning\n")
            self.assertTrue(RUNNER.test_results(stdout.read_text(), code, 1, {"resident"})["passed"])

    def test_real_failed_command_retains_stderr_and_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout, stderr = root / "stdout.log", root / "stderr.log"
            child = "import sys; sys.stderr.write('original failure\\n'); sys.exit(7)"
            code = RUNNER.run_logged([sys.executable, "-c", child], stdout, stderr,
                                     cwd=root, timeout=10)
            self.assertEqual(code, 7)
            self.assertEqual(stderr.read_text(), "original failure\n")
            self.assertFalse(RUNNER.test_results(stdout.read_text(), code, 1, {"resident"})["passed"])

    def test_timeout_retains_both_original_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout, stderr = root / "stdout.log", root / "stderr.log"
            child = (
                "import sys, time; print('started', flush=True); "
                "print('pending', file=sys.stderr, flush=True); time.sleep(30)"
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                RUNNER.run_logged([sys.executable, "-c", child], stdout, stderr,
                                  cwd=root, timeout=2)
            self.assertEqual(stdout.read_text(), "started\n")
            self.assertEqual(stderr.read_text(), "pending\n")

    def test_original_merged_warning_remains_a_failed_receipt(self):
        original = transcript().replace(" ... ok", " ... xkbcomp warning\nok")
        result = RUNNER.test_results(original, 0, 1, {"resident"})
        self.assertEqual(result["cases"], [])
        self.assertEqual(result["summaries"], [("1", "0", "0")])
        self.assertFalse(result["passed"])

    def test_wrong_duplicate_missing_failed_and_ignored_cases_are_rejected(self):
        for text in (
            transcript(name="different"),
            transcript() + transcript(),
            "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored;\n",
            transcript(status="FAILED", summary="0 passed; 1 failed; 0 ignored;"),
            transcript(status="ignored", summary="0 passed; 0 failed; 1 ignored;"),
            transcript(summary="1 passed; 0 failed; 1 ignored;"),
            transcript().split("test result:")[0],
        ):
            with self.subTest(text=text):
                self.assertFalse(RUNNER.test_results(text, 0, 1, {"resident"})["passed"])
        self.assertFalse(RUNNER.test_results(transcript(), 101, 1, {"resident"})["passed"])


if __name__ == "__main__":
    unittest.main()
