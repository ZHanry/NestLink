import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("required_checks", Path(__file__).parents[2] / "scripts/refactor-required-checks.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


class RequiredChecks(unittest.TestCase):
    def fixture(self):
        return {name: [{"id": index, "run_number": 7, "run_attempt": 1, "head_sha": "a" * 40,
                        "event": "push", "path": ".github/workflows/" + name, "status": "completed",
                        "conclusion": "success", "html_url": "https://github.com/ZHanry/NestLink/actions/runs/1"}]
                for index, name in enumerate(checks.WORKFLOWS)}

    def test_exact_sha_success(self):
        self.assertEqual(len(checks.select_runs("a" * 40, self.fixture())), 5)

    def test_missing_wrong_sha_and_untrusted_path_are_rejected(self):
        for field, value in (("head_sha", "b" * 40), ("path", ".github/workflows/other.yml")):
            fixture = self.fixture()
            fixture[checks.WORKFLOWS[0]][0][field] = value
            with self.assertRaises(ValueError):
                checks.select_runs("a" * 40, fixture)
        with self.assertRaises(ValueError):
            checks.select_runs("a" * 40, {})

    def test_latest_failed_pending_or_rerun_blocks_an_older_success(self):
        for status, conclusion in (("completed", "failure"), ("in_progress", None), ("queued", None), ("completed", "cancelled")):
            fixture = self.fixture()
            runs = fixture[checks.WORKFLOWS[0]]
            runs.append(dict(runs[0], run_number=8, status=status, conclusion=conclusion))
            with self.assertRaises(ValueError):
                checks.select_runs("a" * 40, fixture)
        fixture = self.fixture()
        fixture[checks.WORKFLOWS[0]].append(dict(fixture[checks.WORKFLOWS[0]][0], run_attempt=2, conclusion="failure"))
        with self.assertRaises(ValueError):
            checks.select_runs("a" * 40, fixture)
