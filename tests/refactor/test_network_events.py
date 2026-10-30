"""Namespace evidence requires exact real test results and behavioral receipts."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("network_events", ROOT / "scripts/refactor-network-events.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def transcript(test_name):
    if test_name == RUNNER.EVENT_TEST:
        behavior = "\n".join(
            f"isolated kernel notification: {json.dumps(operation)}, generation {generation}"
            for generation, operation in enumerate(RUNNER.EVENT_OPERATIONS, start=1))
    else:
        behavior = ("isolated Linux media route: ipv4_ipv6_same_socket=true, pinned_ifindex=2, "
            "replacement_ifindex=4, wrong_source_down_rename_delete_no_fallback=true")
    return (f"\nrunning 1 test\ntest {test_name} ... ok\n\nsuccesses:\n\n"
        f"---- {test_name} stdout ----\n"
        "isolated network namespace: self=net:[4026533001], init=net:[4026531992]\n"
        f"{behavior}\n\nsuccesses:\n    {test_name}\n\n"
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 27 filtered out; finished in 0.05s\n")


class NetworkEventEvidenceTests(unittest.TestCase):
    def test_both_real_test_receipts_are_accepted(self):
        for test_name in RUNNER.TESTS:
            with self.subTest(test=test_name):
                self.assertEqual(RUNNER.validate_execution(test_name, 0, transcript(test_name)), [])

    def test_zero_tests_cannot_pass_with_a_successful_exit(self):
        output = "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.00s\n"
        for test_name in RUNNER.TESTS:
            with self.subTest(test=test_name):
                errors = RUNNER.validate_execution(test_name, 0, output)
                self.assertIn("exact-test-count", errors)
                self.assertIn("exact-test-passed", errors)
                self.assertIn("one-successful-result", errors)

    def test_wrong_exact_test_name_is_rejected(self):
        errors = RUNNER.validate_execution(RUNNER.PINNING_TEST, 0, transcript(RUNNER.EVENT_TEST))
        self.assertIn("exact-test-passed", errors)
        self.assertIn("captured-test-output", errors)
        self.assertEqual(RUNNER.validate_execution("unknown", 0, ""), ["unknown-test"])

    def test_ignored_failed_and_nonzero_cases_are_rejected(self):
        test_name = RUNNER.EVENT_TEST
        output = transcript(test_name)
        for status in ("ignored", "FAILED"):
            with self.subTest(status=status):
                self.assertIn("exact-test-passed", RUNNER.validate_execution(test_name, 0,
                    output.replace(f"test {test_name} ... ok", f"test {test_name} ... {status}")))
        for returncode in (1, -9, None):
            with self.subTest(returncode=returncode):
                self.assertIn("process-exit", RUNNER.validate_execution(test_name, returncode, output))

    def test_duplicate_test_runs_or_results_are_rejected(self):
        test_name = RUNNER.EVENT_TEST
        output = transcript(test_name)
        for extra, error in (("running 1 test\n", "exact-test-count"),
                (f"test {test_name} ... ok\n", "exact-test-passed"),
                ("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0s\n", "one-successful-result")):
            with self.subTest(error=error):
                self.assertIn(error, RUNNER.validate_execution(test_name, 0, output + extra))

    def test_summary_cannot_report_missing_or_ignored_work(self):
        test_name = RUNNER.EVENT_TEST
        for original, replacement in (("1 passed", "0 passed"), ("0 ignored", "1 ignored"),
                ("0 failed", "1 failed"), ("0 measured", "1 measured")):
            with self.subTest(replacement=replacement):
                self.assertIn("one-successful-result", RUNNER.validate_execution(test_name, 0,
                    transcript(test_name).replace(original, replacement)))

    def test_namespace_must_be_reported_once_and_differ_from_initial_namespace(self):
        test_name = RUNNER.EVENT_TEST
        output = transcript(test_name)
        marker = "isolated network namespace: self=net:[4026533001], init=net:[4026531992]\n"
        for replacement in ("", marker + marker, marker.replace("4026533001", "4026531992")):
            with self.subTest(replacement=replacement):
                self.assertIn("isolated-namespace", RUNNER.validate_execution(test_name, 0,
                    output.replace(marker, replacement)))

    def test_every_kernel_event_operation_and_generation_is_required(self):
        test_name = RUNNER.EVENT_TEST
        output = transcript(test_name)
        first = f"isolated kernel notification: {json.dumps(RUNNER.EVENT_OPERATIONS[0])}, generation 1\n"
        for damaged in (output.replace(first, ""), output + first,
                output.replace("generation 2", "generation 1"),
                output.replace(json.dumps(RUNNER.EVENT_OPERATIONS[0]), "[invalid-json]")):
            with self.subTest(output=damaged):
                self.assertIn("kernel-event-operations", RUNNER.validate_execution(test_name, 0, damaged))

    def test_pinning_requires_both_families_lifecycle_and_new_index(self):
        test_name = RUNNER.PINNING_TEST
        output = transcript(test_name)
        for original, replacement in (("ipv4_ipv6_same_socket=true", "ipv4_ipv6_same_socket=false"),
                ("wrong_source_down_rename_delete_no_fallback=true", "wrong_source_down_rename_delete_no_fallback=false"),
                ("replacement_ifindex=4", "replacement_ifindex=2"),
                ("pinned_ifindex=2", "pinned_ifindex=0")):
            with self.subTest(replacement=replacement):
                self.assertIn("pinned-interface-lifecycle", RUNNER.validate_execution(test_name, 0,
                    output.replace(original, replacement)))

    def test_each_case_gets_a_separate_exact_unshare_invocation(self):
        results = [subprocess.CompletedProcess([], 0, transcript(test_name).encode()) for test_name in RUNNER.TESTS]
        with mock.patch.object(RUNNER.os, "geteuid", return_value=1000, create=True), \
                mock.patch.object(RUNNER.subprocess, "run", side_effect=results) as run:
            executions = RUNNER.execute_cases(ROOT, Path("platform-network-tests"))
        self.assertEqual(len(executions), 2)
        self.assertTrue(all(not item["errors"] for item in executions))
        self.assertEqual(run.call_count, 2)
        for call, test_name in zip(run.call_args_list, RUNNER.TESTS):
            command = call.args[0]
            self.assertEqual(command[:4], ["sudo", "-n", "unshare", "--net"])
            self.assertEqual(command[5:], ["--ignored", "--exact", test_name, "--show-output"])
            self.assertEqual(call.kwargs["timeout"], 120)
        self.assertTrue(all(len(item["stdout_sha256"]) == 64 for item in executions))

    def test_failure_retains_evidence_and_still_runs_the_second_fresh_namespace(self):
        results = [subprocess.CompletedProcess([], 1, b"unshare failed\n"),
            subprocess.CompletedProcess([], 0, transcript(RUNNER.PINNING_TEST).encode())]
        with mock.patch.object(RUNNER.os, "geteuid", return_value=0, create=True), \
                mock.patch.object(RUNNER.subprocess, "run", side_effect=results) as run:
            executions = RUNNER.execute_cases(ROOT, Path("platform-network-tests"))
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0][:2], ["unshare", "--net"])
        self.assertIn("process-exit", executions[0]["errors"])
        self.assertEqual(executions[0]["output"], "unshare failed\n")
        self.assertEqual(executions[1]["errors"], [])

    def test_timeout_is_recorded_as_failed_even_if_a_complete_receipt_was_printed(self):
        results = [subprocess.TimeoutExpired([], 120, output=transcript(RUNNER.EVENT_TEST).encode()),
            subprocess.CompletedProcess([], 0, transcript(RUNNER.PINNING_TEST).encode())]
        with mock.patch.object(RUNNER.os, "geteuid", return_value=0, create=True), \
                mock.patch.object(RUNNER.subprocess, "run", side_effect=results):
            executions = RUNNER.execute_cases(ROOT, Path("platform-network-tests"))
        self.assertIsNone(executions[0]["returncode"])
        self.assertIn("process-exit", executions[0]["errors"])
        self.assertEqual(executions[1]["errors"], [])

    def test_launcher_failure_preserves_a_failed_receipt(self):
        with mock.patch.object(RUNNER.os, "geteuid", return_value=0, create=True), \
                mock.patch.object(RUNNER.subprocess, "run", side_effect=FileNotFoundError("unshare")):
            executions = RUNNER.execute_cases(ROOT, Path("platform-network-tests"))
        self.assertEqual(len(executions), 2)
        for execution in executions:
            self.assertIn("process-exit", execution["errors"])
            self.assertIsNone(execution["namespace"])
            self.assertIn("Could not start isolated kernel test", execution["output"])


if __name__ == "__main__":
    unittest.main()
