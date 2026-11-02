"""Lifecycle regressions for the optional hosted sampler, without invoking perf."""

import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "capacity_perf", pathlib.Path(__file__).with_name("network-capacity-perf.py")
)
PERF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PERF)


class PerfLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name)
        self.output = self.directory / "artifact"
        self.output.mkdir()
        self.executable = self.directory / "original-test"
        self.executable.write_bytes(b"unchanged test executable identity")
        self.command = [str(self.executable), "--exact", "original-case", "--ignored"]
        self.sampler = PERF.PerfSampler(self.output, "exact-source-fixture")
        self.environment = mock.patch.dict(PERF.os.environ, {
            "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_TEMP": str(self.directory)
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def ready(self):
        self.sampler.tool = "/fixture/perf"
        self.sampler.private = self.directory / "private-raw"
        self.sampler.private.mkdir()
        self.sampler.metadata["status"] = "ready"

    def processes(self, target_result, recorder_result):
        target = mock.Mock(pid=123)
        target.wait.return_value = target_result
        recorder = mock.Mock(pid=456)
        recorder.wait.return_value = recorder_result
        recorder.poll.return_value = recorder_result
        return target, recorder

    def test_install_failure_still_executes_original_and_retains_real_return_code(self):
        target_record = {"return_code": None}
        stdout, stderr = object(), object()
        install_failure = subprocess.CompletedProcess(["apt-get"], 100)
        target_failure = subprocess.CompletedProcess(self.command, 37)
        with mock.patch.object(PERF.subprocess, "run", side_effect=[
            install_failure, target_failure
        ]) as run:
            self.sampler.prepare()
            self.assertEqual(self.sampler.metadata["status"], "failed")
            result = self.sampler.run(self.command, stdout, stderr, 660, target_record)
        self.assertEqual(result.returncode, 37)
        self.assertEqual(target_record["return_code"], 37)
        self.assertEqual(self.sampler.metadata["target_return_code"], 37)
        self.assertEqual(self.sampler.metadata["status"], "failed")
        run.assert_called_with(self.command, stdout=stdout, stderr=stderr, timeout=660)
        self.assertEqual(run.call_count, 2)

    def test_timeout_kills_waits_only_original_target_and_stops_its_own_recorder(self):
        self.ready()
        target, recorder = self.processes(-9, 0)
        recorder.poll.return_value = None
        target_record = {"return_code": None}
        with mock.patch.object(PERF.subprocess, "Popen", side_effect=[target, recorder]) as start, \
                mock.patch.object(PERF.time, "monotonic", side_effect=[0, 661, 662]), \
                mock.patch.object(self.sampler, "_command", return_value=True) as cleanup, \
                mock.patch.object(self.sampler, "_report"):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.sampler.run(self.command, object(), object(), 660, target_record)
        target.kill.assert_called_once_with()
        target.wait.assert_called_once_with()
        recorder.kill.assert_not_called()
        recorder.wait.assert_called_once_with(timeout=15)
        cleanup.assert_called_once_with(
            "perf-stop", ["sudo", "-n", "kill", "-INT", "--", "-456"],
            10, allow_failure=True
        )
        self.assertEqual(start.call_args_list[0].args[0], self.command)
        self.assertTrue(start.call_args_list[1].kwargs["start_new_session"])
        self.assertEqual(target_record["return_code"], -9)
        self.assertTrue(self.sampler.metadata["target_timed_out"])

    def test_perf_failure_cannot_replace_workload_error_or_output(self):
        self.ready()
        target, recorder = self.processes(101, 2)
        target_record = {"return_code": None}
        stdout_path = self.output / "execution.log"
        stderr_path = self.output / "execution.stderr.log"
        stdout_path.write_bytes(b"original test failure\n")
        stderr_path.write_bytes(b"original assertion and backtrace\n")
        with stdout_path.open("ab") as stdout, stderr_path.open("ab") as stderr:
            with mock.patch.object(PERF.subprocess, "Popen", side_effect=[target, recorder]) as start, \
                    mock.patch.object(self.sampler, "_report"):
                result = self.sampler.run(self.command, stdout, stderr, 660, target_record)
            self.assertIs(start.call_args_list[0].kwargs["stdout"], stdout)
            self.assertIs(start.call_args_list[0].kwargs["stderr"], stderr)
            self.assertIsNot(start.call_args_list[1].kwargs["stderr"], stderr)
        self.assertEqual(result.returncode, 101)
        self.assertEqual(target_record["return_code"], 101)
        self.assertEqual(self.sampler.metadata["target_return_code"], 101)
        self.assertEqual(self.sampler.metadata["status"], "failed")
        self.assertEqual(stdout_path.read_bytes(), b"original test failure\n")
        self.assertEqual(stderr_path.read_bytes(), b"original assertion and backtrace\n")

    def test_natural_target_exit_race_does_not_mark_recorder_premature(self):
        self.ready()
        target, recorder = self.processes(0, 0)
        target.wait.side_effect = [subprocess.TimeoutExpired(self.command, 1), 0]
        target.poll.return_value = 0
        target_record = {"return_code": None}
        with mock.patch.object(PERF.subprocess, "Popen", side_effect=[target, recorder]), \
                mock.patch.object(self.sampler, "_command") as cleanup, \
                mock.patch.object(self.sampler, "_report"):
            result = self.sampler.run(self.command, object(), object(), 660, target_record)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.sampler.metadata["failures"], [])
        self.assertNotEqual(self.sampler.metadata["status"], "failed")
        cleanup.assert_not_called()
        target.kill.assert_not_called()

    def test_zero_samples_cannot_pass_diagnostic(self):
        self.ready()
        raw = self.sampler.private / "perf.data"
        raw.write_bytes(b"fixture header with no samples")
        (self.output / "perf-data-size.log").write_text(str(raw.stat().st_size))
        (self.output / "perf-data-sha256.log").write_text("0" * 64 + "  private/perf.data\n")
        (self.output / "perf-report.log").write_text("# Samples: 0 of event 'cpu-clock:u'\n")
        with mock.patch.object(self.sampler, "_command", return_value=True):
            self.sampler._report(raw)
        self.assertEqual(self.sampler.metadata["status"], "failed")
        self.assertIn("nonzero samples", self.sampler.metadata["failures"][-1])
        self.assertFalse(self.sampler.metadata["acceptance_qualified"])

    def test_nonzero_report_can_pass_only_diagnostic_without_exporting_raw_data(self):
        self.ready()
        raw = self.sampler.private / "perf.data"
        raw.write_bytes(b"private fixture samples")
        (self.output / "perf-data-size.log").write_text(str(raw.stat().st_size))
        (self.output / "perf-data-sha256.log").write_text("1" * 64 + "  private/perf.data\n")
        (self.output / "perf-report.log").write_text("# Samples: 12K of event 'cpu-clock:u'\n")
        with mock.patch.object(self.sampler, "_command", return_value=True):
            self.sampler._report(raw)
        self.assertEqual(self.sampler.metadata["status"], "passed")
        self.assertEqual(self.sampler.metadata["samples_display"], "12K")
        self.assertFalse(self.sampler.metadata["acceptance_qualified"])
        self.assertFalse(self.sampler.metadata["raw_data_exported"])
        self.assertFalse((self.output / "perf.data").exists())
        self.assertTrue(raw.is_file())


if __name__ == "__main__":
    unittest.main()
