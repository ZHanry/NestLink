"""Lifecycle regressions for the optional hosted sampler, without invoking perf."""

import copy
import importlib.util
import json
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


class PerfPhaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name)
        self.output = self.directory / "artifact"
        self.output.mkdir()
        self.sampler = PERF.PerfSampler(self.output, "exact-source-fixture", phase_reporting=True)
        self.phase = self.sampler.metadata["phase_reporting"]
        self.phase["clock_anchors"] = [
            {"label": "target_start", "realtime_ns": 100_000_000_000,
             "monotonic_before_ns": 50_000_000_000, "monotonic_after_ns": 50_000_000_100},
            {"label": "target_end", "realtime_ns": 120_000_000_000,
             "monotonic_before_ns": 70_000_000_000, "monotonic_after_ns": 70_000_000_100},
        ]
        self.events = [
            {"stage": "before_setup", "at_unix_ms": 100100},
            {"stage": "all_hosts_ready", "at_unix_ms": 110000},
            *[{"stage": "multiplex_control_ready", "wave": 0, "pair": pair,
               "at_unix_ms": 110100 + pair} for pair in range(20)],
            # Flow elapsed durations cannot supply an absolute phase boundary.
            {"stage": "flow_ready", "pair": 0, "flow": 0, "open_microseconds": 2},
        ]
        self.raw = self.directory / "private" / "perf.data"
        self.raw.parent.mkdir()
        self.raw.write_bytes(b"private fixture sampling data")
        self.sampler.private = self.raw.parent
        self.sampler.tool = "/fixture/perf"
        self.sampler.metadata["status"] = "ready"
        self.sampler.metadata["target_return_code"] = 101
        self.write_events()

    def write_events(self):
        (self.output / "samples.jsonl").write_text(
            "".join(json.dumps(event) + "\n" for event in self.events)
        )

    def report_command(self, name, argv, timeout):
        if name == "perf-phase-header":
            text = "# clockid: realtime (0)\n"
        else:
            text = "# Samples: 3 of event 'cpu-clock:u'\n  100.00%  3  fixture  [.] symbol\n"
        (self.output / (name + ".log")).write_text(text)
        return True

    def test_phase_windows_use_existing_records_with_excluded_millisecond_bands(self):
        windows = self.sampler._phase_windows()
        self.assertEqual([window["name"] for window in windows], [
            "setup", "hosted-ready-to-all-controls-recorded", "after-all-controls-recorded"
        ])
        self.assertEqual([window["time_argument"] for window in windows], [
            "100.101000000,109.999999999", "110.001000000,110.118999999",
            "110.120000000,120.000000000"
        ])
        self.assertTrue(all(window["clock_source"] == "CLOCK_REALTIME" for window in windows))
        self.assertTrue(all(window["boundary_quantization_ns"] == 1_000_000 for window in windows))

    def test_observed_forward_and_backward_clock_jumps_refuse_phase_attribution(self):
        original = copy.deepcopy(self.phase["clock_anchors"])
        for jump in (20_000_000, -20_000_000):
            with self.subTest(jump=jump):
                self.phase["clock_anchors"] = copy.deepcopy(original)
                self.phase["clock_anchors"][-1]["realtime_ns"] += jump
                with self.assertRaisesRegex(ValueError, "clock jump"):
                    self.sampler._phase_windows()
        self.assertEqual(self.sampler.metadata["target_return_code"], 101)

    def test_missing_duplicate_reversed_and_unquantified_boundaries_are_refused(self):
        original = copy.deepcopy(self.events)
        cases = {
            "missing": original[:-2] + original[-1:],
            "duplicate": original + [original[2]],
            "reversed": [original[0], {"stage": "all_hosts_ready", "at_unix_ms": 99999}, *original[2:]],
            "missing_timestamp": [*original[:2], {"stage": "multiplex_control_ready", "wave": 0, "pair": 0}, *original[3:]],
            "boolean_timestamp": [{"stage": "before_setup", "at_unix_ms": True}, *original[1:]],
        }
        for name, events in cases.items():
            with self.subTest(case=name):
                self.events = events
                self.write_events()
                with self.assertRaises(ValueError):
                    self.sampler._phase_windows()

    def test_uncertain_endpoint_anchor_is_refused(self):
        self.phase["clock_anchors"][-1]["monotonic_after_ns"] += 2_000_000
        with self.assertRaisesRegex(ValueError, "uncertain clock anchor"):
            self.sampler._phase_windows()

    def test_header_clock_must_attest_realtime_before_any_phase_report(self):
        def wrong_header(name, argv, timeout):
            (self.output / (name + ".log")).write_text("# clockid: monotonic (1)\n")
            return True

        with mock.patch.object(self.sampler, "_command", side_effect=wrong_header) as command:
            self.sampler._report_phases(self.raw)
        self.assertEqual(command.call_count, 1)
        self.assertEqual(self.sampler.metadata["status"], "failed")
        self.assertIn("does not attest CLOCK_REALTIME", self.sampler.metadata["failures"][-1])
        self.assertEqual(self.sampler.metadata["target_return_code"], 101)

    def test_mature_perf_filters_all_three_windows_without_exporting_private_raw(self):
        with mock.patch.object(self.sampler, "_command", side_effect=self.report_command) as command:
            self.sampler._report_phases(self.raw)
        self.assertEqual(command.call_count, 4)
        self.assertEqual(self.sampler.metadata["failures"], [])
        self.assertEqual(self.phase["status"], "passed")
        self.assertTrue(self.phase["perf_header_attests_realtime"])
        self.assertEqual([window["symbol_samples"] for window in self.phase["windows"]], [3, 3, 3])
        for call, window in zip(command.call_args_list[1:], self.phase["windows"]):
            argv = call.args[1]
            self.assertEqual(argv[argv.index("--time") + 1], window["time_argument"])
            self.assertIn("--no-children", argv)
        self.assertFalse((self.output / "perf.data").exists())
        self.assertTrue(self.raw.is_file())
        self.assertFalse(self.sampler.metadata["call_graph"])
        self.assertFalse(self.sampler.metadata["acceptance_qualified"])
        self.assertEqual(self.sampler.metadata["target_return_code"], 101)

    def test_zero_phase_samples_and_report_failure_cannot_replace_original_failure(self):
        def zero_report(name, argv, timeout):
            if name == "perf-phase-header":
                return self.report_command(name, argv, timeout)
            (self.output / (name + ".log")).write_text("# Samples: 0 of event 'cpu-clock:u'\n")
            return True

        with mock.patch.object(self.sampler, "_command", side_effect=zero_report):
            self.sampler._report_phases(self.raw)
        self.assertEqual(self.sampler.metadata["status"], "failed")
        self.assertIn("no symbol samples", self.sampler.metadata["failures"][-1])

        def failed_report(name, argv, timeout):
            if name == "perf-phase-header":
                return self.report_command(name, argv, timeout)
            self.sampler._fail("fixture perf report returned 2")
            return False

        with mock.patch.object(self.sampler, "_command", side_effect=failed_report):
            self.sampler._report_phases(self.raw)
        self.assertEqual(self.sampler.metadata["status"], "failed")
        self.assertEqual(self.sampler.metadata["target_return_code"], 101)
        self.assertFalse((self.output / "perf.data").exists())

    def test_only_phase_recorder_adds_realtime_flags_original_target_is_unchanged(self):
        executable = self.directory / "original-target"
        executable.write_bytes(b"original fixture executable")
        argv = [str(executable), "--exact", "original-case", "--ignored"]
        for enabled in (False, True):
            with self.subTest(phase_reporting=enabled):
                sampler = PERF.PerfSampler(self.output, "exact-source-fixture", phase_reporting=enabled)
                sampler.tool, sampler.private = self.sampler.tool, self.raw.parent
                sampler.metadata["status"] = "ready"
                target, recorder = mock.Mock(pid=123), mock.Mock(pid=456)
                target.wait.return_value = 101
                recorder.poll.return_value = 0
                recorder.wait.return_value = 0
                record = {"return_code": None}
                with mock.patch.object(PERF.subprocess, "Popen", side_effect=[target, recorder]) as start, \
                        mock.patch.object(sampler, "_report"):
                    result = sampler.run(argv, object(), object(), 660, record)
                self.assertEqual(start.call_args_list[0].args[0], argv)
                self.assertEqual(start.call_args_list[0].kwargs.keys(), {"stdout", "stderr"})
                recorder_argv = start.call_args_list[1].args[0]
                self.assertEqual("--clockid" in recorder_argv, enabled)
                self.assertEqual("--timestamp" in recorder_argv, enabled)
                if enabled:
                    self.assertEqual(recorder_argv[recorder_argv.index("--clockid") + 1], "CLOCK_REALTIME")
                else:
                    self.assertNotIn("phase_reporting", sampler.metadata)
                self.assertEqual(result.returncode, 101)
                self.assertEqual(record["return_code"], 101)
                target.kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
