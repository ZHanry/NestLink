"""Optional GitHub-hosted perf orchestration; the capacity test stays unchanged."""

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import time


class PerfSampler:
    def __init__(self, output, source_revision, phase_reporting=False):
        self.output = pathlib.Path(output)
        self.tool = None
        self.private = None
        self.phase_reporting = phase_reporting
        self.metadata = {
            "diagnostic_only": True,
            "acceptance_qualified": False,
            "source_revision": source_revision,
            "script_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
            "status": "preparing",
            "event": "cpu-clock:u",
            "frequency_hz": 99,
            "call_graph": False,
            "raw_user_stack": False,
            "user_registers": False,
            "memory_sampling": False,
            "raw_data_exported": False,
            "target_runs_as_original_runner_user": True,
            "tool_source": "Ubuntu linux-tools packages from the hosted runner apt repositories",
            "runner_image_os": os.environ.get("ImageOS"),
            "runner_image_version": os.environ.get("ImageVersion"),
            "build_overrides": {
                "CARGO_PROFILE_RELEASE_DEBUG": "1",
                "CARGO_PROFILE_RELEASE_STRIP": "none",
            },
            "commands": [],
            "failures": [],
        }
        if phase_reporting:
            self.metadata["phase_reporting"] = {
                "status": "pending",
                "scope": "Existing first-wave record boundaries; the last window extends to original target exit.",
                "clock_source": "CLOCK_REALTIME",
                "event_clock_source": "capacity.rs wall_ms / SystemTime since UNIX_EPOCH",
                "boundary_quantization_ns": 1_000_000,
                "clock_jump_tolerance_ns": 5_000_000,
                "maximum_anchor_uncertainty_ns": 1_000_000,
                "clock_anchors": [],
                "windows": [],
                "limitations": [
                    "Existing event timestamps are truncated to milliseconds; each internal boundary has an excluded one-millisecond band.",
                    "The third window is after-all-controls-recorded, including scheduler handoff, flow opening and any later hold, waves or teardown; it is not pure opening or currentness.",
                    "No absolute timestamp is inferred from flow_ready.open_microseconds, and no call graph is recorded.",
                    "Realtime/monotonic anchors at target start/end and existing one-second waits reject observed offset jumps; transient changes between observations cannot be ruled out.",
                ],
            }

    def _fail(self, reason):
        self.metadata["status"] = "failed"
        self.metadata["failures"].append(str(reason))

    def _save(self):
        try:
            (self.output / "perf-metadata.json").write_text(
                json.dumps(self.metadata, indent=2) + "\n"
            )
        except Exception as error:
            self._fail("perf metadata: " + repr(error))

    def _clock_anchor(self, label):
        if not self.phase_reporting:
            return
        try:
            before = time.monotonic_ns()
            realtime = time.time_ns()
            after = time.monotonic_ns()
            self.metadata["phase_reporting"]["clock_anchors"].append({
                "label": label, "realtime_ns": realtime,
                "monotonic_before_ns": before, "monotonic_after_ns": after,
            })
        except Exception as error:
            # A diagnostic clock failure cannot suppress the original target.
            self._fail("perf phase clock anchor: " + repr(error))

    def _command(self, name, argv, timeout, allow_failure=False):
        record = {"name": name, "argv": argv, "timeout_seconds": timeout,
                  "return_code": None, "timed_out": False}
        self.metadata["commands"].append(record)
        started = time.monotonic()
        try:
            with (self.output / (name + ".log")).open("wb") as stdout, (
                self.output / (name + ".stderr.log")
            ).open("wb") as stderr:
                result = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout)
            record["return_code"] = result.returncode
            if result.returncode != 0:
                if not allow_failure:
                    self._fail(name + " failed")
                return False
            return True
        except subprocess.TimeoutExpired:
            record["timed_out"] = True
            self._fail(name + " timed out")
            return False
        except Exception as error:
            self._fail(name + ": " + repr(error))
            return False
        finally:
            record["seconds"] = time.monotonic() - started

    def prepare(self):
        try:
            if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
                raise RuntimeError("perf sampling requires GitHub-hosted execution")
            if not self._command(
                "perf-install", ["sudo", "-n", "apt-get", "install", "-y",
                                 "linux-tools-common", "linux-tools-generic"], 300
            ):
                return
            if not self._command(
                "perf-packages", ["dpkg-query", "-W", "-f=${binary:Package} ${Version}\n",
                                  "linux-tools*"], 30
            ):
                return
            if not self._command(
                "perf-package-sources", ["apt-cache", "policy", "linux-tools-common",
                                         "linux-tools-generic"], 30
            ):
                return
            candidates = sorted({
                path.resolve() for path in pathlib.Path("/usr/lib/linux-tools").glob("*/perf")
                if path.is_file() and os.access(path, os.X_OK)
            })
            self.metadata["tool_candidates"] = [str(path) for path in candidates]
            if not candidates:
                raise RuntimeError("installed linux-tools has no executable perf binary")
            self.tool = str(candidates[-1])
            self.metadata["tool_path"] = self.tool
            self.metadata["tool_sha256"] = hashlib.sha256(
                pathlib.Path(self.tool).read_bytes()
            ).hexdigest()
            if not self._command(
                "perf-package-owner", ["dpkg-query", "-S", self.tool], 30
            ):
                return
            if not self._command("perf-version", [self.tool, "version", "--build-options"], 30):
                return
            self.metadata["tool_version"] = (self.output / "perf-version.log").read_text()
            self.metadata["perf_event_paranoid"] = pathlib.Path(
                "/proc/sys/kernel/perf_event_paranoid"
            ).read_text().strip()
            self.private = pathlib.Path(tempfile.mkdtemp(
                prefix="network-capacity-perf-private-", dir=os.environ["RUNNER_TEMP"]
            ))
            os.chmod(self.private, 0o700)
            self.metadata["private_raw_directory"] = str(self.private)
            self.metadata["status"] = "ready"
        except Exception as error:
            self._fail("perf setup: " + repr(error))
        finally:
            self._save()

    def run(self, command, stdout, stderr, timeout, target_record):
        self.metadata["target_argv"] = command
        self.metadata["target_timeout_seconds"] = timeout
        self.metadata["target_uid"] = os.getuid()
        try:
            self.metadata["target_executable_sha256"] = hashlib.sha256(
                pathlib.Path(command[0]).read_bytes()
            ).hexdigest()
        except Exception as error:
            self._fail("perf executable identity: " + repr(error))
        if self.metadata["status"] != "ready":
            # A failed diagnostic never suppresses the original workload attempt.
            started = time.monotonic()
            try:
                result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=timeout)
                self.metadata["target_return_code"] = result.returncode
                target_record["return_code"] = result.returncode
                return result
            except subprocess.TimeoutExpired:
                self.metadata["target_timed_out"] = True
                raise
            finally:
                self.metadata["target_seconds"] = time.monotonic() - started
                self._save()
        recorder = None
        recorder_logs = []
        record = None
        started = time.monotonic()
        self._clock_anchor("target_start")
        target = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        self.metadata["target_pid"] = target.pid
        raw = self.private / "perf.data"
        try:
            argv = ["sudo", "-n", "env", "PERF_CONFIG=/dev/null", "LC_ALL=C",
                    self.tool, "record", "-e", "cpu-clock:u", "-F", "99",
                    "--no-buildid-cache", "-o", str(raw), "--pid", str(target.pid)]
            if self.phase_reporting:
                argv.extend(["--timestamp", "--clockid", "CLOCK_REALTIME"])
            record = {"name": "perf-record", "argv": argv, "return_code": None,
                      "timed_out": False, "target_threads_inherited": True}
            self.metadata["commands"].append(record)
            try:
                recorder_logs = [(self.output / "perf-record.log").open("wb"),
                                 (self.output / "perf-record.stderr.log").open("wb")]
                recorder = subprocess.Popen(
                    argv, stdout=recorder_logs[0], stderr=recorder_logs[1], start_new_session=True
                )
                self.metadata["status"] = "recording"
            except Exception as error:
                self._fail("perf attach: " + repr(error))
            premature_exit = False
            while True:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    target.kill()
                    target_record["return_code"] = target.wait()
                    self.metadata["target_return_code"] = target_record["return_code"]
                    self.metadata["target_timed_out"] = True
                    raise subprocess.TimeoutExpired(command, timeout)
                try:
                    return_code = target.wait(timeout=min(1, remaining))
                    break
                except subprocess.TimeoutExpired:
                    self._clock_anchor("target_wait")
                    if (recorder is not None and recorder.poll() is not None
                            and not premature_exit and target.poll() is None):
                        premature_exit = True
                        self._fail("perf recorder exited while the original workload was still running")
            self.metadata["target_return_code"] = return_code
            target_record["return_code"] = return_code
            return subprocess.CompletedProcess(command, return_code)
        finally:
            self.metadata["target_seconds"] = time.monotonic() - started
            self._clock_anchor("target_end")
            try:
                if recorder is not None:
                    if recorder.poll() is None:
                        stopped = self._command(
                            "perf-stop", ["sudo", "-n", "kill", "-INT", "--",
                                          "-" + str(recorder.pid)], 10, allow_failure=True
                        )
                        if not stopped and recorder.poll() is None:
                            self._fail("perf recorder could not be interrupted")
                    try:
                        record["return_code"] = recorder.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        record["timed_out"] = True
                        self._fail("perf recorder did not stop after the workload")
                        self._command(
                            "perf-kill", ["sudo", "-n", "kill", "-KILL", "--",
                                          "-" + str(recorder.pid)], 10
                        )
                        record["return_code"] = recorder.wait(timeout=5)
                    if record["return_code"] != 0:
                        self._fail("perf record failed")
                for stream in recorder_logs:
                    stream.close()
                self._report(raw)
            except Exception as error:
                self._fail("perf finalization: " + repr(error))
            finally:
                self._save()

    def _report(self, raw):
        if not self._command("perf-data-size", ["sudo", "-n", "stat", "--printf=%s", str(raw)], 30):
            return
        self.metadata["raw_data_bytes"] = int((self.output / "perf-data-size.log").read_text())
        if not self._command("perf-data-sha256", ["sudo", "-n", "sha256sum", "--", str(raw)], 30):
            return
        self.metadata["raw_data_sha256"] = (
            self.output / "perf-data-sha256.log"
        ).read_text().split()[0]
        if not self._command(
            "perf-report", ["sudo", "-n", "env", "PERF_CONFIG=/dev/null", "LC_ALL=C",
                            self.tool, "report", "--stdio", "--stdio-color", "never",
                            "--no-children", "--show-nr-samples", "--sort", "dso,symbol",
                            "--percent-limit", "0", "-i", str(raw)], 60
        ):
            return
        report = (self.output / "perf-report.log").read_text()
        samples = re.search(r"^# Samples:\s+([0-9.,]+)([KMG]?)\s", report, re.MULTILINE)
        if not samples or float(samples.group(1).replace(",", "")) <= 0:
            self._fail("perf report did not confirm nonzero samples")
            return
        self.metadata["samples_display"] = samples.group(1) + samples.group(2)
        self.metadata["report_sha256"] = hashlib.sha256(
            (self.output / "perf-report.log").read_bytes()
        ).hexdigest()
        if self.phase_reporting:
            self._report_phases(raw)
        if not self.metadata["failures"]:
            self.metadata["status"] = "passed"

    def _phase_windows(self):
        phase = self.metadata["phase_reporting"]
        anchors = phase["clock_anchors"]
        if len(anchors) < 2 or anchors[0]["label"] != "target_start" or anchors[-1]["label"] != "target_end":
            raise ValueError("missing target endpoint clock anchors")
        lower, upper = [], []
        previous = None
        for anchor in anchors:
            before, after, realtime = (anchor[key] for key in (
                "monotonic_before_ns", "monotonic_after_ns", "realtime_ns"
            ))
            if any(type(value) is not int or value < 0 for value in (before, after, realtime)):
                raise ValueError("invalid clock anchor")
            if before > after or after - before > phase["maximum_anchor_uncertainty_ns"]:
                raise ValueError("uncertain clock anchor")
            if previous is not None and before < previous:
                raise ValueError("nonmonotonic clock anchors")
            previous = after
            lower.append(realtime - after)
            upper.append(realtime - before)
        phase["observed_realtime_offset_span_ns"] = max(0, max(lower) - min(upper))
        if phase["observed_realtime_offset_span_ns"] > phase["clock_jump_tolerance_ns"]:
            raise ValueError("observed realtime clock jump; phase attribution refused")
        events = [json.loads(line) for line in (self.output / "samples.jsonl").read_text().splitlines()]

        def only(stage):
            matching = [event for event in events if event.get("stage") == stage]
            if len(matching) != 1:
                raise ValueError("expected exactly one " + stage + " boundary")
            return matching[0]

        def timestamp(event):
            value = event.get("at_unix_ms")
            if type(value) is not int or value < 0:
                raise ValueError("missing or invalid original event timestamp")
            return value * 1_000_000

        setup = timestamp(only("before_setup"))
        hosts = timestamp(only("all_hosts_ready"))
        controls = [event for event in events if event.get("stage") == "multiplex_control_ready"
                    and type(event.get("wave")) is int and event["wave"] == 0]
        if len(controls) != 20 or any(type(event.get("pair")) is not int for event in controls) or {
            event["pair"] for event in controls
        } != set(range(20)):
            raise ValueError("missing or duplicate original first-wave control owners")
        control_times = [timestamp(event) for event in controls]
        end = anchors[-1]["realtime_ns"]
        quantum = phase["boundary_quantization_ns"]
        if (setup + quantum < anchors[0]["realtime_ns"] or hosts < setup
                or min(control_times) < hosts or max(control_times) + quantum > end):
            raise ValueError("original event boundaries are outside the target clock range or reversed")
        controls_end = max(control_times)
        boundaries = [
            ("setup", setup + quantum, hosts - 1, "before_setup", "all_hosts_ready"),
            ("hosted-ready-to-all-controls-recorded", hosts + quantum, controls_end - 1,
             "all_hosts_ready", "max first-wave multiplex_control_ready (20 unique pairs)"),
            ("after-all-controls-recorded", controls_end + quantum, end,
             "max first-wave multiplex_control_ready (20 unique pairs)", "target_end clock anchor"),
        ]
        windows = []
        for name, start, stop, start_event, stop_event in boundaries:
            if start >= stop:
                raise ValueError("empty or reversed guarded phase window: " + name)
            windows.append({
                "name": name, "start_ns": start, "stop_ns": stop,
                "start_source": start_event, "stop_source": stop_event,
                "clock_source": "CLOCK_REALTIME", "boundary_quantization_ns": quantum,
                "time_argument": f"{start // 1_000_000_000}.{start % 1_000_000_000:09d},"
                                 f"{stop // 1_000_000_000}.{stop % 1_000_000_000:09d}",
            })
        phase["windows"] = windows
        return windows

    def _report_phases(self, raw):
        # Mature perf performs all timestamp filtering and symbol aggregation.
        # Existing target event files are read only after the target has ended.
        try:
            phase = self.metadata["phase_reporting"]
            phase["status"] = "reporting"
            windows = self._phase_windows()
            if not self._command(
                "perf-phase-header", ["sudo", "-n", "env", "PERF_CONFIG=/dev/null", "LC_ALL=C",
                                      self.tool, "report", "--header-only", "-i", str(raw)], 60
            ):
                phase["status"] = "failed"
                return
            header = (self.output / "perf-phase-header.log").read_text()
            # perf v6.8 util/header.c prints clockid_name from util/clockid.c.
            if not re.search(r"^# clockid:\s+realtime \(0\)\s*$", header, re.MULTILINE):
                raise ValueError("perf header does not attest CLOCK_REALTIME")
            phase["perf_header_attests_realtime"] = True
            phase["header_sha256"] = hashlib.sha256(
                (self.output / "perf-phase-header.log").read_bytes()
            ).hexdigest()
            for window in windows:
                name = "perf-phase-" + window["name"]
                if not self._command(
                    name, ["sudo", "-n", "env", "PERF_CONFIG=/dev/null", "LC_ALL=C", self.tool,
                           "report", "--stdio", "--stdio-color", "never", "--no-children",
                           "--show-nr-samples", "--sort", "dso,symbol", "--percent-limit", "0",
                           "--time", window["time_argument"], "-i", str(raw)], 60
                ):
                    phase["status"] = "failed"
                    return
                path = self.output / (name + ".log")
                report = path.read_text()
                samples = sum(int(value) for value in re.findall(
                    r"^\s+[0-9.]+%\s+(\d+)\s+", report, re.MULTILINE
                ))
                window["symbol_samples"] = samples
                window["report_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                if samples <= 0:
                    raise ValueError("phase report has no symbol samples: " + window["name"])
            phase["status"] = "passed"
        except Exception as error:
            self.metadata["phase_reporting"]["status"] = "failed"
            self._fail("perf phase reporting: " + repr(error))
