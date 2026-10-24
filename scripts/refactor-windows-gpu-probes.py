#!/usr/bin/env python3
"""Run only the two owned, GitHub-built synthetic probes with wall deadlines.

Invoke through refactor-windows-normal-user.py on a Windows runner. Neither
probe opens desktop capture. The presenter may show its own NOACTIVATE window.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-directory", type=Path, default=Path("target/debug/examples"))
    args = parser.parse_args()
    directory = args.probe_directory.resolve(strict=True)
    failed = False
    for name in ("windows-gpu-h264-probe.exe", "windows-gpu-presenter-probe.exe"):
        executable = directory / name
        if not executable.is_file():
            raise ValueError(f"Missing GitHub-built probe: {name}")
        try:
            result = subprocess.run(
                [str(executable)], check=False, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, encoding="utf-8", errors="replace", timeout=30,
            )
            print(result.stdout, end="", flush=True)
            print(json.dumps({"probe": name, "exit_code": result.returncode,
                              "watchdog_expired": False}), flush=True)
            failed |= result.returncode != 0
        except subprocess.TimeoutExpired as error:
            # subprocess.run kills and waits for this exact owned child. No
            # process-name search, shared process, or unrelated window is used.
            output = error.stdout or b""
            print(output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output,
                  end="", flush=True)
            print(json.dumps({"probe": name, "exit_code": None,
                              "watchdog_expired": True}), flush=True)
            failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
