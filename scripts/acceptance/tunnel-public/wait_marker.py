"""Read a marker from this runner's owned directory; performs no networking."""
import argparse
import json
from pathlib import Path
import time

from common import require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--marker", choices=("source-probe-ready", "source-observed", "ready-to-stop", "stop-armed", "visitor-done"), required=True)
    parser.add_argument("--timeout", type=int, required=True)
    args = parser.parse_args()
    require(1 <= args.timeout <= 600, "marker-timeout-bound")
    output = Path(args.output).absolute()
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        path = output / "markers" / (args.marker + ".json")
        if path.is_file():
            print(path.read_text(), flush=True)
            if args.marker == "visitor-done":
                report = json.loads((output / "visitor-result.json").read_text())
                raise SystemExit(0 if report["tool_data_checks_passed"] else 1)
            return
        if (output / "visitor-result.json").exists():
            raise SystemExit("Visitor ended before the requested marker; inspect the fixed report")
        time.sleep(0.5)
    raise SystemExit("Owned marker deadline elapsed")


if __name__ == "__main__":
    main()
