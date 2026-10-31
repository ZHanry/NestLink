"""Build/run only the original hosted native subnet game test, retaining evidence."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import time


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    assert os.environ["RUNNER_ENVIRONMENT"] == "github-hosted" and os.geteuid() != 0
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True)
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    assert source == os.environ["GITHUB_SHA"]
    assert not subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"])
    receipt = {"schema_version": 1, "source_revision": source, "run_id": os.environ["GITHUB_RUN_ID"],
               "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "workflow_revision": os.environ["GITHUB_WORKFLOW_SHA"],
               "cargo_lock_sha256": sha256(pathlib.Path("Cargo.lock")), "passed": False,
               "scope": "hosted real official Luanti+Minetest Game on production subnet kernel/NAT/QUIC with explicit signed mechanism credentials; no online login/one-use or physical-site claim"}
    commands = []
    def run(name, argv, timeout):
        started = time.monotonic()
        try:
            result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (output / (name + ".log")).write_bytes(error.stdout or b"")
            commands.append({"command": argv, "timed_out": True, "timeout_seconds": timeout})
            raise
        (output / (name + ".log")).write_bytes(result.stdout)
        commands.append({"command": argv, "return_code": result.returncode, "seconds": time.monotonic() - started})
        print(result.stdout.decode(errors="replace"), flush=True)
        assert result.returncode == 0, name
        return result.stdout
    try:
        built = run("original-daemon-build", ["cargo", "test", "--locked", "-p", "nestlink-daemon", "--bin", "nestlink-daemon",
                    "--no-run", "--message-format=json"], 1200)
        binaries = [item["executable"] for line in built.decode().splitlines() if line.startswith("{")
                    and (item := json.loads(line)).get("reason") == "compiler-artifact"
                    and item.get("target", {}).get("name") == "nestlink-daemon" and item.get("executable")]
        assert len(binaries) == 1
        receipt["test_binary_sha256"] = sha256(pathlib.Path(binaries[0]))
        os.environ["NESTLINK_GAME_EVIDENCE"] = str(output / "actual-luanti")
        selector = "network_subnet_system::native_tests::games::actual_luanti_client_server_play_and_original_kernel_carrier_stop"
        receipt["exact_test_selector"] = selector
        run("actual-game-original-subnet-owner", [binaries[0], selector, "--exact", "--ignored", "--nocapture", "--test-threads=1"], 150)
        run("strict-original-daemon", ["cargo", "clippy", "--locked", "-p", "nestlink-daemon", "--all-targets", "--", "-D", "warnings"], 600)
        receipt["passed"] = True
    except BaseException as error:
        receipt["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        receipt["commands"] = commands
        receipt["files"] = [{"path": str(path.relative_to(output)), "sha256": sha256(path), "bytes": path.stat().st_size}
                            for path in sorted(output.rglob("*")) if path.is_file() and path.name != "receipt.json"]
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    assert receipt["passed"], receipt.get("failure")


if __name__ == "__main__":
    main()
