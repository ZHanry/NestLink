"""GitHub-hosted dual-LAN validation using real distribution DNS services.

All target compilation and execution stays on this hosted runner. Namespace
privilege is limited to the isolated fixture; the original SDK owner runs as
the runner user. These receipts qualify this mechanism, never games or sites.
"""
import argparse
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import time


SELECTOR = "lan::actual_lan_dns_sd_and_udp_use_original_online_owner_and_release_sockets"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    assert os.environ["RUNNER_ENVIRONMENT"] == "github-hosted"
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True)
    commands = []
    processes = []
    namespaces = []
    links = []
    failure = None
    cleanup_errors = []
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    assert source == os.environ["GITHUB_SHA"]
    receipt = {
        "schema_version": 1,
        "source_revision": source,
        "workflow_revision": os.environ["GITHUB_WORKFLOW_SHA"],
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "runner_environment": os.environ["RUNNER_ENVIRONMENT"],
        "scope": "isolated dual LAN UDP DNS and DNS-SD mechanism; no game or target-site acceptance",
        "lock_sha256": sha256(pathlib.Path("Cargo.lock")),
        "commands": commands,
        "passed": False,
    }

    def command(name, argv, timeout=900, env=None, check=True):
        started = time.monotonic()
        path = output / (name + ".log")
        try:
            result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    env=env, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            path.write_bytes(error.stdout or b"")
            commands.append({"name": name, "command": argv, "return_code": None,
                             "timed_out": True, "timeout_seconds": timeout,
                             "elapsed_seconds": time.monotonic() - started,
                             "log": path.name, "log_sha256": sha256(path)})
            raise RuntimeError(name + " timed out; partial same-run log retained") from error
        path.write_bytes(result.stdout)
        commands.append({"name": name, "command": argv, "return_code": result.returncode,
                         "elapsed_seconds": time.monotonic() - started,
                         "log": path.name, "log_sha256": sha256(path)})
        print(result.stdout.decode(errors="replace"), flush=True)
        if check and result.returncode:
            raise RuntimeError(name + " failed; same-run log retained")
        return result

    def ip(name, *argv, check=True):
        return command(name, ["sudo", "-n", "ip", *argv], timeout=10, check=check)

    try:
        assert not subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"])
        command("actual-dnsmasq-version", ["dnsmasq", "--version"], timeout=10)
        command("actual-iproute-version", ["ip", "-Version"], timeout=10)
        component = command("reviewed-dns-component-boundary", ["cargo", "test", "--locked",
            "--manifest-path", "third-party/mdns-sd/Cargo.toml", "--no-default-features", "--lib",
            "service_info::tests::nestlink_routable_publication_is_default_off_exact_interface_and_reversible",
            "--", "--exact", "--show-output", "--color", "never"])
        assert b"test result: ok. 1 passed; 0 failed; 0 ignored;" in component.stdout
        assert not subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"])
        unit = command("lan-unit", ["cargo", "test", "--locked", "-p", "nestlink-sdk", "--lib",
                                    "network::lan::tests::", "--", "--show-output", "--color", "never"])
        assert b"test result: ok. 5 passed; 0 failed; 0 ignored;" in unit.stdout
        command("lan-strict", ["cargo", "clippy", "--locked", "-p", "nestlink-sdk", "-p",
                               "nestlink-daemon", "--all-targets", "--", "-D", "warnings"])
        build = command("original-network-access-build", ["cargo", "test", "--locked", "-p",
                        "nestlink-sdk", "--test", "network_access", "--no-run", "--message-format=json"])
        artifacts = []
        for line in build.stdout.decode(errors="replace").splitlines():
            if not line.startswith("{"):
                continue
            item = json.loads(line)
            if (item.get("reason") == "compiler-artifact" and item.get("executable")
                    and item.get("target", {}).get("name") == "network_access"
                    and item.get("profile", {}).get("test")):
                artifacts.append(pathlib.Path(item["executable"]))
        assert len(artifacts) == 1, "exact original integration binary must be unambiguous"
        binary = artifacts[0]
        receipt["test_binary_sha256"] = sha256(binary)
        receipt["exact_test_selector"] = SELECTOR
        env = os.environ.copy()
        env["NESTLINK_LAN_EVIDENCE"] = str(output / "actual-lan-execution.json")
        suffix = os.environ["GITHUB_RUN_ID"][-7:] + os.environ["GITHUB_RUN_ATTEMPT"]
        for index in range(2):
            namespace = "nl-lan-" + suffix + "-" + str(index)
            host = "nlh" + str(index) + suffix
            peer = "nlp" + str(index)
            prefix = "192.168." + str(211 + index)
            ip("namespace-create-" + str(index), "netns", "add", namespace)
            namespaces.append(namespace)
            ip("veth-create-" + str(index), "link", "add", host, "type", "veth", "peer", "name", peer,
               "netns", namespace)
            links.append(host)
            ip("host-address-" + str(index), "addr", "add", prefix + ".2/24", "dev", host)
            ip("host-up-" + str(index), "link", "set", host, "up")
            ip("namespace-address-" + str(index), "-n", namespace, "addr", "add", prefix + ".3/24", "dev", peer)
            ip("namespace-up-" + str(index), "-n", namespace, "link", "set", peer, "up")
            ip("namespace-loopback-" + str(index), "-n", namespace, "link", "set", "lo", "up")
            observed = ip("host-readback-" + str(index), "-j", "address", "show", "dev", host)
            interface = json.loads(observed.stdout)[0]
            assert any(row.get("local") == prefix + ".2" and row.get("prefixlen") == 24
                       for row in interface["addr_info"])
            for field, value in {"ADDRESS": prefix + ".2", "INDEX": str(interface["ifindex"]),
                                 "PREFIX": prefix + ".0/24", "SERVER": prefix + ".3",
                                 "NAMESPACE": namespace}.items():
                env["NESTLINK_LAN_" + str(index) + "_" + field] = value
            log = (output / ("actual-dnsmasq-" + str(index) + ".log")).open("wb")
            port = str(38303 if index == 0 else 38403)
            argv = ["sudo", "-n", "ip", "netns", "exec", namespace, "dnsmasq", "--no-daemon",
                    "--no-hosts", "--no-resolv", "--interface=" + peer, "--except-interface=lo",
                    "--port=" + port, "--log-queries", "--log-facility=-",
                    "--address=/remote" + ("a" if index == 0 else "b") + ".nestlink-test/10.222.0." + str(index + 1),
                    "--pid-file="]
            process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
            processes.append((process, log))
            commands.append({"name": "actual-dnsmasq-" + str(index), "command": argv,
                             "log": "actual-dnsmasq-" + str(index) + ".log"})
            time.sleep(0.15)
            assert process.poll() is None, "actual distribution dnsmasq did not remain running"
        command("actual-original-owner-lan", [str(binary), SELECTOR, "--exact", "--ignored",
                 "--nocapture", "--color", "never"], timeout=90, env=env)
        actual = json.loads((output / "actual-lan-execution.json").read_text())
        assert actual["passed"] and actual["source_revision"] == source
        receipt["execution_passed"] = True
    except BaseException as error:
        failure = type(error).__name__ + ": " + str(error)
    finally:
        for index, namespace in enumerate(reversed(namespaces)):
            try:
                pids = ip("namespace-owned-pids-" + str(index), "netns", "pids", namespace).stdout.split()
                if pids:
                    command("namespace-kill-" + str(index), ["sudo", "-n", "kill", "-TERM",
                            *[str(int(pid)) for pid in pids]], timeout=10, check=False)
                ip("namespace-remove-" + str(index), "netns", "delete", namespace)
            except BaseException as error:
                cleanup_errors.append(str(error))
        for index, host in enumerate(links):
            try:
                result = ip("host-final-readback-" + str(index), "link", "show", "dev", host, check=False)
                if result.returncode == 0:
                    ip("host-final-remove-" + str(index), "link", "delete", host)
                    result = ip("host-final-absence-" + str(index), "link", "show", "dev", host, check=False)
                assert result.returncode != 0, "owned LAN interface remained after cleanup"
            except BaseException as error:
                cleanup_errors.append(str(error))
        for process, stream in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.send_signal(signal.SIGKILL)
                process.wait(timeout=5)
                cleanup_errors.append("namespace DNS process required final kill")
            finally:
                stream.close()
        receipt["failure"] = failure
        receipt["cleanup_errors"] = cleanup_errors
        receipt["passed"] = failure is None and not cleanup_errors
        receipt["files"] = [{"path": path.name, "sha256": sha256(path), "bytes": path.stat().st_size}
                            for path in sorted(output.iterdir()) if path.is_file() and path.name != "receipt.json"]
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    assert receipt["passed"], "hosted LAN mechanism did not qualify; exact failure and cleanup retained"


if __name__ == "__main__":
    main()
