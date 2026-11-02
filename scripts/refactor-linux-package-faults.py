"""Actual hosted dpkg interruption and installed server port-conflict fixtures.

This extends the existing unsigned candidate qualification. The production DEB
builder, dpkg and installed server own all package/runtime operations. The
public dpkg pre-invoke hook is only a deterministic crash observation point;
it is not a replacement installer or a formal signed-update qualification.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request
import zipfile

OLD_SOURCE = "c0fc249fc24c4bab389fe10690a2becb1b71257e"
OLD_ARTIFACTS = {
    "amd64": (13055507795, "cfaef16fd89a66c5a211e9fd17eefe2235bd66d88683f115040b9df7b062c8f1"),
    "arm64": (13055977059, "bde3779b2c60c9bfa7994b59a9bf1c9cab34f35681c99f7c39a07f045a3be21a"),
}
SERVER = Path("/opt/nestlink-rc/server/nestlink-server")


def retained_package(output, architecture, producer):
    artifact, expected = OLD_ARTIFACTS[architecture]
    request = urllib.request.Request(f"https://api.github.com/repos/ZHanry/NestLink/actions/artifacts/{artifact}/zip",
        headers={"Accept": "application/vnd.github+json",
                 "User-Agent": "NestLink-explicit-hosted-package-recovery"})
    # The API redirects to its signed artifact URL. Python's unredirected header
    # keeps the workflow token on the original api.github.com request only.
    request.add_unredirected_header("Authorization", "Bearer " + os.environ["GITHUB_TOKEN"])
    archive = output / "retained-previous-artifact.zip"
    with urllib.request.urlopen(request, timeout=90) as source, archive.open("xb") as destination:
        total = 0
        while chunk := source.read(1024 * 1024):
            total += len(chunk)
            if total > 64 * 1024 * 1024:
                raise ValueError("retained package artifact exceeds fixed download bound")
            destination.write(chunk)
    if producer.digest(archive) != expected:
        raise ValueError("retained package artifact differs from the reviewed official ZIP digest")
    with zipfile.ZipFile(archive) as package_zip:
        prior = json.loads(package_zip.read("linux-network-package.json"))
        if prior["source_revision"] != OLD_SOURCE or prior["status"] != "passed":
            raise ValueError("retained baseline is not its qualified source")
        name = "NestLink-candidate-linux-" + architecture + "-network.deb"
        if prior["package"]["path"] != name:
            raise ValueError("retained package path differs from the exact role/architecture")
        item = package_zip.getinfo(name)
        if item.file_size != prior["package"]["bytes"] or item.file_size > 64 * 1024 * 1024:
            raise ValueError("retained package size differs")
        package = output / ("retained-" + name)
        package.write_bytes(package_zip.read(item))
    if producer.digest(package) != prior["package"]["sha256"]:
        raise ValueError("retained DEB differs from its qualified receipt")
    return package, {"source_revision": OLD_SOURCE, "artifact_id": artifact, "official_zip_sha256": expected,
                     "downloaded_zip_sha256": producer.digest(archive), "package_sha256": producer.digest(package),
                     "binary_sha256": prior["build_provenance"]["binary_sha256"]}


def payload_snapshot(root, digest):
    if root.is_symlink():
        raise ValueError("candidate payload root unexpectedly became a link")
    snapshot = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("candidate payload contains an unexpected linked/special file")
        snapshot[str(path.relative_to(root))] = {"type": "directory" if path.is_dir() else "file",
            "mode": path.stat().st_mode & 0o777,
            **({"sha256": digest(path)} if path.is_file() else {})}
    return snapshot


def interrupted_replacement(args, producer, architecture, version, sentinel, receipt, command):
    package, prior = retained_package(args.output, architecture, producer)
    installed = Path("/opt/nestlink-rc/network/nestlink-daemon")
    expected_state = producer.digest(sentinel)
    with tempfile.TemporaryDirectory(prefix="nestlink-package-interruption-") as temporary:
        private = Path(temporary)
        payload = private / "payload"
        payload.mkdir()
        producer.copy_fixed(args.binary, payload / "nestlink-daemon")
        incoming = args.output / ("HOSTED-FAULT-FIXTURE-linux-" + architecture + "-network.deb")
        fixture_version = version + "+hosted.interruption.1"
        producer.deb_candidate(payload, incoming, "network", architecture,
            {"source_revision": receipt["source_revision"], "version": fixture_version, "sequence": 1})
        incoming_version = command("incoming-fixture-deb-version", ["dpkg-deb", "--field", incoming, "Version"]).decode().strip()
        prior_version = command("retained-baseline-deb-version", ["dpkg-deb", "--field", package, "Version"]).decode().strip()
        command("real-dpkg-upgrade-version-order", ["dpkg", "--compare-versions", incoming_version, "gt", prior_version])
        extracted = private / "retained-payload"
        command("extract-retained-rollback-payload", ["dpkg-deb", "--extract", package, extracted])
        roots = (Path("opt/nestlink-rc/network"), Path("usr/share/doc/nestlink-rc-network"))
        expected_payload = {str(root): payload_snapshot(extracted / root, producer.digest) for root in roots}
        command("install-retained-rollback-baseline", ["sudo", "-n", "dpkg", "--install", package])
        if producer.digest(installed) != prior["binary_sha256"]:
            raise ValueError("rollback baseline is not its original qualified executable")
        command("unpack-real-incoming-upgrade", ["sudo", "-n", "dpkg", "--unpack", incoming])
        status = command("unpacked-upgrade-status", ["dpkg-query", "--show", "--showformat=${Status}", "nestlink-rc-network"]).decode()
        if status != "install ok unpacked" or producer.digest(installed) != receipt["build_provenance"]["binary_sha256"]:
            raise ValueError("upgrade did not reach the real unpacked new-payload state")
        barrier = private / "before-configure.py"
        marker = private / "actual-dpkg.json"
        barrier.write_text('''import json,os,pathlib,signal,sys,time
parent=os.getppid()
for _ in range(8):
    proc=pathlib.Path('/proc')/str(parent)
    if (proc/'exe').resolve()==pathlib.Path('/usr/bin/dpkg').resolve():
        break
    parent=int((proc/'stat').read_text().split(') ',1)[1].split()[1])
else:
    raise RuntimeError('original dpkg ancestor missing')
start=(proc/'stat').read_text().split(') ',1)[1].split()[19]
pathlib.Path(sys.argv[1]).write_text(json.dumps({'dpkg_pid':parent,'dpkg_start':start,'hook_pid':os.getpid()}))
signal.alarm(30)
signal.pause()
''', encoding="utf-8")
        hook = shlex.join(["python3", str(barrier), str(marker)])
        argv = ["sudo", "-n", "dpkg", "--pre-invoke=" + hook, "--configure", "nestlink-rc-network"]
        log_path = args.output / "interrupted-real-dpkg-configure.log"
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        observed = None
        try:
            deadline = time.monotonic() + 5
            while not marker.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise ValueError("real dpkg did not reach its bounded pre-configure crash point")
                time.sleep(0.025)
            observed = json.loads(marker.read_text())
            proc = Path("/proc") / str(observed["dpkg_pid"])
            if (proc / "exe").resolve() != Path("/usr/bin/dpkg").resolve() or (proc / "stat").read_text().split(") ", 1)[1].split()[19] != observed["dpkg_start"]:
                raise ValueError("crash fixture no longer owns the exact original dpkg process")
            command("kill-exact-original-dpkg", ["sudo", "-n", "kill", "-KILL", str(observed["dpkg_pid"])])
            command("stop-exact-owned-dpkg-hook", ["sudo", "-n", "kill", "-TERM", str(observed["hook_pid"])])
            output, _ = process.communicate(timeout=10)
            log_path.write_bytes(output)
            receipt["commands"].append({"name": "interrupted-real-dpkg-configure", "return_code": process.returncode,
                                        "log": log_path.name, "log_sha256": producer.digest(log_path)})
            if process.returncode == 0:
                raise ValueError("the original dpkg unexpectedly completed instead of being interrupted")
        finally:
            if process.poll() is None:
                if observed:
                    subprocess.run(["sudo", "-n", "kill", "-TERM", str(observed["hook_pid"])], check=False)
                output, _ = process.communicate(timeout=35)
                log_path.write_bytes(output)
        after = command("interrupted-unpacked-status", ["dpkg-query", "--show", "--showformat=${Status}", "nestlink-rc-network"]).decode()
        if after != "install ok unpacked":
            raise ValueError("interrupted dpkg did not preserve its explicit unconfigured recovery state")
        command("explicit-original-package-rollback", ["sudo", "-n", "dpkg", "--force-downgrade", "--install", package])
        for root in roots:
            if payload_snapshot(Path("/") / root, producer.digest) != expected_payload[str(root)]:
                raise ValueError("rollback left changed bytes, permissions or upgrade residual files")
        if producer.digest(sentinel) != expected_state:
            raise ValueError("interrupted replacement or rollback changed retained user state")
        status = command("restored-configured-status", ["dpkg-query", "--show", "--showformat=${Status}", "nestlink-rc-network"]).decode()
        if status != "install ok installed":
            raise ValueError("explicit rollback did not finish the original dpkg recovery")
        restored_version = command("restored-dpkg-version", ["dpkg-query", "--show", "--showformat=${Version}", "nestlink-rc-network"]).decode().strip()
        if restored_version != prior_version:
            raise ValueError("rollback did not restore the original package version metadata")
        command("reinstall-current-after-rollback", ["sudo", "-n", "dpkg", "--install", args.output / receipt["package"]["path"]])
        if producer.digest(installed) != receipt["build_provenance"]["binary_sha256"]:
            raise ValueError("recovery did not restore the current exact-source candidate")
        receipt["interrupted_upgrade"] = {"passed": True, "baseline": prior, "fixture_package_version": incoming_version,
            "restored_package_version": restored_version,
            "incoming_fixture_sha256": producer.digest(incoming), "actual_dpkg_sigkill": True,
            "interrupted_status": after, "restored_status": status, "original_payload_and_modes_restored": True,
            "retained_user_state_unchanged": True, "candidate_payload_residuals_absent": True,
            "current_exact_source_candidate_restored": True,
            "scope": "Actual unsigned candidate DEB version upgrade interrupted after unpack and before configure; explicit original dpkg downgrade and residual verification. No formal signed lifecycle or post-admission schema rollback claim."}


def port_conflict(args, producer, architecture, version, receipt, command):
    if SERVER.exists() or subprocess.run(["dpkg-query", "--status", "nestlink-rc-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        raise ValueError("isolated candidate server package already exists")
    with tempfile.TemporaryDirectory(prefix="nestlink-package-port-") as temporary:
        private = Path(temporary)
        payload = private / "payload"; payload.mkdir()
        producer.copy_fixed(args.server, payload / "nestlink-server")
        package = args.output / ("NestLink-candidate-linux-" + architecture + "-server.deb")
        producer.deb_candidate(payload, package, "server", architecture,
            {"source_revision": receipt["source_revision"], "version": version, "sequence": 1})
        try:
            command("install-current-server", ["sudo", "-n", "dpkg", "--install", package])
            if producer.digest(SERVER) != producer.digest(args.server):
                raise ValueError("installed server differs from the same-source hosted build")
            holder = socket.socket(); holder.bind(("127.0.0.1", 0)); holder.listen(2); holder.settimeout(2)
            address = holder.getsockname(); origin = f"http://{address[0]}:{address[1]}"
            deployment = private / "deployment"
            try:
                command("port-fixture-init", [SERVER, "init", "--directory", deployment, "--management-origin", origin,
                    "--listen", f"{address[0]}:{address[1]}", "--allow-loopback-http"])
                retained = {name: producer.digest(deployment / name) for name in ("server.toml", "vault.key", "permit.key")}
                failed = command("actual-installed-port-conflict-refused", [SERVER, "control", "--config", deployment / "server.toml"], success=False)
                if b"Address already in use" not in failed and b"os error 98" not in failed:
                    raise ValueError("server failure did not identify the actual occupied TCP port")
                with socket.create_connection(address, timeout=2) as client:
                    peer, _ = holder.accept()
                    with peer:
                        peer.sendall(b"original-port-owner-retained")
                        if client.recv(64) != b"original-port-owner-retained":
                            raise ValueError("conflict refusal disturbed the original listener")
                        client.shutdown(socket.SHUT_WR)
                        if peer.recv(1) != b"":
                            raise ValueError("owned listener fixture did not finish its exact connection")
                if any(producer.digest(deployment / name) != expected for name, expected in retained.items()):
                    raise ValueError("port conflict modified deployment identity or configuration")
            finally:
                holder.close()
            log_path = args.output / "server-after-port-release.log"
            with log_path.open("wb") as log:
                runtime = subprocess.Popen([str(SERVER), "control", "--config", str(deployment / "server.toml")], stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            with urllib.request.urlopen(origin + "/api/v3/health", timeout=0.5) as reply:
                                health = json.load(reply)
                            break
                        except OSError:
                            if runtime.poll() is not None or time.monotonic() >= deadline:
                                raise ValueError("installed server did not become healthy after the original port was released")
                            time.sleep(0.05)
                finally:
                    if runtime.poll() is None:
                        runtime.send_signal(signal.SIGTERM)
                    if runtime.wait(timeout=5) != 0:
                        raise ValueError("installed server did not stop normally after conflict recovery")
            with socket.socket() as released:
                released.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                released.bind(address)
            receipt["actual_port_conflict"] = {"passed": True, "protocol": "TCP", "ordinary_uid": os.geteuid(),
                "installed_server_sha256": producer.digest(SERVER), "package_sha256": producer.digest(package),
                "original_listener_retained": True, "configuration_and_identity_unchanged": True,
                "real_health_after_port_release": health, "normal_server_stop_and_port_rebind": True}
        finally:
            command("uninstall-current-server-fixture", ["sudo", "-n", "dpkg", "--remove", "nestlink-rc-server"])
            if SERVER.exists():
                raise ValueError("server fixture uninstall left executable bytes")
