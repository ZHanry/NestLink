#!/usr/bin/python3
"""Verified Ubuntu 24.04 x64/ARM64 package lifecycle. Never touches v14 state.

This command intentionally requires explicit execution as root. Normal-user
daemons are stopped only through their authenticated IPC maintenance owner.
No forced kill, cross-version state restore or implicit credential import.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid

# In a source checkout the verifier is beside linux/; installed packages place
# exactly the same reviewed module beside this script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "native"))
import release_verify as verify

BASE = Path("/usr/lib/nestlink-v15")
RECEIPTS = Path("/var/lib/nestlink-v15-installer")
CACHE = Path("/var/cache/nestlink-v15")
PACKAGE_NAMES = {"desktop": "nestlink-v15-desktop", "server": "nestlink-v15-server"}


def private_root(path, mode=0o700):
    try:
        path.mkdir(mode=mode)
    except FileExistsError:
        pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & (0o022 if mode == 0o755 else 0o077):
        raise ValueError("installer directory is linked, writable by another user or unowned")


def write_new(path, value, mode=0o600):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def atomic_json(path, value, mode=0o600):
    temporary = path.with_name(path.name + ".new-" + uuid.uuid4().hex)
    write_new(temporary, value, mode)
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run(args, *, env=None, timeout=180):
    result = subprocess.run([str(arg) for arg in args], env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if len(result.stdout) + len(result.stderr) > 1024 * 1024 or result.returncode:
        # Never echo tool output, private paths, configuration or process argv.
        raise ValueError("lifecycle command failed: " + str(args[0]))
    return result.stdout


def validate_instance(value):
    if not isinstance(value, dict) or set(value) != {"schema_version", "namespace", "instance_id", "active"} or type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["namespace"] != "NestLink-v15" or type(value["active"]) is not bool:
        raise ValueError("invalid public installation generation")
    if not isinstance(value["instance_id"], str) or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value["instance_id"]) or value["instance_id"] == "00000000-0000-0000-0000-000000000000":
        raise ValueError("invalid installation generation UUID")
    return value


def public_instance(root):
    marker = root / "installation-instance.json"
    info = verify.regular(marker)
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("installation generation is not root-owned and protected")
    return validate_instance(verify.bounded_json(marker))


def instance_state(root, state):
    instance = public_instance(root)
    if not instance["active"]:
        raise ValueError("installation generation is inactive")
    if state.parent.name == "instances":
        if state.name != instance["instance_id"]:
            raise ValueError("a retained generation is still running; explicit cleanup is required")
        return state
    return state / "instances" / instance["instance_id"]


def next_instance(record):
    prior = record.get("instance")
    if prior is not None:
        validate_instance(prior)
    if record["current"] is not None:
        if prior is None or not prior["active"]:
            raise ValueError("accepted installation has no active generation")
        return dict(prior)
    if prior is not None and prior["active"]:
        raise ValueError("retired receipt still names an active generation")
    return {"schema_version": 1, "namespace": "NestLink-v15", "instance_id": str(uuid.uuid4()), "active": True}


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def pending_instance(root):
    path = root / "installation-instance-pending.json"
    try:
        info = verify.regular(path)
    except FileNotFoundError:
        return None
    if info.st_uid != 0 or info.st_mode & 0o077 or not (root / "installation-incomplete.json").exists():
        raise ValueError("instance recovery record has lost its installation fence")
    value = verify.bounded_json(path)
    if set(value) != {"schema_version", "purpose", "prior_receipt", "prior_instance"} or value["schema_version"] != 1 or value["purpose"] != "installation-instance-transaction":
        raise ValueError("invalid instance recovery record")
    if value["prior_instance"] is not None:
        validate_instance(value["prior_instance"])
    return value


def recover_instance(root, role):
    pending = pending_instance(root)
    if pending is None:
        return
    # Caller owns the exclusive install gate, and its crash journal blocks all
    # product startup. No business was admitted after this pending commit.
    prior = pending["prior_receipt"]
    if prior.get("schema_version") != 1 or prior.get("role") != role:
        raise ValueError("instance recovery receipt belongs to another package role")
    marker = root / "installation-instance.json"
    if pending["prior_instance"] is None:
        if marker.exists():
            verify.regular(marker)
            marker.unlink()
    else:
        atomic_json(marker, pending["prior_instance"], 0o644)
    atomic_json(RECEIPTS / (role + ".json"), prior)
    (root / "installation-instance-pending.json").unlink()
    sync_directory(root)


def commit_instance(root, role, prior, record):
    try:
        original = public_instance(root)
    except FileNotFoundError:
        original = None
    pending = {"schema_version": 1, "purpose": "installation-instance-transaction", "prior_receipt": prior, "prior_instance": original}
    write_new(root / "installation-instance-pending.json", pending)
    sync_directory(root)
    atomic_json(root / "installation-instance.json", validate_instance(record["instance"]), 0o644)
    atomic_json(RECEIPTS / (role + ".json"), record)
    (root / "installation-instance-pending.json").unlink()
    sync_directory(root)


def accepted_update(record, incoming, recover=False):
    sequence = incoming["sequence"]
    maximum = record["maximum_sequence"]
    latest = record.get("maximum_accepted")
    prior = record.get("instance")
    exact_reinstall = (record["current"] is None and prior is not None and not validate_instance(prior)["active"] and sequence == maximum and incoming == latest)
    exact_recovery = recover and incoming == record["current"] and incoming == latest and sequence == maximum
    if sequence < maximum or (sequence == maximum and not exact_reinstall and not exact_recovery):
        raise ValueError("update is replayed or downgraded; only an exact latest accepted reinstall is allowed")
    if latest and latest["update_certificate_sha256"] != incoming["update_certificate_sha256"]:
        raise ValueError("uninstall must not reset pinned update trust")


def read_receipt(role):
    pending = pending_instance(BASE / role)
    if pending is not None:
        result = pending["prior_receipt"]
        if result.get("schema_version") != 1 or result.get("role") != role:
            raise ValueError("invalid interrupted instance receipt")
        return result
    path = RECEIPTS / (role + ".json")
    try:
        info = verify.regular(path)
    except FileNotFoundError:
        return {"schema_version": 1, "role": role, "current": None, "previous": None, "maximum_sequence": 0, "maximum_accepted": None, "instance": None}
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError("installation receipt is not root private")
    result = verify.bounded_json(path)
    if result.get("schema_version") != 1 or result.get("role") != role or type(result.get("maximum_sequence")) is not int:
        raise ValueError("invalid installation receipt")
    result.setdefault("maximum_accepted", result["current"])
    result.setdefault("instance", None)
    return result


def installed_processes(role):
    root = BASE / role
    found = []
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            executable = (process / "exe").resolve(strict=True)
            if not executable.is_relative_to(root):
                continue
            uid = process.stat().st_uid
            raw = (process / "cmdline").read_bytes()
            if len(raw) > 128 * 1024:
                raise ValueError("process argument budget exceeded")
            args = raw.split(b"\0")
            # Installation controllers bypass normal product startup and keep
            # their own exclusive locks; they are never forwarding runtimes.
            if executable.name == "nestlink-daemon" and args[1:2] and args[1] in (b"maintenance", b"shutdown", b"file-quota"):
                continue
            if role == "server":
                found.append((uid, None))
                continue
            account = pwd.getpwuid(uid)
            if b"--state-dir" in args:
                index = args.index(b"--state-dir") + 1
                state = Path(os.fsdecode(args[index]))
            else:
                environment = (process / "environ").read_bytes()
                if len(environment) > 256 * 1024:
                    raise ValueError("process environment budget exceeded")
                values = dict(item.split(b"=", 1) for item in environment.split(b"\0") if b"=" in item)
                parent = Path(os.fsdecode(values.get(b"XDG_STATE_HOME", os.fsencode(Path(account.pw_dir) / ".local/state"))))
                state = parent / "NestLink-v15"
            if uid == 0 or not state.is_absolute():
                raise ValueError("invalid privileged user runtime or relative state")
            found.append((uid, instance_state(root, state)))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return sorted(set(found), key=lambda item: (item[0], str(item[1])))


@contextmanager
def user_maintenance(uid, state, executable):
    account = pwd.getpwuid(uid)
    control_id = str(uuid.uuid4())
    control = state / ("maintenance-" + control_id)
    process = subprocess.Popen(["runuser", "-u", account.pw_name, "--", str(executable), "maintenance",
                                "--state-dir", str(state), "--control-dir", str(control),
                                "--timeout-seconds", "90", "--hold-seconds", "1800"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ready = False
    try:
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ValueError("normal-user maintenance owner stopped before ready")
            try:
                result = verify.bounded_json(control / "ready.json")
            except FileNotFoundError:
                time.sleep(0.05)
                continue
            if result.get("state") != "ready" or result.get("control_id") != control_id:
                raise ValueError("maintenance ready receipt belongs to another owner")
            ready = True
            break
        if not ready:
            raise ValueError("normal-user maintenance timed out without forced termination")
        yield
    finally:
        if ready and process.poll() is None:
            # create-new, uid-owned and private; never replace an existing marker.
            release = control / "release.json"
            with release.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                os.fchown(stream.fileno(), uid, account.pw_gid)
                stream.write(json.dumps({"schema_version": 1, "control_id": control_id, "action": "release"}).encode())
                stream.flush()
                os.fsync(stream.fileno())
            try:
                if process.wait(timeout=10):
                    raise ValueError("maintenance owner did not release successfully")
            except subprocess.TimeoutExpired as error:
                raise ValueError("maintenance release pending; retained installation fence") from error
        # A non-ready owner is bounded by its own deadline and retains a journal.
        # Do not kill it or erase failure evidence. Clean only exact own files
        # after confirmed success; never recurse through a user's state tree.
        if ready and process.poll() == 0:
            for name in ("ready.json", "release.json", "released.json"):
                target = control / name
                info = target.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != uid:
                    raise ValueError("maintenance cleanup owner mismatch")
                target.unlink()
            control.rmdir()


class Transaction:
    def __init__(self, role, recover=False):
        self.role, self.recover = role, recover
        self.owner = uuid.uuid4().hex
        self.root = BASE / role
        self.lock = None

    def __enter__(self):
        private_root(BASE, 0o755)
        private_root(self.root, 0o755)
        private_root(RECEIPTS)
        private_root(CACHE)
        lock_path = self.root / "installation-admission.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        self.lock = os.fdopen(descriptor, "r+b")
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size or info.st_mode & 0o022:
            raise ValueError("invalid stable installation lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = self.root / "installation-v15.json"
        if marker.exists():
            if verify.bounded_json(marker) != {"schema_version": 1, "namespace": "NestLink-v15"}:
                raise ValueError("unknown installation namespace")
        else:
            write_new(marker, {"schema_version": 1, "namespace": "NestLink-v15"}, 0o644)
        journal = self.root / "installation-incomplete.json"
        self.was_incomplete = journal.exists()
        if self.was_incomplete and not self.recover:
            raise ValueError("incomplete transaction requires explicit --recover-incomplete")
        if journal.exists():
            info = verify.regular(journal)
            if info.st_uid != 0 or info.st_mode & 0o077:
                raise ValueError("invalid interrupted transaction owner")
        atomic_json(journal, {"schema_version": 1, "owner": self.owner, "role": self.role})
        return self

    def finish(self):
        (self.root / "installation-incomplete.json").unlink()

    def __exit__(self, kind, value, traceback):
        if self.lock:
            self.lock.close()


def cache_release(data, item, package, manifest, signature, certificate, pin):
    directory = CACHE / item["sha256"]
    if directory.exists():
        verify_selected_cache = verify.verify_selected(directory, directory / "manifest.json", directory / "manifest.p7s", directory / "update.crt", pin, item["id"])
        if verify_selected_cache[1] != item:
            raise ValueError("rollback cache differs from the fixed package")
    else:
        private_root(directory)
        target = directory.joinpath(*verify.relative(item["path"]).parts)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        for source, destination in ((package, target), (manifest, directory / "manifest.json"), (signature, directory / "manifest.p7s"), (certificate, directory / "update.crt")):
            with source.open("rb") as incoming, destination.open("xb") as outgoing:
                os.fchmod(outgoing.fileno(), 0o600)
                shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
                outgoing.flush()
                os.fsync(outgoing.fileno())
        verify.verify_selected(directory, directory / "manifest.json", directory / "manifest.p7s", directory / "update.crt", pin, item["id"])
    return release_record(data, item, manifest, pin)


def release_record(data, item, manifest, pin):
    return {"id": item["id"], "manifest_sha256": verify.sha256(manifest), "package_sha256": item["sha256"],
            "update_certificate_sha256": pin, "version": data["version"], "sequence": data["release_sequence"],
            "source_revision": data["source_revision"], "state_compatibility": item["state_compatibility"]}


def compatible(previous, incoming):
    if previous and previous["state_compatibility"] != incoming["state_compatibility"]:
        raise ValueError("state format differs; use an explicit encrypted backup/migration procedure before upgrading")


def plan_upgrade(args, previous, incoming, record):
    if not previous or previous["state_compatibility"] == incoming["state_compatibility"]:
        return None
    if args.role != "server":
        raise ValueError("this user-state format has no supported migration; preserve data and use a reviewed migrator")
    before = re.fullmatch(r"v15-control-schema([1-9][0-9]*)-epoch1", previous["state_compatibility"])
    after = re.fullmatch(r"v15-control-schema([1-9][0-9]*)-epoch1", incoming["state_compatibility"])
    if before is None or after is None or not 4 <= int(before[1]) < int(after[1]):
        raise ValueError("no supported forward schema/epoch migration exists for this package pair")
    config = getattr(args, "migrate_config", None)
    backup = getattr(args, "migration_backup", None)
    password = getattr(args, "migration_password_file", None)
    if any(value is None or not value.is_absolute() for value in (config, backup, password)):
        raise ValueError("cross-schema upgrade requires explicit absolute config, new encrypted backup and private password-file paths")
    instance = validate_instance(record["instance"])
    expected = Path("/var/lib/nestlink-v15/instances") / instance["instance_id"] / "server.toml"
    if config != expected or backup.is_relative_to(expected.parent) or password.is_relative_to(expected.parent):
        raise ValueError("migration must target the active installation generation and retain backup/password outside its renamed directory")
    return {"config":config,"backup":backup,"password_file":password,"from_schema":int(before[1]),"to_schema":int(after[1])}


def server_command(executable, command, *arguments):
    return run(["runuser", "-u", "nestlink-v15", "--", executable, command, *arguments], timeout=900)


def migration_reply(raw, plan):
    value = json.loads(raw)
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value.get("schema_version") != 1 or value.get("from_schema") != plan["from_schema"] or value.get("to_schema") != plan["to_schema"] or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value.get("transaction_id", "")):
        raise ValueError("native migration receipt does not match the accepted schema transition")
    for field in ("archive_sha256", "old_snapshot_sha256", "new_snapshot_sha256"):
        verify.fixed_hash(value.get(field))
    return value


def select_cached(record):
    directory = CACHE / verify.fixed_hash(record["package_sha256"])
    manifest, signature, certificate = (directory / name for name in ("manifest.json", "manifest.p7s", "update.crt"))
    if verify.sha256(manifest) != record["manifest_sha256"]:
        raise ValueError("cached signed manifest differs from accepted receipt")
    return verify.verify_selected(directory, manifest, signature, certificate, record["update_certificate_sha256"], record["id"])


def activate(root, data, role):
    target = root / "versions" / (data["version"] + "-r" + str(data["release_sequence"]))
    if not target.is_dir() or target.is_symlink():
        raise ValueError("dpkg did not install the fixed versioned payload")
    temporary = root / ("current.new-" + uuid.uuid4().hex)
    temporary.symlink_to(target.relative_to(root))
    os.replace(temporary, root / "current")


def verify_installed_payload(root, data, item, pin, role):
    directory = root / "versions" / (data["version"] + "-r" + str(data["release_sequence"]))
    manifest = directory / "payload.json"
    if verify.sha256(manifest) != item["payload_manifest_sha256"]:
        raise ValueError("installed payload manifest differs from the signed package statement")
    verify.verify_cms(manifest, directory / "payload.p7s", directory / "update.crt", pin)
    inner = verify.validate_manifest(verify.bounded_json(manifest))
    if inner["purpose"] != "native-payload" or any(inner[key] != data[key] for key in ("version", "release_sequence", "source_revision")):
        raise ValueError("installed payload and package statements describe different releases")
    roles = ("server",) if role == "server" else ("desktop", "daemon")
    selected = [value for value in inner["artifacts"] if value["platform"] == "linux" and value["architecture"] == item["architecture"] and value["format"] == "executable" and value["role"] in roles]
    expected = {"nestlink-" + value for value in roles}
    if len(selected) != len(expected) or {Path(value["path"]).name for value in selected} != expected:
        raise ValueError("installed payload contains a different native executable set")
    for value in selected:
        executable = directory / Path(value["path"]).name
        if value["state_compatibility"] != item["state_compatibility"] or verify.regular(executable).st_size != value["bytes"] or verify.sha256(executable) != value["sha256"]:
            raise ValueError("installed executable differs from its independently signed payload")


def package_metadata(package, data, item, role):
    expected_arch = {"x86_64": "amd64", "aarch64": "arm64"}[item["architecture"]]
    for key, expected in (("Package", PACKAGE_NAMES[role]), ("Architecture", expected_arch), ("Version", data["version"] + "-" + str(data["release_sequence"]))):
        if run(["dpkg-deb", "--field", package, key]).decode().strip() != expected:
            raise ValueError("DEB metadata differs from its signed release identity")
    host = {"x86_64": "x86_64", "aarch64": "aarch64"}.get(platform.machine())
    if item["architecture"] != host or item["platform"] != "linux" or item["format"] != "deb" or item["role"] != role:
        raise ValueError("package is for a different platform/role/architecture")


def lifecycle(args):
    with Transaction(args.role, args.recover_incomplete) as transaction, ExitStack() as owners:
        record = read_receipt(args.role)
        recover_instance(transaction.root, args.role)
        original_record = dict(record)
        previous = record["current"]
        active = False
        if args.role == "server":
            active = subprocess.run(["systemctl", "is-active", "--quiet", "nestlink-v15-control.service"], check=False).returncode == 0
            run(["systemctl", "stop", "nestlink-v15-control.service"])
            if installed_processes("server"):
                raise ValueError("a manually started v15 server still owns this installation; stop it gracefully")
        else:
            controller = transaction.root / "current" / "nestlink-daemon"
            for uid, state in installed_processes("desktop"):
                owners.enter_context(user_maintenance(uid, state, controller))
        environment = dict(os.environ, NESTLINK_V15_INSTALL_OWNER=transaction.owner)
        if args.action == "uninstall":
            if previous is None:
                raise ValueError("no active accepted installation to uninstall")
            run(["dpkg", "--remove", PACKAGE_NAMES[args.role]], env=environment)
            current = transaction.root / "current"
            if current.is_symlink():
                current.unlink()
            instance = next_instance(record)
            instance["active"] = False
            record["previous"], record["current"], record["instance"] = previous, None, instance
            commit_instance(transaction.root, args.role, original_record, record)
            transaction.finish()
            return
        migration = None
        if args.action == "rollback":
            incoming = record["previous"]
            if not incoming or not previous:
                raise ValueError("no exact previously accepted package to roll back to")
            compatible(previous, incoming)
            data, item, package = select_cached(incoming)
        else:
            data, item, package = verify.verify_selected(args.bundle, args.manifest, args.signature, args.certificate, args.certificate_sha256, args.artifact_id)
            if data["purpose"] != "native-packages":
                raise ValueError("update is not a native package statement")
            proposed = release_record(data, item, args.manifest, args.certificate_sha256)
            accepted_update(record, proposed, recover=args.recover_incomplete and getattr(transaction, "was_incomplete", False))
            if previous and previous["update_certificate_sha256"] != args.certificate_sha256:
                raise ValueError("update trust-key rotation requires an explicit separately signed procedure")
            incoming = cache_release(data, item, package, args.manifest, args.signature, args.certificate, args.certificate_sha256)
            migration = plan_upgrade(args, previous, incoming, record)
            # Execute only the reverified root-private immutable cache copy.
            # The caller may own/change the downloaded bundle after verification.
            data, item, package = select_cached(incoming)
        package_metadata(package, data, item, args.role)
        generation = next_instance(record)
        complete_transaction = getattr(args, "complete_schema_transaction", None)
        if complete_transaction is not None and (args.role != "server" or not args.recover_incomplete or not getattr(transaction, "was_incomplete", False) or str(uuid.UUID(complete_transaction)) != complete_transaction):
            raise ValueError("complete-schema-transaction requires a canonical transaction UUID and explicit interrupted server-package recovery")
        migration_started = False
        migration_receipt = None
        migration_admission_attempted = False
        executable = transaction.root / "versions" / (data["version"] + "-r" + str(data["release_sequence"])) / "nestlink-server"
        try:
            run(["apt-get", "install", "--yes", "--no-install-recommends"] + (["--allow-downgrades"] if args.action == "rollback" else []) + [package], env=environment, timeout=900)
            verify_installed_payload(transaction.root, data, item, incoming["update_certificate_sha256"], args.role)
            if complete_transaction is not None:
                migration_admission_attempted = True
                directory = Path("/var/lib/nestlink-v15/instances") / generation["instance_id"]
                server_command(executable, "recover-migration", "--directory", directory, "--transaction", complete_transaction, "--complete")
            if migration is not None:
                schema_reply = json.loads(server_command(executable, "schema", "--config", migration["config"]))
                if schema_reply.get("schema") == migration["to_schema"] and args.recover_incomplete and getattr(transaction, "was_incomplete", False):
                    # A prior explicit recovery may have completed migration
                    # while the root package fence remained closed. Never run
                    # a reverse restore after this admission boundary.
                    migration_admission_attempted = True
                else:
                    if schema_reply.get("schema") != migration["from_schema"]:
                        raise ValueError("active deployment schema differs from the signed package migration plan")
                    migration_started = True
                    raw = server_command(executable, "migrate", "--config", migration["config"], "--from-schema", str(migration["from_schema"]), "--to-schema", str(migration["to_schema"]), "--backup", migration["backup"], "--password-file", migration["password_file"], "--defer-admission")
                    migration_receipt = migration_reply(raw, migration)
            activate(transaction.root, data, args.role)
            config = Path("/var/lib/nestlink-v15/instances") / generation["instance_id"] / "server.toml"
            configured = args.role == "server" and config.exists()
            if configured and migration_receipt is None:
                run(["runuser", "-u", "nestlink-v15", "--", transaction.root / "current/nestlink-server", "check", "--config", config])
            latest = record.get("maximum_accepted") if args.action == "rollback" else incoming
            record.update(current=incoming, previous=previous, maximum_sequence=max(record["maximum_sequence"], data["release_sequence"]), maximum_accepted=latest, instance=generation)
            commit_instance(transaction.root, args.role, original_record, record)
            if migration_receipt is not None:
                migration_admission_attempted = True
                server_command(executable, "recover-migration", "--directory", migration["config"].parent, "--transaction", migration_receipt["transaction_id"], "--complete")
            transaction.finish()
        except (OSError, ValueError, subprocess.SubprocessError):
            if migration_admission_attempted or (migration_started and migration_receipt is None):
                # Unknown completion/finalization must retain the package gate
                # and new migrator; downgrading its executable could strand a
                # new schema or resurrect a pre-revocation snapshot.
                raise
            if migration_receipt is not None:
                server_command(executable, "recover-migration", "--directory", migration["config"].parent, "--transaction", migration_receipt["transaction_id"], "--rollback")
            if previous:
                old_data, old_item, old_package = select_cached(previous)
                if migration_receipt is None:
                    compatible(previous, incoming)
                package_metadata(old_package, old_data, old_item, args.role)
                run(["dpkg", "--force-downgrade", "--install", old_package], env=environment)
                verify_installed_payload(transaction.root, old_data, old_item, previous["update_certificate_sha256"], args.role)
                activate(transaction.root, old_data, args.role)
                # A failed upgrade remains explicit, even after the old exact
                # binary was restored. A new recovery invocation must finish
                # the retained journal before any v15 product may restart.
            raise
        if active and configured:
            run(["systemctl", "start", "nestlink-v15-control.service"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "rollback", "uninstall", "assert-ready"))
    parser.add_argument("--role", choices=PACKAGE_NAMES, required=True)
    parser.add_argument("--recover-incomplete", action="store_true")
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--certificate-sha256")
    parser.add_argument("--artifact-id")
    parser.add_argument("--migrate-config", type=Path)
    parser.add_argument("--migration-backup", type=Path)
    parser.add_argument("--migration-password-file", type=Path)
    parser.add_argument("--complete-schema-transaction", help="explicitly finish this still-fenced schema transaction during --recover-incomplete")
    parser.add_argument("--require-config", action="store_true", help="service condition: require this generation's explicit server.toml")
    args = parser.parse_args()
    if sys.platform != "linux":
        raise ValueError("Ubuntu lifecycle requires Linux")
    if args.action == "assert-ready":
        if (BASE / args.role / "installation-incomplete.json").exists():
            raise ValueError("installation maintenance is incomplete")
        instance = public_instance(BASE / args.role)
        if not instance["active"]:
            raise ValueError("installation generation is retired")
        if args.require_config:
            if args.role != "server":
                raise ValueError("require-config is only valid for the server role")
            config = Path("/var/lib/nestlink-v15/instances") / instance["instance_id"] / "server.toml"
            verify.regular(config)
        return
    if os.geteuid() != 0:
        raise ValueError("run this installation command explicitly as root")
    if args.action == "install" and any(getattr(args, field) is None for field in ("bundle", "manifest", "signature", "certificate", "certificate_sha256", "artifact_id")):
        parser.error("install requires fixed bundle/manifest/signature/public certificate pin/artifact id")
    lifecycle(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("NestLink lifecycle refused: " + str(error), file=sys.stderr)
        raise SystemExit(1)
