"""Pinned official game processes, only in an explicit GitHub-hosted lab.

The real client handles discovery, connection, game packets, rendering and demo
recording. This driver uses its ordinary console/UI; it implements no game wire
protocol. Its public evidence never contains NestLink management credentials.
"""
import argparse
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import tarfile
import time
import urllib.request


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hosted():
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.geteuid() != 0, "original game driver must be the ordinary runner"


def prepare(output, game):
    hosted()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    manifest = json.loads(pathlib.Path("config/network-games.json").read_text())[game]
    archive = output / (game + ".tar.gz")
    with urllib.request.urlopen(manifest["url"], timeout=120) as response:
        archive.write_bytes(response.read())
    assert sha256(archive) == manifest["sha256"]
    assert archive.stat().st_size == manifest["bytes"]
    with tarfile.open(archive) as bundle:
        bundle.extractall(output, filter="data")
    root = output / manifest["directory"]
    for name, expected in manifest["files"].items():
        assert sha256(root / name) == expected, name
    (output / "upstream-inputs.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(str(root), flush=True)


class Actors:
    def __init__(self, output):
        self.output = output
        self.actors = []
        self.commands = []

    def start(self, name, argv, env=None, cwd=None):
        log = (self.output / (name + ".log")).open("wb")
        process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                                   env=env, cwd=cwd, start_new_session=True)
        self.actors.append((name, process, log))
        self.commands.append({"name": name, "command": argv, "pid": process.pid})
        return process

    def run(self, argv, env=None, timeout=10):
        result = subprocess.run(argv, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout, check=False)
        self.commands.append({"command": argv, "return_code": result.returncode,
                              "output": result.stdout.decode(errors="replace")})
        assert result.returncode == 0, self.commands[-1]
        return result.stdout.decode(errors="replace")

    def close(self):
        failures = []
        for name, process, log in reversed(self.actors):
            if process.poll() is None:
                # This still-live exact parent holds its own freshly created
                # process group. No searched or reconstructed PID is accepted.
                subprocess.run(["sudo", "-n", "kill", "-TERM", "--", "-" + str(process.pid)],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    failures.append(name + " required final SIGKILL")
                    subprocess.run(["sudo", "-n", "kill", "-KILL", "--", "-" + str(process.pid)],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5)
                    process.wait(timeout=5)
            log.close()
        return failures


def namespace(name, argv, env=None):
    # Namespace selection needs the root wrapper. The actual unmodified game
    # image runs under the original ordinary UID/GID, with no capabilities.
    values = ["HOME=" + os.environ["HOME"]]
    values.extend(key + "=" + value for key, value in (env or {}).items())
    return ["sudo", "-n", "ip", "netns", "exec", name, "setpriv",
            "--reuid=" + str(os.getuid()), "--regid=" + str(os.getgid()),
            "--init-groups", "--no-new-privs", "env", *values, *map(str, argv)]


def wait_for(predicate, seconds, description):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(description)


def teeworlds():
    hosted()
    output = pathlib.Path(os.environ["NESTLINK_GAME_EVIDENCE"]).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    prepared = pathlib.Path(os.environ["NESTLINK_GAME_PREPARED"]).resolve()
    manifest = json.loads(pathlib.Path("config/network-games.json").read_text())["teeworlds"]
    root = prepared / manifest["directory"]
    for name, expected in manifest["files"].items():
        assert sha256(root / name) == expected, name
    actors = Actors(output)
    receipt = {"schema_version": 1, "source_revision": os.environ["GITHUB_SHA"],
               "game": manifest, "commands": actors.commands, "ordinary_uid": os.getuid(),
               "scope": "hosted isolated dual LAN real official Teeworlds; no physical site or human gameplay acceptance",
               "passed": False}
    failure = None
    try:
        left = os.environ["NESTLINK_LAN_0_NAMESPACE"]
        right = os.environ["NESTLINK_LAN_1_NAMESPACE"]
        home = output / "teeworlds-home"
        home.mkdir(mode=0o700)
        display = ":97"
        env = os.environ.copy()
        env.update(DISPLAY=display, LIBGL_ALWAYS_SOFTWARE="1", SDL_AUDIODRIVER="dummy", HOME=str(home))
        xvfb = actors.start("teeworlds-xvfb", ["Xvfb", display, "-screen", "0", "1024x768x24", "-nolisten", "tcp"], env=env)
        wait_for(lambda: pathlib.Path("/tmp/.X11-unix/X97").exists(), 5, "Xvfb did not become ready")
        server_config = output / "teeworlds-server.cfg"
        server_config.write_text('sv_name "NestLink W28 real room"\nsv_port 8304\nbindaddr 192.168.212.3\nsv_map dm1\nsv_register 0\nsv_gametype dm\nsv_max_clients 4\ndebug 1\nconsole_output_level 2\n')
        server = actors.start("teeworlds-server", namespace(right,
            [root / "teeworlds_srv", "-f", server_config]), cwd=root)
        capture = actors.start("teeworlds-packet-capture", ["sudo", "-n", "ip", "netns", "exec", left,
            "tcpdump", "-i", "nlp0", "-U", "-n", "-w", str(output / "teeworlds-client.pcap"), "udp"])
        client_config = output / "teeworlds-client.cfg"
        client_config.write_text('player_name "NestLinkHosted"\ncl_show_welcome 0\ncl_skip_start_menu 1\nui_browser_page 6\ngfx_fullscreen 0\ngfx_screen_width 1024\ngfx_screen_height 768\ngfx_limitfps 1\ngfx_maxfps 30\nsnd_enable 0\ndebug 1\nconsole_output_level 2\ncl_auto_demo_record 1\n')
        client = actors.start("teeworlds-client", namespace(left,
            [root / "teeworlds", "-f", client_config],
            {key: env[key] for key in ("DISPLAY", "LIBGL_ALWAYS_SOFTWARE", "SDL_AUDIODRIVER", "HOME")}), cwd=root)
        def live():
            assert client.poll() is None and server.poll() is None and xvfb.poll() is None
            return True
        window = actors.run(["xdotool", "search", "--sync", "--onlyvisible", "--name", "Teeworlds"],
                            env=env, timeout=10).splitlines()[0]
        actors.run(["xdotool", "windowfocus", "--sync", window], env=env)
        time.sleep(3)
        actors.run(["import", "-window", "root", str(output / "teeworlds-lan-browser.png")], env=env)
        browser_text = actors.run(["tesseract", str(output / "teeworlds-lan-browser.png"), "stdout"], env=env)
        (output / "teeworlds-lan-browser.txt").write_text(browser_text)
        assert "NestLink" in browser_text and "W28" in browser_text, "real LAN room missing from official browser"
        def console(command):
            actors.run(["xdotool", "key", "F1"], env=env)
            time.sleep(0.15)
            actors.run(["xdotool", "type", "--clearmodifiers", "--delay", "2", command], env=env)
            actors.run(["xdotool", "key", "Return"], env=env)
            time.sleep(0.1)
            actors.run(["xdotool", "key", "F1"], env=env)
        console("connect 192.168.211.2:8303")
        server_log = output / "teeworlds-server.log"
        wait_for(lambda: live() and "player has entered the game" in server_log.read_text(errors="replace"),
                 12, "official server did not accept real client into game")
        started = time.monotonic()
        for key in ("d", "a", "space", "d"):
            actors.run(["xdotool", "keydown", key], env=env)
            time.sleep(2.5)
            actors.run(["xdotool", "keyup", key], env=env)
            live()
        actors.run(["import", "-window", "root", str(output / "teeworlds-playing.png")], env=env)
        receipt["sustained_play_seconds"] = time.monotonic() - started
        (output / "teeworlds-ready-for-revoke").write_text("real joined client completed input sequence")
        wait_for(lambda: (output / "teeworlds-revoked").exists(), 5, "original management did not commit revocation")
        revoked_at = time.monotonic()
        client_log = output / "teeworlds-client.log"
        wait_for(lambda: live() and "offline error=" in client_log.read_text(errors="replace"),
                 18, "official client did not disconnect after original authority revocation")
        receipt["client_offline_after_revocation_seconds"] = time.monotonic() - revoked_at
        actors.run(["import", "-window", "root", str(output / "teeworlds-revoked.png")], env=env)
        console("quit")
        assert client.wait(timeout=5) == 0
        demos = [path for path in home.rglob("*.demo") if path.is_file()]
        assert demos and any(path.stat().st_size > 1024 for path in demos), "official snapshots/demo not retained"
        receipt.update(actual_official_client=True, actual_official_server=True,
                       official_lan_browser_room_observed=True, actual_map="dm1",
                       movement_input_sequence=["right 2.5s", "left 2.5s", "jump 2.5s", "right 2.5s"],
                       actual_management_revocation=True, official_client_exit_code=0,
                       demo_files=[{"path": str(path.relative_to(output)), "sha256": sha256(path),
                                    "bytes": path.stat().st_size} for path in demos])
    except BaseException as error:
        failure = type(error).__name__ + ": " + str(error)
    finally:
        cleanup = actors.close()
        receipt.update(failure=failure, cleanup_errors=cleanup, passed=failure is None and not cleanup)
        receipt["files"] = [{"path": str(path.relative_to(output)), "sha256": sha256(path),
                             "bytes": path.stat().st_size} for path in sorted(output.rglob("*"))
                            if path.is_file() and path.name != "teeworlds-execution.json"]
        (output / "teeworlds-execution.json").write_text(json.dumps(receipt, indent=2) + "\n")
    assert receipt["passed"], receipt.get("failure") or receipt["cleanup_errors"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "teeworlds"))
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--game", choices=("teeworlds",), default="teeworlds")
    args = parser.parse_args()
    if args.action == "prepare":
        assert args.output is not None
        prepare(args.output.resolve(), args.game)
    else:
        teeworlds()
