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
import shutil
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


def download(output, manifest, name):
    archive = output / (name + ".tar.gz")
    with urllib.request.urlopen(manifest["url"], timeout=120) as response:
        archive.write_bytes(response.read())
    assert sha256(archive) == manifest["sha256"]
    assert archive.stat().st_size == manifest["bytes"]
    with tarfile.open(archive) as bundle:
        bundle.extractall(output, filter="data")
    root = output / manifest["directory"]
    for name, expected in manifest["files"].items():
        assert sha256(root / name) == expected, name
    return root


def prepare(output, game):
    hosted()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    manifest = json.loads(pathlib.Path("config/network-games.json").read_text())[game]
    root = download(output, manifest, game)
    if game == "luanti":
        content = download(output, manifest["content"], "minetest-game")
        shutil.copytree(content, root / "games" / "minetest")
        for name, expected in manifest["content"]["files"].items():
            assert sha256(root / "games" / "minetest" / name) == expected
        subprocess.run(["cmake", "-S", str(root), "-B", str(root / "build"), "-G", "Ninja",
                        "-DRUN_IN_PLACE=TRUE", "-DBUILD_SERVER=TRUE", "-DBUILD_CLIENT=TRUE",
                        "-DCMAKE_BUILD_TYPE=Release", "-DENABLE_SOUND=FALSE", "-DENABLE_CURL=FALSE",
                        "-DENABLE_GETTEXT=FALSE", "-DBUILD_UNITTESTS=FALSE"], check=True)
        subprocess.run(["cmake", "--build", str(root / "build"), "--parallel", "2"], check=True)
        built = {"source_revision": manifest["source_revision"], "binaries": {
            name: sha256(root / "bin" / name) for name in ("luanti", "luantiserver")}}
        (output / "luanti-build.json").write_text(json.dumps(built, indent=2) + "\n")
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

    def window(self, title, env, seconds):
        # The upstream SDL window can be mapped before its caption is set.
        # Query the current X state repeatedly; a single --sync query can wait
        # on creation events after that already existing window changes title.
        argv = ["xdotool", "search", "--onlyvisible", "--name", title]
        deadline = time.monotonic() + seconds
        attempts = 0
        blocked_queries = 0
        while time.monotonic() < deadline:
            attempts += 1
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                result = subprocess.run(argv, env=env, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, timeout=min(2, remaining), check=False)
            except subprocess.TimeoutExpired:
                # Initial software GL setup can hold the X server briefly.
                # A blocked individual observation is still pending startup;
                # it consumes the same absolute bound, never an added retry.
                blocked_queries += 1
                continue
            assert result.returncode in (0, 1), result.stdout.decode(errors="replace")
            if result.returncode == 0:
                windows = result.stdout.decode().splitlines()
                assert len(windows) == 1, "exact owned X server must expose one matching game window"
                self.commands.append({"command": argv, "return_code": 0,
                                      "attempts": attempts, "blocked_queries": blocked_queries,
                                      "window_ids": windows})
                actual = self.run(["xdotool", "getwindowname", windows[0]], env=env)
                assert title in actual
                return windows[0]
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        self.commands.append({"command": argv, "attempts": attempts, "timed_out": True,
                              "blocked_queries": blocked_queries, "timeout_seconds": seconds})
        raise AssertionError("actual visible " + title + " window did not appear within its startup bound")

    def observe_failure(self, prefix, env):
        errors = []
        for argv in (["import", "-window", "root", str(self.output / (prefix + "-failure.png"))],
                     ["xwininfo", "-root", "-tree"]):
            try:
                observed = self.run(argv, env=env, timeout=5)
                if argv[0] == "xwininfo":
                    (self.output / (prefix + "-failure-windows.txt")).write_text(observed)
            except BaseException as error:
                errors.append(type(error).__name__ + ": " + str(error))
        return errors

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
    env = None
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
        # A unicast-only UDP bind cannot receive the upstream LAN broadcast.
        # The namespace has only this one isolated LAN; the bridge still pins
        # every response to the original exact 192.168.212.3:8304 server.
        server_config.write_text('sv_name "NestLink W28 real room"\nsv_port 8304\nbindaddr 0.0.0.0\nsv_map dm1\nsv_register 0\nsv_gametype dm\nsv_max_clients 4\ndebug 1\nconsole_output_level 2\n')
        # The official storage API deliberately refuses absolute config paths.
        # Keep a public receipt copy, then use its unchanged bytes relative to
        # the original archive's current storage root.
        shutil.copyfile(server_config, root / "nestlink-hosted-server.cfg")
        server = actors.start("teeworlds-server", namespace(right,
            [root / "teeworlds_srv", "-f", "nestlink-hosted-server.cfg"]), cwd=root)
        capture = actors.start("teeworlds-packet-capture", ["sudo", "-n", "ip", "netns", "exec", left,
            "tcpdump", "-i", "nlp0", "-U", "-n", "-w", str(output / "teeworlds-client.pcap"), "udp"])
        actors.start("teeworlds-server-packet-capture", ["sudo", "-n", "ip", "netns", "exec", right,
            "tcpdump", "-i", "nlp1", "-U", "-n", "-w", str(output / "teeworlds-server.pcap"), "udp"])
        client_config = output / "teeworlds-client.cfg"
        client_config.write_text('player_name "NestLinkHosted"\ncl_show_welcome 0\ncl_skip_start_menu 1\nui_browser_page 6\ngfx_fullscreen 0\ngfx_screen_width 1024\ngfx_screen_height 768\ngfx_limitfps 1\ngfx_maxfps 30\nsnd_enable 0\ndebug 1\nconsole_output_level 2\ncl_auto_demo_record 1\n')
        shutil.copyfile(client_config, root / "nestlink-hosted-client.cfg")
        client = actors.start("teeworlds-client", namespace(left,
            [root / "teeworlds", "-f", "nestlink-hosted-client.cfg"],
            {key: env[key] for key in ("DISPLAY", "LIBGL_ALWAYS_SOFTWARE", "SDL_AUDIODRIVER", "HOME")}), cwd=root)
        def live():
            assert client.poll() is None and server.poll() is None and xvfb.poll() is None
            return True
        window = actors.window("Teeworlds", env, 10)
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
        if env is not None:
            receipt["failure_observation_errors"] = actors.observe_failure("teeworlds", env)
    finally:
        cleanup = actors.close()
        receipt.update(failure=failure, cleanup_errors=cleanup, passed=failure is None and not cleanup)
        receipt["files"] = [{"path": str(path.relative_to(output)), "sha256": sha256(path),
                             "bytes": path.stat().st_size} for path in sorted(output.rglob("*"))
                            if path.is_file() and path.name != "teeworlds-execution.json"]
        (output / "teeworlds-execution.json").write_text(json.dumps(receipt, indent=2) + "\n")
    assert receipt["passed"], receipt.get("failure") or receipt["cleanup_errors"]


def luanti():
    hosted()
    output = pathlib.Path(os.environ["NESTLINK_GAME_EVIDENCE"]).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    prepared = pathlib.Path(os.environ["NESTLINK_GAME_PREPARED"]).resolve()
    manifest = json.loads(pathlib.Path("config/network-games.json").read_text())["luanti"]
    root = prepared / manifest["directory"]
    binaries = json.loads((prepared / "luanti-build.json").read_text())
    for name, expected in binaries["binaries"].items():
        assert sha256(root / "bin" / name) == expected
    actors = Actors(output)
    receipt = {"schema_version": 1, "source_revision": os.environ["GITHUB_SHA"],
               "game": manifest, "build": binaries, "commands": actors.commands,
               "ordinary_uid": os.getuid(), "passed": False,
               "scope": "hosted real Luanti+Minetest Game through original kernel TUN/prefix NAT/QUIC with explicit signed mechanism credentials; production login/one-use and physical sites retain separate evidence"}
    failure = None
    env = None
    try:
        left = os.environ["NESTLINK_LUANTI_0_NAMESPACE"]
        right = os.environ["NESTLINK_LUANTI_1_NAMESPACE"]
        home = output / "luanti-home"
        home.mkdir(mode=0o700)
        env = os.environ.copy()
        env.update(DISPLAY=":96", LIBGL_ALWAYS_SOFTWARE="1", SDL_AUDIODRIVER="dummy", HOME=str(home))
        xvfb = actors.start("luanti-xvfb", ["Xvfb", ":96", "-screen", "0", "1024x768x24", "-nolisten", "tcp"], env=env)
        wait_for(lambda: pathlib.Path("/tmp/.X11-unix/X96").exists(), 5, "Luanti Xvfb did not become ready")
        world = output / "luanti-world"
        world.mkdir(mode=0o700)
        (world / "world.mt").write_text("gameid = minetest\nbackend = sqlite3\nplayer_backend = sqlite3\nauth_backend = sqlite3\ncreative_mode = true\nenable_damage = false\n")
        server_config = output / "luanti-server.conf"
        server_config.write_text("server_name = NestLink Luanti real room\nserver_announce = false\nenable_ipv6 = false\nbind_address = 192.168.1.42\nport = 45123\nmax_users = 2\ndisallow_empty_password = false\ncreative_mode = true\nenable_damage = false\nmg_name = flat\nmgflat_spflags = nolakes,nohills\nstatic_spawnpoint = (0, 10, 0)\n")
        server = actors.start("luanti-server", namespace(right,
            [root / "bin" / "luantiserver", "--config", server_config, "--world", world,
             "--gameid", "minetest", "--logfile", output / "luanti-server-debug.log"]), cwd=root)
        actors.start("luanti-packet-capture", ["sudo", "-n", "ip", "netns", "exec", left,
            "tcpdump", "-i", "eth0", "-U", "-n", "-w", str(output / "luanti-client.pcap"), "udp", "port", "45123"])
        client_config = output / "luanti-client.conf"
        client_config.write_text("enable_sound = false\nfullscreen = false\nscreen_w = 1024\nscreen_h = 768\nvsync = false\nfps_max = 30\nviewing_range = 20\nclouds = false\nvideo_driver = opengl\n")
        client = actors.start("luanti-client", namespace(left,
            [root / "bin" / "luanti", "--info", "--go", "--address", "10.211.2.42", "--port", "45123",
             "--name", "NestLinkHosted", "--password", "", "--config", client_config,
             "--logfile", output / "luanti-client-debug.log"],
            {key: env[key] for key in ("DISPLAY", "LIBGL_ALWAYS_SOFTWARE", "SDL_AUDIODRIVER", "HOME")}), cwd=root)
        window = actors.window("Luanti", env, 25)
        actors.run(["xdotool", "windowfocus", "--sync", window], env=env)
        def live():
            assert client.poll() is None and server.poll() is None and xvfb.poll() is None
            return True
        server_log = output / "luanti-server-debug.log"
        wait_for(lambda: live() and server_log.exists() and "joins game" in server_log.read_text(errors="replace"),
                 20, "actual Luanti player did not join through approved alias")
        joined = server_log.read_text(errors="replace")
        assert "NestLinkHosted [192.168.1.254] joins game" in joined, "server did not observe original gateway's approved LAN masquerade"
        started = time.monotonic()
        for key in ("w", "s", "space"):
            actors.run(["xdotool", "keydown", key], env=env)
            time.sleep(3)
            actors.run(["xdotool", "keyup", key], env=env)
            live()
        actors.run(["xdotool", "mousemove_relative", "--", "0", "300"], env=env)
        actors.run(["xdotool", "mousedown", "1"], env=env)
        time.sleep(2)
        actors.run(["xdotool", "mouseup", "1"], env=env)
        actors.run(["import", "-window", "root", str(output / "luanti-playing.png")], env=env)
        receipt["sustained_play_seconds"] = time.monotonic() - started
        (output / "luanti-ready-for-stop").write_text("real player joined and completed original game input sequence")
        wait_for(lambda: (output / "luanti-owner-stopped").exists(), 6, "original packet owner did not stop and release")
        stopped_at = time.monotonic()
        client_log = output / "luanti-client-debug.log"
        wait_for(lambda: client_log.exists() and "Connection error" in client_log.read_text(errors="replace"),
                 25, "official Luanti client did not observe stopped original data path")
        receipt["client_disconnect_after_original_stop_seconds"] = time.monotonic() - stopped_at
        actors.run(["import", "-window", "root", str(output / "luanti-stopped.png")], env=env)
        receipt["official_client_exit_code"] = client.wait(timeout=5)
        # Official --go skips the menu and exits with failure after a network
        # disconnection. That exact upstream exit contract is expected here.
        assert receipt["official_client_exit_code"] == 1
        receipt.update(actual_official_client=True, actual_official_server=True,
                       actual_minimum_game_content="Minetest Game 5.8.0 (complete unchanged package)",
                       direct_ip_join="10.211.2.42:45123", server_observed_peer="192.168.1.254",
                       expected_upstream_go_network_error_exit_code=1,
                       movement_input_sequence=["forward 3s", "backward 3s", "jump 3s", "dig 2s"],
                       original_packet_owner_stop=True, production_management_revocation_claimed=False)
    except BaseException as error:
        failure = type(error).__name__ + ": " + str(error)
        if env is not None:
            receipt["failure_observation_errors"] = actors.observe_failure("luanti", env)
    finally:
        cleanup = actors.close()
        receipt.update(failure=failure, cleanup_errors=cleanup, passed=failure is None and not cleanup)
        receipt["files"] = [{"path": str(path.relative_to(output)), "sha256": sha256(path),
                             "bytes": path.stat().st_size} for path in sorted(output.rglob("*"))
                            if path.is_file() and path.name != "luanti-execution.json"]
        (output / "luanti-execution.json").write_text(json.dumps(receipt, indent=2) + "\n")
    assert receipt["passed"], receipt.get("failure") or receipt["cleanup_errors"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt("original coordinator stopped")))
    parser.add_argument("action", choices=("prepare", "teeworlds", "luanti"))
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--game", choices=("teeworlds", "luanti"), default="teeworlds")
    args = parser.parse_args()
    if args.action == "prepare":
        assert args.output is not None
        prepare(args.output.resolve(), args.game)
    elif args.action == "teeworlds":
        teeworlds()
    else:
        luanti()
