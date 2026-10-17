"""Serve two local site artifacts, run selected browsers, and close owned servers."""
import argparse
from datetime import datetime, timezone
from functools import partial
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


def site_inputs(directory):
    return [
        {"path": path.relative_to(directory).as_posix(), "bytes": path.stat().st_size,
         "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for path in sorted(directory.rglob("*")) if path.is_file()
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verification-dir", required=True, type=Path)
    parser.add_argument("--production-dir", required=True, type=Path)
    parser.add_argument("--playwright-package", required=True, type=Path)
    parser.add_argument("--browsers", default="chrome,edge")
    parser.add_argument("--cases", choices=["all", "identity"], default="all")
    parser.add_argument("--node", default=shutil.which("node"))
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    report = (root / (args.report or Path(
        f"artifacts/core-verification/web-browser-{stamp}-{os.getpid()}.json"))).resolve()
    if not report.is_relative_to(root / "artifacts") or report.exists():
        parser.error("report must be a new file inside repository artifacts")
    if not args.node:
        parser.error("Node.js is required")
    directories = [args.verification_dir.resolve(), args.production_dir.resolve()]
    # Trunk emits index.html even when the input HTML has a different name.
    verification_entry = ("browser-verification.html" if
                          (directories[0] / "browser-verification.html").is_file()
                          else "index.html")
    for directory, entry in zip(directories, [verification_entry, "index.html"]):
        if not (directory / entry).is_file():
            parser.error("missing site entry: " + str(directory / entry))
    report.parent.mkdir(parents=True, exist_ok=True)
    before = [site_inputs(directory) for directory in directories]
    servers = []
    threads = []
    try:
        for directory in directories:
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0), partial(QuietHandler, directory=str(directory)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            servers.append(server)
            thread.start()
            threads.append(thread)
        env = os.environ.copy()
        env.update(
            PLAYWRIGHT_PACKAGE=str(args.playwright_package.resolve()),
            NESTLINK_WEB_BROWSERS=args.browsers,
            NESTLINK_WEB_BROWSER_CASES=args.cases,
            NESTLINK_WEB_BROWSER_REPORT=str(report),
            NESTLINK_WEB_VERIFY_URL=(
                f"http://127.0.0.1:{servers[0].server_port}/{verification_entry}"),
            NESTLINK_WEB_PRODUCTION_URL=f"http://127.0.0.1:{servers[1].server_port}/",
        )
        code = subprocess.run(
            [args.node, str(root / "scripts/refactor-web-browser-check.cjs")],
            cwd=root, env=env, check=False).returncode
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join()
    after = [site_inputs(directory) for directory in directories]
    receipt = report.with_suffix(".site-inputs.json")
    with receipt.open("x", encoding="utf-8") as output:
        json.dump({
            "schema_version": 1,
            "scope": "Local browser check against these static site bytes; not release acceptance",
            "sites": [{"directory": str(directory), "files_before": a, "files_after": b}
                      for directory, a, b in zip(directories, before, after)],
            "verification_entry": verification_entry,
            "site_inputs_unchanged": before == after,
            "owned_servers_closed": True,
            "exit_code": code,
        }, output, ensure_ascii=False, indent=2)
        output.write("\n")
    print("Owned local servers closed; retained site input receipt: " + str(receipt), flush=True)
    return code if before == after else 1


if __name__ == "__main__":
    raise SystemExit(main())
