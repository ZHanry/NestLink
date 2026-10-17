#!/usr/bin/python3
"""DEB maintainer hook. Only the verified lifecycle transaction may mutate it."""
import json
import os
from pathlib import Path
import re
import pwd
import stat
import subprocess
import sys


def main():
    role, phase, action = sys.argv[1:4]
    if role not in ("desktop", "server") or phase not in ("prerm", "postinst", "postrm"):
        raise ValueError("unknown package hook")
    # dpkg's failed-upgrade recovery calls must remain possible. They do not
    # activate code or touch user state; the lifecycle journal stays fenced.
    if action in ("abort-upgrade", "abort-remove", "abort-deconfigure", "failed-upgrade", "disappear"):
        return
    owner = os.environ.get("NESTLINK_V15_INSTALL_OWNER", "")
    if not re.fullmatch(r"[0-9a-f]{32}", owner):
        raise ValueError("use the signed NestLink v15 lifecycle owner, not direct dpkg/apt")
    marker = Path("/usr/lib/nestlink-v15") / role / "installation-incomplete.json"
    info = marker.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_size > 4096:
        raise ValueError("invalid installation transaction")
    data = json.loads(marker.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or data.get("owner") != owner or data.get("role") != role:
        raise ValueError("package operation does not belong to this transaction")
    if phase == "postinst" and action == "configure":
        if role == "server":
            account = subprocess.run(["getent", "passwd", "nestlink-v15"], check=False, stdout=subprocess.DEVNULL)
            if account.returncode:
                subprocess.run(["useradd", "--system", "--home-dir", "/var/lib/nestlink-v15", "--shell", "/usr/sbin/nologin", "--user-group", "nestlink-v15"], check=True)
            account_info = pwd.getpwnam("nestlink-v15")
            state = Path("/var/lib/nestlink-v15")
            try:
                state.mkdir(mode=0o700)
            except FileExistsError:
                info = state.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != account_info.pw_uid or info.st_mode & 0o077:
                    raise ValueError("server state parent has unexpected ownership/type/permissions")
            else:
                os.chown(state, account_info.pw_uid, account_info.pw_gid)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    # Removal and purge deliberately preserve user identity, quotas, config,
    # update trust, backups and the rollback cache. No recursive user-data wipe.


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("NestLink package hook refused: " + str(error), file=sys.stderr)
        raise SystemExit(1)
