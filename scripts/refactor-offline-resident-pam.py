"""Hosted fixture: retain a real PAM X11 login for the original resident child.

systemd v255's PAMName adapter supplies PAM_TTY, but not PAM_XDISPLAY;
pam_systemd reads the latter instead of DISPLAY when registering logind's
Display. This thin adapter calls the existing libpam/login stack with the
actual fixture Xvfb display. The product still reads the original system bus
and validates the real child's PID, UID, active session and display itself.
"""
import argparse
import ctypes
import json
import os
import pwd
import signal
import sys


PAM_SILENT = 0x8000
PAM_XDISPLAY = 11
PAM_ESTABLISH_CRED = 2
PAM_DELETE_CRED = 4
PAM_CONV_ERR = 19


class Message(ctypes.Structure):
    _fields_ = [("style", ctypes.c_int), ("message", ctypes.c_char_p)]


class Response(ctypes.Structure):
    _fields_ = [("response", ctypes.c_void_p), ("return_code", ctypes.c_int)]


ConversationFunction = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(Message)),
    ctypes.POINTER(ctypes.POINTER(Response)), ctypes.c_void_p,
)


class Conversation(ctypes.Structure):
    _fields_ = [("function", ConversationFunction), ("data", ctypes.c_void_p)]


def main():
    if (sys.platform != "linux" or os.geteuid() != 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise RuntimeError("R02: real PAM fixture requires a privileged GitHub-hosted Linux service")
    parser = argparse.ArgumentParser()
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--display", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command.pop(0)
    if (args.uid <= 0 or not args.command or not os.path.isabs(args.command[0])
            or not args.display.startswith(":") or not args.display[1:].isdigit()
            or os.environ.get("DISPLAY") != args.display):
        raise RuntimeError("one original normal UID, actual local Xvfb display and absolute child required")
    user = pwd.getpwuid(args.uid)
    pam = ctypes.CDLL("libpam.so.0")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.calloc.restype = ctypes.c_void_p
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int

    @ConversationFunction
    def converse(count, messages, responses, _data):
        # Session/account setup is privileged like systemd's original PAMName
        # path. It cannot prompt for or accept authentication credentials.
        if count <= 0 or count > 32 or any(messages[index].contents.style not in (3, 4)
                                         for index in range(count)):
            return PAM_CONV_ERR
        allocation = libc.calloc(count, ctypes.sizeof(Response))
        if not allocation:
            return PAM_CONV_ERR
        responses[0] = ctypes.cast(allocation, ctypes.POINTER(Response))
        return 0

    conversation = Conversation(converse, None)
    handle = ctypes.c_void_p()
    pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.POINTER(Conversation), ctypes.POINTER(ctypes.c_void_p)]
    pam.pam_set_item.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    pam.pam_putenv.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    pam.pam_getenv.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    pam.pam_getenv.restype = ctypes.c_char_p
    pam.pam_strerror.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pam.pam_strerror.restype = ctypes.c_char_p
    for name in ("pam_acct_mgmt", "pam_setcred", "pam_open_session", "pam_close_session", "pam_end"):
        function = getattr(pam, name)
        function.argtypes = [ctypes.c_void_p, ctypes.c_int]
        function.restype = ctypes.c_int

    def checked(stage, result):
        if result:
            text = pam.pam_strerror(handle, result)
            detail = text.decode("utf-8", errors="replace")[:512] if text else str(result)
            raise RuntimeError(f"original PAM {stage} failed: {detail}")

    opened = False
    credentialed = False
    child = None
    exit_code = 1
    try:
        checked("start", pam.pam_start(b"login", user.pw_name.encode(), ctypes.byref(conversation),
                                       ctypes.byref(handle)))
        display = ctypes.create_string_buffer(args.display.encode())
        checked("XDISPLAY", pam.pam_set_item(handle, PAM_XDISPLAY, ctypes.cast(display, ctypes.c_void_p)))
        for name in ("DISPLAY", "XDG_SESSION_TYPE", "XDG_SESSION_CLASS"):
            checked("environment", pam.pam_putenv(handle, f"{name}={os.environ[name]}".encode()))
        checked("account", pam.pam_acct_mgmt(handle, PAM_SILENT))
        checked("credentials", pam.pam_setcred(handle, PAM_ESTABLISH_CRED | PAM_SILENT))
        credentialed = True
        checked("open_session", pam.pam_open_session(handle, PAM_SILENT))
        opened = True
        session = pam.pam_getenv(handle, b"XDG_SESSION_ID")
        if not session:
            raise RuntimeError("original PAM did not return a registered logind session ID")
        environment = os.environ.copy()
        for name in ("XDG_SESSION_ID", "XDG_SESSION_TYPE", "XDG_SESSION_CLASS", "XDG_SESSION_DESKTOP",
                     "XDG_SEAT", "XDG_VTNR"):
            value = pam.pam_getenv(handle, name.encode())
            if value is not None:
                environment[name] = value.decode()
        environment.update(HOME=user.pw_dir, USER=user.pw_name, LOGNAME=user.pw_name)
        print(json.dumps({"fixture": "original_pam_xdisplay", "uid": args.uid,
                          "pam_xdisplay": args.display, "pam_session_id": session.decode()}),
              file=sys.stderr, flush=True)
        owner_pid = os.getpid()

        def forward(number, _frame):
            if child is not None:
                try:
                    os.kill(child, number)
                except ProcessLookupError:
                    pass

        forwarded = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
        for number in forwarded:
            signal.signal(number, forward)
        child = os.fork()
        if child == 0:
            try:
                for number in forwarded:
                    signal.signal(number, signal.SIG_DFL)
                os.initgroups(user.pw_name, user.pw_gid)
                os.setresgid(user.pw_gid, user.pw_gid, user.pw_gid)
                os.setresuid(args.uid, args.uid, args.uid)
                # Credential changes clear PDEATHSIG. Arm it only after all
                # UID/GID changes, then close the parent-death race explicitly.
                if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != owner_pid:
                    os._exit(125)
                os.execve(args.command[0], args.command, environment)
            except BaseException as error:
                print(f"original PAM resident exec failed: {error}", file=sys.stderr, flush=True)
                os._exit(126)
        _, status = os.waitpid(child, 0)
        child = None
        exit_code = os.waitstatus_to_exitcode(status)
        if exit_code < 0:
            exit_code = 128 - exit_code
    finally:
        if child is not None:
            try:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
            except ProcessLookupError:
                pass
        cleanup_error = None
        for enabled, stage, function, flags in (
            (opened, "close_session", pam.pam_close_session, PAM_SILENT),
            (credentialed, "delete_credentials", pam.pam_setcred, PAM_DELETE_CRED | PAM_SILENT),
        ):
            if enabled:
                try:
                    checked(stage, function(handle, flags))
                except RuntimeError as error:
                    if cleanup_error is None:
                        cleanup_error = error
        if handle:
            result = pam.pam_end(handle, 0)
            handle = ctypes.c_void_p()
            try:
                checked("end", result)
            except RuntimeError as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error:
            raise cleanup_error
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
