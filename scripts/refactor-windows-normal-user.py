#!/usr/bin/env python3
"""Run Windows business-process checks with a verified medium, non-admin token.

GitHub's hosted Windows runner starts elevated. NestLink's daemon and its
private-file tests deliberately require the ordinary desktop user's token.
Filter the caller's own token without changing the account, machine, or ACLs.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import shutil
import subprocess
import sys


def run(arguments: list[str]) -> int:
    if sys.platform != "win32":
        raise RuntimeError("this launcher requires Windows")
    if not arguments:
        raise ValueError("provide a command, or --check to verify the test token")
    force_filter = arguments[0] == "--filter-token"
    if force_filter:
        arguments = arguments[1:]
        if not arguments:
            raise ValueError("--filter-token requires a command or --check")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.c_void_p
    handle = wintypes.HANDLE
    dword = wintypes.DWORD
    boolean = wintypes.BOOL

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", pointer), ("attributes", dword)]

    class StartupInfo(ctypes.Structure):
        _fields_ = [
            ("size", dword), ("reserved", wintypes.LPWSTR),
            ("desktop", wintypes.LPWSTR), ("title", wintypes.LPWSTR),
            ("x", dword), ("y", dword), ("width", dword), ("height", dword),
            ("chars_x", dword), ("chars_y", dword), ("fill", dword),
            ("flags", dword), ("show", wintypes.WORD),
            ("reserved_size", wintypes.WORD), ("reserved_bytes", pointer),
            ("stdin", handle), ("stdout", handle), ("stderr", handle),
        ]

    class ProcessInfo(ctypes.Structure):
        _fields_ = [
            ("process", handle), ("thread", handle),
            ("process_id", dword), ("thread_id", dword),
        ]

    kernel.GetCurrentProcess.restype = handle
    kernel.CloseHandle.argtypes = [handle]
    kernel.CloseHandle.restype = boolean
    kernel.GetStdHandle.argtypes = [dword]
    kernel.GetStdHandle.restype = handle
    kernel.WaitForSingleObject.argtypes = [handle, dword]
    kernel.WaitForSingleObject.restype = dword
    kernel.GetExitCodeProcess.argtypes = [handle, ctypes.POINTER(dword)]
    kernel.GetExitCodeProcess.restype = boolean
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer
    security.OpenProcessToken.argtypes = [handle, dword, ctypes.POINTER(handle)]
    security.OpenProcessToken.restype = boolean
    security.GetTokenInformation.argtypes = [handle, ctypes.c_int, pointer, dword, ctypes.POINTER(dword)]
    security.GetTokenInformation.restype = boolean
    security.SetTokenInformation.argtypes = [handle, ctypes.c_int, pointer, dword]
    security.SetTokenInformation.restype = boolean
    security.CreateRestrictedToken.argtypes = [
        handle, dword, dword, pointer, dword, pointer, dword, pointer,
        ctypes.POINTER(handle),
    ]
    security.CreateRestrictedToken.restype = boolean
    security.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(pointer)]
    security.ConvertStringSidToSidW.restype = boolean
    security.GetLengthSid.argtypes = [pointer]
    security.GetLengthSid.restype = dword
    security.GetSidSubAuthorityCount.argtypes = [pointer]
    security.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    security.GetSidSubAuthority.argtypes = [pointer, dword]
    security.GetSidSubAuthority.restype = ctypes.POINTER(dword)
    security.CreateProcessAsUserW.argtypes = [
        handle, wintypes.LPCWSTR, wintypes.LPWSTR, pointer, pointer,
        boolean, dword, pointer, wintypes.LPCWSTR,
        ctypes.POINTER(StartupInfo), ctypes.POINTER(ProcessInfo),
    ]
    security.CreateProcessAsUserW.restype = boolean

    def checked(result: object) -> None:
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())

    def information(token: handle, category: int) -> ctypes.Array:
        size = dword()
        security.GetTokenInformation(token, category, None, 0, ctypes.byref(size))
        # TokenElevation requires the exact DWORD size and returns BAD_LENGTH
        # for its size query; variable-sized token classes use INSUFFICIENT_BUFFER.
        if ctypes.get_last_error() not in (24, 122) or not size.value:
            raise ctypes.WinError(ctypes.get_last_error())
        data = ctypes.create_string_buffer(size.value)
        checked(security.GetTokenInformation(token, category, data, size, ctypes.byref(size)))
        return data

    def normal(token: handle) -> bool:
        elevated = ctypes.cast(information(token, 20), ctypes.POINTER(dword)).contents.value
        label_data = information(token, 25)
        label = ctypes.cast(label_data, ctypes.POINTER(SidAndAttributes)).contents
        count = security.GetSidSubAuthorityCount(label.sid).contents.value
        if not count:
            return False
        integrity = security.GetSidSubAuthority(label.sid, count - 1).contents.value
        session = ctypes.cast(information(token, 12), ctypes.POINTER(dword)).contents.value
        return not elevated and 0x2000 <= integrity < 0x3000 and session != 0

    original = handle()
    filtered = handle()
    medium_sid = pointer()
    process = ProcessInfo()
    try:
        # QUERY | DUPLICATE | ASSIGN_PRIMARY | ADJUST_DEFAULT. A restricted
        # version of our own primary token needs no foreign-account logon.
        checked(security.OpenProcessToken(kernel.GetCurrentProcess(), 0x8B, ctypes.byref(original)))
        selected = original
        if force_filter or not normal(original):
            # LUA_TOKEN | DISABLE_MAX_PRIVILEGE removes administrative groups
            # and privileges, including an elevated token's default owner.
            checked(security.CreateRestrictedToken(
                original, 0x5, 0, None, 0, None, 0, None, ctypes.byref(filtered)
            ))
            checked(security.ConvertStringSidToSidW("S-1-16-8192", ctypes.byref(medium_sid)))
            label = SidAndAttributes(medium_sid, 0x20)
            checked(security.SetTokenInformation(
                filtered, 25, ctypes.byref(label),
                ctypes.sizeof(label) + security.GetLengthSid(medium_sid),
            ))
            # Newly created private directories must belong to the actual
            # user, even if the runner's original default owner was Admins.
            user_data = information(filtered, 1)
            user = ctypes.cast(user_data, ctypes.POINTER(SidAndAttributes)).contents
            owner = pointer(user.sid)
            checked(security.SetTokenInformation(filtered, 4, ctypes.byref(owner), ctypes.sizeof(owner)))
            selected = filtered
        if not normal(selected):
            raise RuntimeError("refusing to run business tests without a medium, non-elevated user token")
        print("Windows test token verified: medium integrity, non-elevated, interactive user session", flush=True)
        if arguments == ["--check"]:
            return 0
        if selected is original:
            return subprocess.run(arguments, check=False).returncode
        executable = shutil.which(arguments[0])
        if executable is None or not executable.lower().endswith(".exe"):
            raise ValueError("the test command must resolve to a native .exe")
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline([executable, *arguments[1:]]))
        startup = StartupInfo()
        startup.size = ctypes.sizeof(startup)
        startup.flags = 0x100  # STARTF_USESTDHANDLES, preserve CI log streaming.
        startup.stdin = kernel.GetStdHandle(dword(-10).value)
        startup.stdout = kernel.GetStdHandle(dword(-11).value)
        startup.stderr = kernel.GetStdHandle(dword(-12).value)
        checked(security.CreateProcessAsUserW(
            selected, executable, command, None, None, True, 0, None,
            os.getcwd(), ctypes.byref(startup), ctypes.byref(process),
        ))
        if kernel.WaitForSingleObject(process.process, 0xFFFFFFFF) != 0:
            raise ctypes.WinError(ctypes.get_last_error())
        code = dword()
        checked(kernel.GetExitCodeProcess(process.process, ctypes.byref(code)))
        return code.value
    finally:
        for owned in (process.thread, process.process, filtered, original):
            if owned:
                kernel.CloseHandle(owned)
        if medium_sid:
            kernel.LocalFree(medium_sid)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
