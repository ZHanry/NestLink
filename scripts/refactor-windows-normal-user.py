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
    security.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(pointer)]
    security.ConvertSidToStringSidW.restype = boolean
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, dword, ctypes.POINTER(pointer), ctypes.POINTER(dword),
    ]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = boolean
    security.GetSecurityDescriptorDacl.argtypes = [
        pointer, ctypes.POINTER(boolean), ctypes.POINTER(pointer), ctypes.POINTER(boolean),
    ]
    security.GetSecurityDescriptorDacl.restype = boolean
    security.SetSecurityInfo.argtypes = [handle, dword, dword, pointer, pointer, pointer, pointer]
    security.SetSecurityInfo.restype = dword
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
    user_text = pointer()
    user_descriptor = pointer()
    process = ProcessInfo()
    try:
        # An already filtered child only needs QUERY. Asking it for adjustment
        # rights on its primary token can correctly be denied by Windows.
        checked(security.OpenProcessToken(kernel.GetCurrentProcess(), 0x8, ctypes.byref(original)))
        selected = original
        if force_filter or not normal(original):
            kernel.CloseHandle(original)
            original = handle()
            # QUERY | DUPLICATE | ASSIGN_PRIMARY | ADJUST_DEFAULT | WRITE_DAC,
            # only in the parent. The original token is never modified.
            checked(security.OpenProcessToken(kernel.GetCurrentProcess(), 0x4008B, ctypes.byref(original)))
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
            # An elevated runner can have an Administrators-only default DACL.
            # Its filtered child must be able to open its own process/token and
            # create grandchildren (rustc, link.exe, and actual test daemons).
            checked(security.ConvertSidToStringSidW(user.sid, ctypes.byref(user_text)))
            user_sid_text = ctypes.wstring_at(user_text)
            checked(security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                f"D:P(A;;GA;;;{user_sid_text})(A;;GA;;;SY)", 1,
                ctypes.byref(user_descriptor), None,
            ))
            present, defaulted, dacl = boolean(), boolean(), pointer()
            checked(security.GetSecurityDescriptorDacl(
                user_descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted),
            ))
            if not present.value or not dacl.value:
                raise RuntimeError("ordinary-user token DACL is missing")
            checked(security.SetTokenInformation(filtered, 6, ctypes.byref(dacl), ctypes.sizeof(dacl)))
            error = security.SetSecurityInfo(filtered, 6, 4, None, None, dacl, None)
            if error:
                raise ctypes.WinError(error)
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
        if user_text:
            kernel.LocalFree(user_text)
        if user_descriptor:
            kernel.LocalFree(user_descriptor)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
