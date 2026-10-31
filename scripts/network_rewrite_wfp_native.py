"""Narrow native cooperation for the isolated hosted Windows WFP experiment.

Uses the Windows account/process/WFP APIs, not a packet-filter model. No global
flush, routing change, machine permission change or reusable credential export.
"""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import uuid


class GUID(c.Structure):
    _fields_ = [("data1", w.DWORD), ("data2", w.WORD), ("data3", w.WORD), ("data4", c.c_ubyte * 8)]

    @classmethod
    def parse(cls, value):
        return cls.from_buffer_copy(uuid.UUID(str(value)).bytes_le)

    def text(self):
        return str(uuid.UUID(bytes_le=bytes(self)))


class Display(c.Structure):
    _fields_ = [("name", w.LPWSTR), ("description", w.LPWSTR)]


class Blob(c.Structure):
    _fields_ = [("size", w.DWORD), ("data", c.c_void_p)]


class Data(c.Union):
    _fields_ = [("integer", c.c_uint64), ("pointer", c.c_void_p)]


class Value(c.Structure):
    _fields_ = [("kind", c.c_int32), ("data", Data)]


class Action(c.Structure):
    _fields_ = [("kind", w.DWORD), ("key", GUID)]


class Condition(c.Structure):
    _fields_ = [("field", GUID), ("match", c.c_int32), ("value", Value)]


class Context(c.Union):
    _fields_ = [("raw", c.c_uint64), ("key", GUID)]


class Filter(c.Structure):
    _fields_ = [("key", GUID), ("display", Display), ("flags", w.DWORD),
                ("provider", c.POINTER(GUID)), ("data", Blob), ("layer", GUID),
                ("sublayer", GUID), ("weight", Value), ("count", w.DWORD),
                ("conditions", c.c_void_p), ("action", Action), ("context", Context),
                ("reserved", c.POINTER(GUID)), ("filter_id", c.c_uint64), ("effective", Value)]


def checked(value):
    if not value:
        raise c.WinError(c.get_last_error())


class Native:
    def __init__(self):
        self.kernel = c.WinDLL("kernel32", use_last_error=True)
        self.security = c.WinDLL("advapi32", use_last_error=True)
        self.net = c.WinDLL("netapi32", use_last_error=True)
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.kernel.CloseHandle.restype = w.BOOL
        self.kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        self.kernel.WaitForSingleObject.restype = w.DWORD
        self.kernel.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
        self.kernel.TerminateProcess.restype = w.BOOL
        self.kernel.GetExitCodeProcess.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
        self.kernel.GetExitCodeProcess.restype = w.BOOL
        self.kernel.LocalFree.argtypes = [c.c_void_p]
        self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p]
        self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
        self.kernel.CreateDirectoryW.argtypes = [w.LPCWSTR, c.c_void_p]
        self.kernel.CreateDirectoryW.restype = w.BOOL

    def directory(self, path: Path, sddl: str):
        class Attributes(c.Structure):
            _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]
        descriptor = c.c_void_p()
        checked(self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, c.byref(descriptor), None))
        try:
            attributes = Attributes(c.sizeof(Attributes), descriptor, False)
            checked(self.kernel.CreateDirectoryW(str(path), c.byref(attributes)))
        finally:
            self.kernel.LocalFree(descriptor)


class Account:
    def __init__(self, native: Native):
        self.native, self.name, self.password = native, "nlwfp" + secrets.token_hex(6), "N!a9" + secrets.token_urlsafe(25)
        self.created = False
        class User(c.Structure):
            _fields_ = [("name", w.LPWSTR), ("password", w.LPWSTR), ("password_age", w.DWORD),
                        ("privilege", w.DWORD), ("home", w.LPWSTR), ("comment", w.LPWSTR),
                        ("flags", w.DWORD), ("script", w.LPWSTR)]
        native.net.NetUserAdd.argtypes = [w.LPCWSTR, w.DWORD, c.c_void_p, c.POINTER(w.DWORD)]
        native.net.NetUserAdd.restype = w.DWORD
        native.net.NetUserDel.argtypes = [w.LPCWSTR, w.LPCWSTR]
        native.net.NetUserDel.restype = w.DWORD
        value = User(self.name, self.password, 0, 1, None, "Disposable hosted WFP different-SID probe", 0x201, None)
        field = w.DWORD()
        status = native.net.NetUserAdd(None, 1, c.byref(value), c.byref(field))
        if status:
            raise RuntimeError(f"NetUserAdd capability unavailable ({status}, field {field.value})")
        self.created = True
        native.security.LogonUserW.argtypes = [w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, w.DWORD, w.DWORD, c.POINTER(w.HANDLE)]
        native.security.LogonUserW.restype = w.BOOL
        token = w.HANDLE()
        try:
            checked(native.security.LogonUserW(self.name, ".", self.password, 2, 0, c.byref(token)))
            native.security.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
            native.security.GetTokenInformation.restype = w.BOOL
            length = w.DWORD()
            native.security.GetTokenInformation(token, 1, None, 0, c.byref(length))
            if c.get_last_error() != 122 or not 0 < length.value <= 65536:
                raise RuntimeError("LogonUser token query unavailable")
            data = c.create_string_buffer(length.value)
            checked(native.security.GetTokenInformation(token, 1, data, length, c.byref(length)))
            sid = c.cast(data, c.POINTER(c.c_void_p)).contents
            text = c.c_void_p()
            native.security.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(c.c_void_p)]
            native.security.ConvertSidToStringSidW.restype = w.BOOL
            checked(native.security.ConvertSidToStringSidW(sid, c.byref(text)))
            try:
                self.sid = c.wstring_at(text)
            finally:
                native.kernel.LocalFree(text)
        except BaseException:
            self.close()
            raise
        finally:
            if token:
                native.kernel.CloseHandle(token)

    def run(self, executable: Path, arguments: list[str], env: dict, cwd: Path, timeout: float = 15):
        class Startup(c.Structure):
            _fields_ = [("size", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR),
                        ("title", w.LPWSTR), ("x", w.DWORD), ("y", w.DWORD), ("width", w.DWORD),
                        ("height", w.DWORD), ("chars_x", w.DWORD), ("chars_y", w.DWORD),
                        ("fill", w.DWORD), ("flags", w.DWORD), ("show", w.WORD),
                        ("reserved_size", w.WORD), ("reserved_bytes", c.c_void_p),
                        ("stdin", w.HANDLE), ("stdout", w.HANDLE), ("stderr", w.HANDLE)]
        class Process(c.Structure):
            _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]
        api = self.native.security.CreateProcessWithLogonW
        api.argtypes = [w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, w.DWORD, w.LPCWSTR, w.LPWSTR,
                        w.DWORD, c.c_void_p, w.LPCWSTR, c.POINTER(Startup), c.POINTER(Process)]
        api.restype = w.BOOL
        command = c.create_unicode_buffer(subprocess.list2cmdline([str(executable), *arguments]))
        environment = c.create_unicode_buffer("\0".join(f"{key}={value}" for key, value in sorted(env.items(), key=lambda item: item[0].upper())) + "\0\0")
        startup, process = Startup(), Process()
        startup.size = c.sizeof(Startup)
        checked(api(self.name, ".", self.password, 0, str(executable), command, 0x400 | 0x08000000,
                    environment, str(cwd), c.byref(startup), c.byref(process)))
        try:
            waited = self.native.kernel.WaitForSingleObject(process.process, int(timeout * 1000))
            if waited != 0:
                checked(self.native.kernel.TerminateProcess(process.process, 124))
                self.native.kernel.WaitForSingleObject(process.process, 5000)
                raise TimeoutError("exact different-SID probe exceeded its fixed budget")
            code = w.DWORD()
            checked(self.native.kernel.GetExitCodeProcess(process.process, c.byref(code)))
            if code.value:
                raise RuntimeError(f"different-SID probe failed ({code.value})")
            return process.pid
        finally:
            self.native.kernel.CloseHandle(process.thread)
            self.native.kernel.CloseHandle(process.process)

    def close(self):
        if self.created:
            status = self.native.net.NetUserDel(None, self.name)
            if status:
                raise RuntimeError(f"owned disposable account deletion failed ({status})")
            self.created = False


class Wfp:
    """Inject/remove one explicitly owned foreign filter, with exact readback."""
    def __init__(self):
        self.native, self.api, self.handle = Native(), c.WinDLL("fwpuclnt", use_last_error=True), w.HANDLE()
        self.api.FwpmEngineOpen0.argtypes = [w.LPCWSTR, w.DWORD, c.c_void_p, c.c_void_p, c.POINTER(w.HANDLE)]
        self.api.FwpmEngineOpen0.restype = w.DWORD
        self.api.FwpmEngineClose0.argtypes = [w.HANDLE]
        self.api.FwpmEngineClose0.restype = w.DWORD
        self.api.FwpmFreeMemory0.argtypes = [c.POINTER(c.c_void_p)]
        self.api.FwpmFreeMemory0.restype = None
        self.api.FwpmFilterAdd0.argtypes = [w.HANDLE, c.POINTER(Filter), c.c_void_p, c.POINTER(c.c_uint64)]
        self.api.FwpmFilterAdd0.restype = w.DWORD
        self.api.FwpmFilterGetByKey0.argtypes = [w.HANDLE, c.POINTER(GUID), c.POINTER(c.POINTER(Filter))]
        self.api.FwpmFilterGetByKey0.restype = w.DWORD
        self.api.FwpmFilterDeleteById0.argtypes = [w.HANDLE, c.c_uint64]
        self.api.FwpmFilterDeleteById0.restype = w.DWORD
        for name in ("FwpmTransactionBegin0", "FwpmTransactionCommit0", "FwpmTransactionAbort0"):
            getattr(self.api, name).argtypes = [w.HANDLE, w.DWORD] if name.endswith("Begin0") else [w.HANDLE]
            getattr(self.api, name).restype = w.DWORD
        self.code(self.api.FwpmEngineOpen0(None, 10, None, None, c.byref(self.handle)))

    @staticmethod
    def code(status):
        if status:
            raise RuntimeError(f"native WFP experiment operation failed ({status:#x})")

    def security(self, key):
        descriptor, text = c.c_void_p(), c.c_void_p()
        api = self.api.FwpmFilterGetSecurityInfoByKey0
        api.argtypes = [w.HANDLE, c.POINTER(GUID), w.DWORD, c.c_void_p, c.c_void_p, c.c_void_p, c.c_void_p, c.POINTER(c.c_void_p)]
        api.restype = w.DWORD
        self.code(api(self.handle, c.byref(key), 7, None, None, None, None, c.byref(descriptor)))
        security = self.native.security
        security.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p]
        security.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = w.BOOL
        security.GetSecurityDescriptorControl.argtypes = [c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD)]
        security.GetSecurityDescriptorControl.restype = w.BOOL
        try:
            control, revision = w.WORD(), w.DWORD()
            checked(security.GetSecurityDescriptorControl(descriptor, c.byref(control), c.byref(revision)))
            checked(security.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 7, c.byref(text), None))
            return {"sddl": c.wstring_at(text), "control": control.value & ~0x8000, "revision": revision.value}
        finally:
            if text:
                self.native.kernel.LocalFree(text)
            self.api.FwpmFreeMemory0(c.byref(descriptor))

    def read(self, key):
        raw = c.POINTER(Filter)()
        self.code(self.api.FwpmFilterGetByKey0(self.handle, c.byref(key), c.byref(raw)))
        try:
            value = raw.contents
            if value.count != 3 or not value.conditions or value.weight.kind != 4 or value.effective.kind != 4:
                raise ValueError("owned diagnostic filter no longer has its original shape")
            if not value.weight.data.pointer or not value.effective.data.pointer or value.data.size > 65536:
                raise ValueError("invalid diagnostic filter observation")
            conditions = []
            for condition in c.cast(value.conditions, c.POINTER(Condition * value.count)).contents:
                if condition.value.kind not in (1, 2, 3):
                    raise ValueError("diagnostic condition changed; preserve it")
                mask = {1: 0xff, 2: 0xffff, 3: 0xffffffff}[condition.value.kind]
                conditions.append({"field": condition.field.text(), "match": condition.match,
                                   "type": condition.value.kind, "value": condition.value.data.integer & mask})
            return {"key": value.key.text(), "name": value.display.name, "description": value.display.description,
                    "flags": value.flags, "provider": value.provider.contents.text() if value.provider else None,
                    "data": c.string_at(value.data.data, value.data.size).hex() if value.data.size else "",
                    "layer": value.layer.text(), "sublayer": value.sublayer.text(),
                    "weight": c.cast(value.weight.data.pointer, c.POINTER(c.c_uint64)).contents.value,
                    "conditions": conditions, "action": value.action.kind, "action_key": value.action.key.text(),
                    "context": bytes(value.context).hex(), "reserved": value.reserved.contents.text() if value.reserved else None,
                    "filter_id": value.filter_id,
                    "effective_weight": c.cast(value.effective.data.pointer, c.POINTER(c.c_uint64)).contents.value,
                    "security": self.security(key)}
        finally:
            allocation = c.cast(raw, c.c_void_p)
            self.api.FwpmFreeMemory0(c.byref(allocation))

    def inject(self, plan):
        key = GUID.parse(uuid.uuid4())
        provider = GUID.parse(plan["owner_id"])
        layer = GUID.parse("c38d57d1-05a7-4c33-904f-7fbceee60e82")
        sublayer = GUID.parse(uuid.UUID(int=uuid.UUID(plan["owner_id"]).int ^ 1))
        name = "NestLink:hosted-WFP-foreign:" + key.text()
        weight = c.c_uint64(999)
        value = Filter()
        value.key, value.display, value.flags = key, Display(name, "explicitly owned hostile-state test"), 1
        value.provider, value.layer, value.sublayer = c.pointer(provider), layer, sublayer
        value.weight = Value(4, Data(pointer=c.cast(c.pointer(weight), c.c_void_p)))
        endpoint = plan["endpoint"]
        address, port = endpoint.rsplit(":", 1)
        if address != "127.0.0.1":
            raise ValueError("diagnostic filter supports only the exact IPv4 lab endpoint")
        conditions = (Condition * 3)(
            Condition(GUID.parse("b235ae9a-1d64-49b8-a44c-5ff3d9095045"), 0, Value(3, Data(integer=0x7f000001))),
            Condition(GUID.parse("c35a604d-d22b-4e1a-91b4-68f674ee674b"), 0, Value(2, Data(integer=int(port)))),
            Condition(GUID.parse("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"), 0, Value(1, Data(integer=17 if plan["transport"] == "udp" else 6))),
        )
        value.count, value.conditions = 3, c.cast(conditions, c.c_void_p)
        value.action = Action(4097, GUID())
        identifier = c.c_uint64()
        self.code(self.api.FwpmFilterAdd0(self.handle, c.byref(value), None, c.byref(identifier)))
        observed = self.read(key)
        if observed["filter_id"] != identifier.value or observed["provider"] != provider.text() or observed["name"] != name:
            raise ValueError("foreign diagnostic identity readback mismatch")
        return observed

    def remove_exact(self, observed):
        key = GUID.parse(observed["key"])
        self.code(self.api.FwpmTransactionBegin0(self.handle, 0))
        try:
            if self.read(key) != observed:
                raise ValueError("diagnostic filter changed; preserve foreign object")
            self.code(self.api.FwpmFilterDeleteById0(self.handle, observed["filter_id"]))
            self.code(self.api.FwpmTransactionCommit0(self.handle))
        except BaseException:
            self.api.FwpmTransactionAbort0(self.handle)
            raise

    def close(self):
        if self.handle:
            self.code(self.api.FwpmEngineClose0(self.handle))
            self.handle = w.HANDLE()
