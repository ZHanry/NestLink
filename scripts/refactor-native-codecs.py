"""Supply pinned native VP8/Opus libraries and verifiable installation receipts.

Requires Python 3.10+. Build targets are explicit: Windows x64, native Linux
x64/ARM64, and Android ARM64/x86_64 using the pinned Linux-hosted NDK. Every build uses a new work
directory and freshly verified extraction; existing source/build trees are never
reused or removed. `verify` and cached `--offline` builds do not access the
network. A receipt attests this build, not platform/product acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "docs/refactor/native-codecs.lock.json"
RECEIPT = "nestlink-codecs.json"
SUPPORTED = (
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "aarch64-linux-android",
    "x86_64-linux-android",
)
ANDROID_TARGETS = frozenset(("aarch64-linux-android", "x86_64-linux-android"))
ANDROID_NDK = {
    "revision": "27.2.12479018",
    "host_tag": "linux-x86_64",
    "api_level": 30,
    "page_size_bytes": 16384,
    "final_shared_object_linker_flag": "-Wl,-z,max-page-size=16384",
    "repository_url": "https://dl.google.com/android/repository/repository2-3.xml",
    "linux_archive_url": "https://dl.google.com/android/repository/android-ndk-r27c-linux.zip",
    "linux_archive_bytes": 663987688,
    "linux_archive_sha1": "090e8083a715fdb1a3e402d0763c388abb03fb4e",
    "linux_archive_sha256": "59c2f6dc96743b5daf5d1626684640b20a6bd2b1d85b13156b90333741bad5cc",
}
ANDROID_MACHINES = {"aarch64-linux-android": (2, 183), "x86_64-linux-android": (2, 62)}
FEATURES = {"vp8": True, "vp8_encoder": True, "vp8_decoder": True, "vp9": False, "opus_float": True, "opus_fixed_point": False, "opus_dred": False, "opus_deep_plc": False, "opus_osce": False, "opus_custom_modes": False, "opus_nonthreadsafe_pseudostack": False}
HASH = re.compile(r"[0-9a-f]{64}\Z")
POISON_FLAGS = ("CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "ASFLAGS", "CC", "CXX", "LD", "AR", "AS", "CROSS", "CL", "_CL_", "CMAKE_ARGS", "CMAKE_TOOLCHAIN_FILE", "CMAKE_PROJECT_INCLUDE", "CMAKE_PROJECT_INCLUDE_BEFORE")


class SupplyError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise SupplyError(message)


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def is_link(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def safe_relative(value):
    require(isinstance(value, str) and value and "\\" not in value, "Expected a nonempty POSIX relative path")
    require(not value.startswith("/") and "//" not in value, "Absolute or noncanonical path rejected")
    parts = value.split("/")
    for part in parts:
        require(part not in {"", ".", ".."} and not part.endswith((" ", ".")), "Unsafe path component")
        require(not any(ord(character) < 32 or character in ':<>"|?*' for character in part), "Nonportable path component")
        require(not re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part), "Reserved Windows path component")
    require(PurePosixPath(value).as_posix() == value, "Noncanonical relative path")
    return value


def load_lock(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    require(data.get("schema_version") == 1 and data.get("kind") == "nestlink-native-codecs-lock", "Unsupported native codec lock")
    require({item["name"] for item in data["sources"]} == {"libvpx", "opus"} and len(data["sources"]) == 2, "Lock must identify exactly libvpx and Opus")
    for item in data["sources"]:
        require(re.fullmatch(r"[0-9a-f]{40}", item["commit"]) and HASH.fullmatch(item["archive_sha256"]), "Malformed source digest")
        require(type(item["archive_bytes"]) is int and 0 < item["archive_bytes"] <= 32 * 1024 * 1024, "Invalid source archive size")
        require(item["archive_prefix"] == f"{item['name']}-{item['commit']}", "Unexpected source archive prefix")
        repository = "webmproject/libvpx" if item["name"] == "libvpx" else "xiph/opus"
        require(item["url"] == f"https://codeload.github.com/{repository}/tar.gz/{item['commit']}", "Source URL must identify the pinned public repository and commit")
        require(0 < item["max_unpacked_bytes"] <= 512 * 1024 * 1024 and 0 < item["max_members"] <= 100000, "Unbounded extraction budget")
    require(set(data["targets"]) == set(SUPPORTED), "Supplier target matrix differs from its reviewed implementations")
    require(data["profile"] == "release" and data["linkage"] == "static", "Unsupported build profile")
    require(all(type(value) is bool for value in data["features"].values()), "Feature settings must be booleans")
    require(data["features"] == FEATURES, "Lock requests features not implemented by this supplier")
    require(data.get("android_ndk") == ANDROID_NDK, "Android NDK revision or 16 KiB page-size policy differs from this supplier")
    for target in SUPPORTED:
        windows = target.endswith("windows-msvc")
        if target in ANDROID_TARGETS:
            arm64 = target == "aarch64-linux-android"
            expected = {
                "os": "android",
                "arch": "aarch64" if arm64 else "x86_64",
                "android_abi": "arm64-v8a" if arm64 else "x86_64",
                "crt": "bionic",
                "vpx_target": "arm64-android-gcc" if arm64 else "x86_64-android-gcc",
                "libraries": {"vpx": "lib/libvpx.a", "opus": "lib/libopus.a"},
            }
        else:
            arm64 = target == "aarch64-unknown-linux-gnu"
            expected = {"os": "windows" if windows else "linux", "arch": "aarch64" if arm64 else "x86_64", "crt": "dynamic" if windows else "system", "vpx_target": "x86_64-win64-vs17" if windows else "arm64-linux-gcc" if arm64 else "x86_64-linux-gcc", "libraries": {"vpx": "lib/vpx.lib" if windows else "lib/libvpx.a", "opus": "lib/opus.lib" if windows else "lib/libopus.a"}}
        require(data["targets"][target] == expected, "Lock target configuration is not implemented by this supplier")
    require(isinstance(data.get("cross_compilation_policy"), str), "Missing cross-target policy")
    return data


def verify_archive(path, spec):
    require(path.is_file() and not is_link(path), f"Archive is not a regular file: {path}")
    require(path.stat().st_size == spec["archive_bytes"], f"Archive size mismatch: {spec['name']}")
    require(file_sha256(path) == spec["archive_sha256"], f"Archive SHA256 mismatch: {spec['name']}")


def get_archive(cache, spec, offline=False):
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / f"{spec['name']}-{spec['commit']}.tar.gz"
    if path.exists():
        verify_archive(path, spec)
        return path
    require(not offline, f"Offline archive missing: {path}")
    request = urllib.request.Request(spec["url"], headers={"User-Agent": "NestLink-native-codec-supplier/1", "Accept-Encoding": "identity"})
    temporary = None
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            require(response.geturl() == spec["url"], "Unexpected source download redirect")
            length = response.headers.get("Content-Length")
            require(length is None or int(length) == spec["archive_bytes"], "HTTP source size differs from lock")
            with tempfile.NamedTemporaryFile(dir=cache, prefix=spec["name"] + "-", suffix=".partial", delete=False) as output:
                temporary = Path(output.name)
                total = 0
                while chunk := response.read(256 * 1024):
                    total += len(chunk)
                    require(total <= spec["archive_bytes"], "Download exceeds pinned source size")
                    output.write(chunk)
        verify_archive(temporary, spec)
        if path.exists():
            verify_archive(path, spec)
        else:
            temporary.replace(path)
            temporary = None
        return path
    finally:
        # Only our single, named temporary file is removed; never source/build trees.
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def tree_manifest(source):
    require(source.is_dir() and not is_link(source), "Source root must be a real directory")
    records = []
    for path in regular_tree_entries(source):
        relative = safe_relative(path.relative_to(source).as_posix())
        if path.is_file():
            records.append({"path": relative, "bytes": path.stat().st_size, "sha256": file_sha256(path)})
        else:
            require(path.is_dir(), "Special file in source tree")
    return records


def regular_tree_entries(root):
    pending, entries = [root], []
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            require(not is_link(path), "Link/reparse point in file tree")
            require(path.is_file() or path.is_dir(), "Special file in file tree")
            entries.append(path)
            require(len(entries) <= 100000, "File tree entry budget exceeded")
            if path.is_dir():
                pending.append(path)
    return sorted(entries)


def tree_digest(records):
    return hashlib.sha256(json.dumps(records, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def extract_fresh(archive, spec, source):
    verify_archive(archive, spec)
    require(not source.exists(), f"Refusing to reuse source tree: {source}")
    with tarfile.open(archive, "r:gz") as tar:
        members, total = [], 0
        for item in tar:
            require(len(members) < spec["max_members"], "Too many archive members")
            total += item.size
            require(total <= spec["max_unpacked_bytes"], "Unpacked source exceeds budget")
            members.append(item)
        validated, names = [], {}
        for item in members:
            require(item.isdir() or item.isreg(), "Archive links and special files are forbidden")
            name = item.name.rstrip("/") if item.isdir() else item.name
            safe_relative(name)
            require(name == spec["archive_prefix"] or name.startswith(spec["archive_prefix"] + "/"), "Archive member is outside its pinned prefix")
            require(name.casefold() not in names, "Duplicate or case-colliding archive member")
            names[name.casefold()] = item.isdir()
            relative = name[len(spec["archive_prefix"]):].lstrip("/")
            if not relative:
                require(item.isdir(), "Archive root must be a directory")
            else:
                validated.append((item, relative))
        spellings = {}
        for item, relative in validated:
            parts = (spec["archive_prefix"] + "/" + relative).split("/")
            require(all(names.get("/".join(parts[:index]).casefold(), True) for index in range(1, len(parts))), "Archive file used as parent directory")
            for index in range(1, len(parts) + 1):
                spelling = "/".join(parts[:index])
                require(spellings.get(spelling.casefold(), spelling) == spelling, "Case-colliding implicit directory")
                spellings[spelling.casefold()] = spelling
        source.mkdir(parents=True)
        for item, relative in validated:
            destination = source / relative
            if item.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(item) as content, destination.open("xb") as output:
                shutil.copyfileobj(content, output)
            require(destination.stat().st_size == item.size, "Truncated archive member")
            if os.name != "nt":
                destination.chmod(0o755 if item.mode & 0o111 else 0o644)
    # Hash actual fresh bytes, rather than trusting an earlier extraction manifest.
    return tree_manifest(source)


def find_tool(name, env, explicit=None):
    location = str(explicit) if explicit else shutil.which(name, path=env.get("PATH"))
    require(location is not None, f"Required native build tool not found: {name}")
    path = Path(location).resolve()
    require(path.is_file(), f"Required tool is not a file: {name}")
    return path


def capture(command, env, accepted=(0,)):
    result = subprocess.run(list(map(str, command)), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    require(result.returncode in accepted, f"Tool preflight failed: {Path(command[0]).name} (exit {result.returncode})")
    return result.stdout.decode("utf-8", "replace").strip()


def resolve_ndk_path(value):
    candidate = Path(value)
    revision = ANDROID_NDK["revision"]
    if candidate.name.lower() == "ndk":
        return candidate / revision
    if (candidate / "source.properties").is_file():
        return candidate
    for relative in (Path("ndk") / revision, Path(revision)):
        versioned = candidate / relative
        if (versioned / "source.properties").is_file():
            return versioned
    return candidate


def msvc_environment(env, work, explicit_vswhere):
    program_files = env.get("ProgramFiles(x86)") or env.get("PROGRAMFILES(X86)")
    guess = Path(program_files) / "Microsoft Visual Studio/Installer/vswhere.exe" if program_files else None
    vswhere = find_tool("vswhere.exe", env, explicit_vswhere or guess)
    installation = Path(capture([vswhere, "-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], env))
    setup = installation / "Common7/Tools/VsDevCmd.bat"
    require(setup.is_file() and not any(character in str(setup) for character in '"%!\r\n'), "Invalid Visual Studio environment script path")
    wrapper = work / "read-msvc-env.cmd"
    wrapper.write_text(f'@echo off\ncall "{setup}" -arch=x64 -host_arch=x64 >nul\nif errorlevel 1 exit /b 1\nset\n', encoding="utf-8")
    environment = {key.upper(): value for key, value in env.items()}
    # Environment contents are parsed in memory and never written to logs/receipts.
    for line in capture(["cmd.exe", "/d", "/c", wrapper], env).splitlines():
        if "=" in line and not line.startswith("="):
            key, value = line.split("=", 1)
            environment[key.upper()] = value
    require(environment.get("VSCMD_ARG_TGT_ARCH") == "x64", "Visual Studio environment is not x64")
    return environment, installation, vswhere


def verify_build_host(target, machine, system, os_name):
    require(target in SUPPORTED, "Supplier target is not implemented")
    arm64 = target == "aarch64-unknown-linux-gnu"
    expected = {"aarch64", "arm64"} if arm64 else {"amd64", "x86_64"}
    require(machine.lower() in expected, "Native Linux ARM64 requires an ARM64 host; other targets require x86_64")
    windows = target.endswith("windows-msvc")
    require((windows and os_name == "nt") or (not windows and os_name == "posix" and system == "Linux"), "Native targets must match the host OS; Android cross-builds require Linux x86_64")


def verify_native_compiler(target, compiler_target):
    require(target in {"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"}, "Expected a native Linux compiler target")
    architecture = "aarch64" if target == "aarch64-unknown-linux-gnu" else "x86_64"
    require(re.fullmatch(architecture + r"-(?:[A-Za-z0-9_]+-)?linux-gnu", compiler_target), "Compiler target must match the locked native GNU/Linux architecture")


def prepare_tools(args, work, target):
    env = dict(os.environ)
    poisoned = [key for key in POISON_FLAGS if env.get(key)]
    require(not poisoned, "Unset build flag overrides before supplying codecs: " + ", ".join(poisoned))
    verify_build_host(target, platform.machine(), platform.system(), os.name)
    windows = target.endswith("windows-msvc")
    android = target in ANDROID_TARGETS
    tools = {}
    android_info = None
    if windows:
        env, installation, tools["vswhere"] = msvc_environment(env, work, args.vswhere)
        if args.msys_bin:
            require(args.msys_bin.is_dir(), "--msys-bin must be an existing tool directory")
            env["PATH"] = str(args.msys_bin.resolve()) + os.pathsep + env["PATH"]
        tools["msbuild"] = find_tool("MSBuild.exe", env, installation / "MSBuild/Current/Bin/MSBuild.exe")
        tools["cc"] = find_tool("cl.exe", env)
        tools["lib"] = find_tool("lib.exe", env)
    elif android:
        ndk = None
        for value in (args.ndk, env.get("ANDROID_NDK_HOME"), env.get("ANDROID_NDK_ROOT"), env.get("ANDROID_HOME"), env.get("ANDROID_SDK_ROOT")):
            if not value:
                continue
            ndk = resolve_ndk_path(value)
            break
        require(ndk is not None, "Android builds require --ndk or an Android SDK/NDK environment variable")
        ndk = ndk.resolve()
        require(re.fullmatch(r"[A-Za-z0-9_./:\\-]+", str(ndk)), "Android NDK path must use ASCII without spaces or shell metacharacters")
        require(ndk.is_dir() and not is_link(ndk), "Android NDK must be an installed regular directory")
        source_properties = ndk / "source.properties"
        require(source_properties.is_file() and not is_link(source_properties), "Android NDK source.properties is missing")
        revision_text = source_properties.read_text(encoding="utf-8")
        revision = re.search(r"(?m)^Pkg\.Revision\s*=\s*([^\r\n]+)", revision_text)
        require(revision and revision.group(1).strip() == ANDROID_NDK["revision"], "Android NDK revision differs from the pinned lock")
        ndk_bin = ndk / "toolchains/llvm/prebuilt" / ANDROID_NDK["host_tag"] / "bin"
        require(ndk_bin.is_dir() and not is_link(ndk_bin), "Pinned NDK Linux host toolchain is missing")
        triple = target
        api = ANDROID_NDK["api_level"]
        target_compiler = ndk_bin / f"{triple}{api}-clang"
        target_cxx = ndk_bin / f"{triple}{api}-clang++"
        tools.update({
            "cc": find_tool(target_compiler.name, env, target_compiler),
            "cxx": find_tool(target_cxx.name, env, target_cxx),
            "ar": find_tool("llvm-ar", env, ndk_bin / "llvm-ar"),
            "ranlib": find_tool("llvm-ranlib", env, ndk_bin / "llvm-ranlib"),
            "nm": find_tool("llvm-nm", env, ndk_bin / "llvm-nm"),
            "strip": find_tool("llvm-strip", env, ndk_bin / "llvm-strip"),
            "objcopy": find_tool("llvm-objcopy", env, ndk_bin / "llvm-objcopy"),
        })
        env["PATH"] = str(ndk_bin) + os.pathsep + env["PATH"]
        env["ANDROID_NDK_HOME"] = str(ndk)
        env["ANDROID_NDK_ROOT"] = str(ndk)
        env["CC"] = str(tools["cc"])
        env["CXX"] = str(tools["cxx"])
        env["AR"] = str(tools["ar"])
        env["RANLIB"] = str(tools["ranlib"])
        env["NM"] = str(tools["nm"])
        env["STRIP"] = str(tools["strip"])
        env["LD"] = str(tools["cc"])
        objcopy = tools["objcopy"]
        wrapper = work / "tools" / "ndk-llvm-objcopy-strip"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text(
            "#!/bin/sh\n"
            "if [ \"$#\" -eq 4 ] && [ \"$1\" = \"--strip-debug\" ] && [ \"$2\" = \"-o\" ]; then\n"
            f"  exec {objcopy} --strip-debug \"$4\" \"$3\"\n"
            "fi\n"
            f"exec {objcopy} \"$@\"\n",
            encoding="utf-8", newline="\n",
        )
        wrapper.chmod(0o755)
        tools["strip_compat"] = wrapper
        expected_machine = "aarch64-unknown-linux-android30" if target == "aarch64-linux-android" else "x86_64-unknown-linux-android30"
        require(capture([tools["cc"], "-dumpmachine"], env) == expected_machine, "NDK C compiler target differs from the locked Android ABI/API")
        android_info = {
            "abi": "arm64-v8a" if target == "aarch64-linux-android" else "x86_64",
            "target": target,
            "expected_elf_machine": ANDROID_MACHINES[target][1],
            "compiler_target": expected_machine,
            "ndk_path": str(ndk),
            "api_level": api,
            "ndk_revision": ANDROID_NDK["revision"],
            "ndk_host_tag": ANDROID_NDK["host_tag"],
            "source_properties_sha256": file_sha256(source_properties),
            "ndk_archive": {key: ANDROID_NDK[key] for key in ("linux_archive_url", "linux_archive_bytes", "linux_archive_sha1", "linux_archive_sha256")},
            "page_size_bytes": ANDROID_NDK["page_size_bytes"],
            "final_shared_object_linker_flag": ANDROID_NDK["final_shared_object_linker_flag"],
        }
    else:
        tools["cc"] = find_tool("gcc", env, args.cc)
        verify_native_compiler(target, capture([tools["cc"], "-dumpmachine"], env))
        tools["ar"] = find_tool("ar", env)
    if target.startswith("x86_64"):
        tools["nasm"] = find_tool("nasm", env, args.nasm)
        env["PATH"] = str(tools["nasm"].parent) + os.pathsep + env["PATH"]
    for name in ("cmake", "ninja", "bash", "make", "perl", "sed", "awk", "grep", "diff", "uname"):
        tools[name] = find_tool(name, env)
    system = capture([tools["uname"], "-s"], env)
    require(not windows or system.startswith(("MSYS_NT", "MINGW")), "Windows requires an MSYS/Git-for-Windows bash + make/perl toolchain, not WSL bash")
    # libvpx's configure expands CC as a shell command without quoting it.
    # The captured MSVC PATH fixes cl.exe to the compiler verified below;
    # NDK builds instead use the API-pinned Clang wrapper directly.
    if windows:
        # Let the VS target choose both compiler and linker together. Setting
        # only CC bypasses upstream's paired CC/LD defaults.
        env.pop("CC", None)
    elif not android:
        env["CC"] = str(tools["cc"])
    versions = []
    for name, path in tools.items():
        if name == "cc" and windows:
            # cl can return 2 for its expected missing-input diagnostic.
            version = capture([path], env, accepted=(0, 2))
            require("Microsoft" in version and "x64" in version, "Expected native x64 MSVC compiler banner")
        elif name == "lib":
            # Microsoft LIB returns 1100 after successfully displaying usage.
            version = capture([path, "/?"], env, accepted=(0, 1100))
            require("Microsoft" in version and "LIB" in version, "Expected Microsoft library manager banner")
        elif name == "msbuild":
            version = capture([path, "-version", "-nologo"], env)
        elif name == "vswhere":
            version = capture([path, "-?"], env)
        elif name == "nasm":
            version = capture([path, "-v"], env)
        elif name == "uname":
            version = capture([path, "-a"], env)
        elif name == "awk":
            version = capture([path, "-W", "version"], env)
        else:
            version = capture([path, "--version"], env)
        versions.append({"name": name, "path": str(path), "version": version[:2000], "sha256": file_sha256(path)})
    return env, tools, versions, android_info


def parse_cache(text):
    entries = {}
    for line in text.splitlines():
        match = re.match(r"([^/#][^:=]*):[^=]+=(.*)$", line)
        if match:
            entries[match[1]] = match[2]
    return entries


def check_features(vpx_header, opus_cache, opus_header, compile_commands, target, opus_version, android_info=None):
    windows = target.endswith("windows-msvc")
    android = target in ANDROID_TARGETS
    vpx = dict(re.findall(r"^#define\s+([A-Z0-9_]+)\s+([01])\s*$", vpx_header, re.M))
    arch_macro = "VPX_ARCH_AARCH64" if target.startswith("aarch64-") else "VPX_ARCH_X86_64"
    expected = {"CONFIG_VP8": "1", "CONFIG_VP8_ENCODER": "1", "CONFIG_VP8_DECODER": "1", "CONFIG_VP9": "0", "CONFIG_REALTIME_ONLY": "1", "CONFIG_SHARED": "0", "CONFIG_STATIC": "1", arch_macro: "1"}
    if windows:
        expected["CONFIG_STATIC_MSVCRT"] = "0"
    for name, value in expected.items():
        require(vpx.get(name) == value, f"libvpx configuration mismatch: {name}")
    cache = parse_cache(opus_cache)
    required_cache = {"CMAKE_BUILD_TYPE": "Release", "OPUS_PACKAGE_VERSION": opus_version, "OPUS_ENABLE_FLOAT_API": "ON", "OPUS_FIXED_POINT": "OFF", "OPUS_DRED": "OFF", "OPUS_DEEP_PLC": "OFF", "OPUS_OSCE": "OFF", "OPUS_CUSTOM_MODES": "OFF", "OPUS_NONTHREADSAFE_PSEUDOSTACK": "OFF", "BUILD_SHARED_LIBS": "OFF", "OPUS_BUILD_SHARED_LIBRARY": "OFF", "OPUS_BUILD_PROGRAMS": "OFF", "OPUS_BUILD_TESTING": "OFF", "BUILD_TESTING": "OFF"}
    if windows:
        required_cache.update({"OPUS_STATIC_RUNTIME": "OFF", "CMAKE_MSVC_RUNTIME_LIBRARY": "MultiThreadedDLL"})
    if android:
        require(android_info is not None, "Android feature validation requires pinned NDK details")
        required_cache.update({
            "ANDROID_ABI": android_info["abi"],
            "ANDROID_PLATFORM": f"android-{ANDROID_NDK['api_level']}",
            "ANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES": "ON",
        })
    for name, value in required_cache.items():
        require(cache.get(name) == value, f"Opus configuration mismatch: {name}")
    if android:
        toolchain = cache.get("CMAKE_TOOLCHAIN_FILE", "").replace("\\", "/")
        require(toolchain.endswith("/build/cmake/android.toolchain.cmake"), "Opus was not configured with the pinned NDK CMake toolchain")
    require(f'#define PACKAGE_VERSION "{opus_version}"' in opus_header, "Opus configured package version differs from lock")
    require(isinstance(compile_commands, list) and compile_commands, "Missing Opus compile commands")
    forbidden = {"ENABLE_DRED", "ENABLE_DEEP_PLC", "ENABLE_OSCE", "CUSTOM_MODES", "FIXED_POINT", "DISABLE_FLOAT_API", "NONTHREADSAFE_PSEUDOSTACK"}
    definitions = set()
    for entry in compile_commands:
        command = entry.get("command") or " ".join(entry.get("arguments", []))
        found = set(re.findall(r"(?:^|\s)[/-]D([A-Za-z_][A-Za-z0-9_]*)", command))
        definitions.update(found)
        require(not found & forbidden, "Disabled Opus feature appears in actual compilation flags")
        if windows:
            require(re.search(r"(?:^|\s)[/-]MD(?:\s|$)", command) and not re.search(r"(?:^|\s)[/-](?:MTd?|MDd)(?:\s|$)", command), "Opus compilation does not use release dynamic MSVC CRT")
        if android:
            arch = "aarch64" if target == "aarch64-linux-android" else "x86_64"
            expected_triple = rf"--target={arch}-(?:none-)?linux-android{ANDROID_NDK['api_level']}"
            expected_sysroot = (Path(android_info["ndk_path"]) / "toolchains/llvm/prebuilt" / ANDROID_NDK["host_tag"] / "sysroot").as_posix()
            require(re.search(expected_triple, command), "Opus compile command does not target the pinned Android ABI/API")
            require("--sysroot=" + expected_sysroot in command and "-DANDROID" in command, "Opus compile command is missing the pinned Android sysroot")
            require("-D__BIONIC_NO_PAGE_SIZE_MACRO" in command, "NDK flexible 16 KiB page-size support is missing from Opus compilation")
    require("OPUS_BUILD" in definitions, "Opus compile definitions were not identified")
    return {"libvpx_macros": expected, "opus_cache": required_cache, "opus_compile_definitions": sorted(definitions), "opus_compile_command_count": len(compile_commands)}


def inspect_elf_archive(path, expected_machine):
    """Verify every regular archive member is a 64-bit ELF object for one ABI."""
    data = path.read_bytes()
    require(data.startswith(b"!<arch>\n"), "Native library is not a regular static archive")
    offset, count, machines = 8, 0, set()
    while offset < len(data):
        require(offset + 60 <= len(data), "Truncated static archive member header")
        header = data[offset:offset + 60]
        require(header[58:60] == b"`\n", "Malformed static archive member header")
        try:
            size = int(header[48:58].decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise SupplyError("Malformed static archive member size") from error
        body_start = offset + 60
        body_end = body_start + size
        require(body_end <= len(data), "Truncated static archive member")
        name = header[:16].decode("ascii", "replace").strip()
        member = data[body_start:body_end]
        if name.startswith("#1/"):
            try:
                name_bytes = int(name[3:])
            except ValueError as error:
                raise SupplyError("Malformed BSD archive member name") from error
            require(name_bytes <= len(member), "Truncated BSD archive member name")
            member = member[name_bytes:]
        elif name in {"/", "/SYM64/", "//", "__.SYMDEF", "__.SYMDEF SORTED"}:
            member = b""
        if member:
            require(len(member) >= 20 and member[:4] == b"\x7fELF", "Static archive contains a non-ELF object")
            require(member[4] == 2 and member[5] in {1, 2}, "Static archive ELF object is not ELF64")
            machine = int.from_bytes(member[18:20], "little" if member[5] == 1 else "big")
            machines.add(machine)
            count += 1
        offset = body_end + (size & 1)
    require(offset == len(data), "Malformed static archive alignment")
    require(count > 0, "Static archive contains no ELF objects")
    require(machines == {expected_machine}, f"Static archive object architecture mismatch: {sorted(machines)}")
    return {"object_count": count, "elf_class": 64, "machine": expected_machine, "archive_sha256": file_sha256(path)}


def target_machine(target):
    if target in ANDROID_TARGETS:
        return ANDROID_MACHINES[target][1]
    if target == "aarch64-unknown-linux-gnu":
        return 183
    if target == "x86_64-unknown-linux-gnu":
        return 62
    return None


def install_manifest(prefix, libraries, target=None):
    require(prefix.is_dir() and not is_link(prefix), "Install prefix must be a real directory")
    records = []
    seen = set()
    for path in regular_tree_entries(prefix):
        if path.is_dir():
            continue
        require(path.is_file(), "Special file in installation")
        relative = safe_relative(path.relative_to(prefix).as_posix())
        if relative == RECEIPT:
            continue
        require(relative.casefold() not in seen, "Case collision in installation")
        seen.add(relative.casefold())
        kind = "library" if relative in libraries.values() else "header" if relative.startswith("include/") and relative.endswith(".h") else "metadata"
        if kind == "library":
            with path.open("rb") as stream:
                require(stream.read(8) == b"!<arch>\n", "Native library is not a regular static archive")
            machine = target_machine(target) if target else None
            if machine is not None:
                inspect_elf_archive(path, machine)
        else:
            require(path.suffix.lower() not in {".lib", ".a", ".dll", ".so", ".dylib"}, "Unexpected library outside locked installation paths")
        records.append({"path": relative, "kind": kind, "bytes": path.stat().st_size, "sha256": file_sha256(path)})
    return records


def verify_receipt(prefix, target, lock_path):
    lock = load_lock(lock_path)
    require(target in lock["targets"], "Unvalidated target requested")
    require(prefix.is_dir() and not is_link(prefix), "Install prefix must be a real directory")
    receipt_path = prefix / RECEIPT
    require(receipt_path.is_file() and not is_link(receipt_path), "Missing regular native codec receipt")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    expected = {"schema_version": 1, "kind": "nestlink-native-codecs", "target": target, "profile": "release", "linkage": "static", "crt": lock["targets"][target]["crt"], "lock_sha256": file_sha256(lock_path), "features": lock["features"], "libraries": lock["targets"][target]["libraries"]}
    for key, value in expected.items():
        require(receipt.get(key) == value, f"Native receipt mismatch: {key}")
    require(all(type(value) is bool for value in receipt["features"].values()), "Receipt feature values must be booleans")
    sources = receipt.get("sources", [])
    require(len(sources) == len(lock["sources"]) and {item["name"] for item in sources} == {"libvpx", "opus"}, "Receipt source list differs from lock")
    for spec in lock["sources"]:
        item = next(source for source in sources if source["name"] == spec["name"])
        require(all(item.get(key) == spec[key] for key in ("name", "version", "commit", "archive_sha256", "archive_bytes")), "Receipt source identity differs from lock")
        require(HASH.fullmatch(item.get("source_tree_sha256", "")), "Receipt lacks clean source tree digest")
    records = receipt.get("files", [])
    require(records == install_manifest(prefix, expected["libraries"], target), "Installed files differ from receipt (missing, extra, modified, or invalid entry)")
    paths = {record["path"] for record in records}
    required = set(expected["libraries"].values()) | {"include/vpx/vpx_encoder.h", "include/vpx/vpx_decoder.h", "include/opus/opus.h", "include/opus/opus_defines.h"}
    require(required <= paths, "Required native library/header missing")
    machine = target_machine(target)
    if machine is not None:
        reported = receipt.get("validation", {}).get("archive_architectures")
        actual = {name: inspect_elf_archive(prefix / relative, machine) for name, relative in expected["libraries"].items()}
        require(reported == actual, "Native archive architecture evidence differs from installed ELF objects")
    if target in ANDROID_TARGETS:
        validation = receipt.get("validation", {})
        evidence = validation.get("android_ndk")
        abi = lock["targets"][target]["android_abi"]
        compiler_target = ("aarch64-unknown-linux-android" if target == "aarch64-linux-android" else "x86_64-unknown-linux-android") + str(ANDROID_NDK["api_level"])
        expected_ndk = {
            "target": target,
            "abi": abi,
            "expected_elf_machine": machine,
            "compiler_target": compiler_target,
            "api_level": ANDROID_NDK["api_level"],
            "ndk_revision": ANDROID_NDK["revision"],
            "ndk_host_tag": ANDROID_NDK["host_tag"],
            "page_size_bytes": ANDROID_NDK["page_size_bytes"],
            "final_shared_object_linker_flag": ANDROID_NDK["final_shared_object_linker_flag"],
            "ndk_archive": {key: ANDROID_NDK[key] for key in ("linux_archive_url", "linux_archive_bytes", "linux_archive_sha1", "linux_archive_sha256")},
        }
        require(isinstance(evidence, dict) and all(evidence.get(key) == value for key, value in expected_ndk.items()), "Native receipt Android NDK/API/page-size evidence differs from lock")
        require(HASH.fullmatch(evidence.get("source_properties_sha256", "")), "Native receipt lacks Android NDK source.properties digest")
    return receipt


def build(args, lock):
    require(args.target in SUPPORTED, "Unreviewed native target")
    work = args.work_dir.absolute()
    require(not work.exists(), "Build work directory must not exist; choose a new directory (existing work is never removed)")
    require(re.fullmatch(r"[A-Za-z0-9_./:\\-]+", str(work)), "Native build work path must use ASCII without spaces or shell metacharacters")
    work.mkdir(parents=True)
    work = work.resolve()
    env, tools, tool_records, android_info = prepare_tools(args, work, args.target)
    prefix = work / args.target
    prefix.mkdir()
    windows = args.target.endswith("windows-msvc")
    android = args.target in ANDROID_TARGETS
    commands, sources, configuration = [], [], {}

    def run(argv, cwd, label):
        argv = list(map(str, argv))
        log_path = work / "logs" / (label + ".log")
        log_path.parent.mkdir(exist_ok=True)
        print("Running " + label, flush=True)
        with log_path.open("xb") as log:
            result = subprocess.run(argv, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
        commands.append({"argv": argv, "cwd": str(cwd), "log_path": str(log_path), "log_sha256": file_sha256(log_path), "exit_code": result.returncode})
        require(result.returncode == 0, f"{label} failed ({result.returncode}); inspect {log_path}")

    source_paths = {}
    for spec in lock["sources"]:
        archive = get_archive(args.cache_dir, spec, args.offline)
        source = work / "sources" / spec["archive_prefix"]
        manifest = extract_fresh(archive, spec, source)
        source_paths[spec["name"]] = source
        record = {key: spec[key] for key in ("name", "version", "commit", "archive_sha256", "archive_bytes")}
        record.update({"source_tree_sha256": tree_digest(manifest), "source_tree_format": "sha256 of UTF-8 canonical JSON sorted file records (path, bytes, sha256); permissions excluded", "source_file_count": len(manifest)})
        sources.append(record)
        write_json(work / "evidence" / (spec["name"] + "-source-files.json"), manifest)
        build_dir = work / "build" / spec["name"]
        build_dir.mkdir(parents=True)
        if spec["name"] == "libvpx":
            options = ["--enable-vp8", "--enable-vp8-encoder", "--enable-vp8-decoder", "--disable-vp9", "--enable-static", "--disable-shared", "--enable-realtime-only", "--disable-examples", "--disable-tools", "--disable-docs", "--disable-unit-tests", "--disable-webm-io", "--disable-libyuv", "--disable-postproc", "--disable-vp9-postproc", "--target=" + lock["targets"][args.target]["vpx_target"]]
            if args.target.startswith("x86_64"):
                options.append("--as=nasm")
            options += ["--disable-static-msvcrt"] if windows else ["--enable-pic", "--prefix=" + str(prefix), "--libdir=" + str(prefix / "lib")]
            configuration["libvpx"] = options
            run([tools["bash"], "--noprofile", "--norc", (source / "configure").as_posix(), *options], build_dir, "vpx-configure")
            if windows:
                run([tools["make"], "dist"], build_dir, "vpx-project")
                project = build_dir / "vpx.vcxproj"
                runtime = [item.text for item in ET.parse(project).iter() if item.tag.rsplit("}", 1)[-1] == "RuntimeLibrary"]
                require("MultiThreadedDLL" in runtime and not set(runtime) & {"MultiThreaded", "MultiThreadedDebug"}, "VP8 project does not consistently use dynamic CRT")
                # MSVC /GL objects cannot be indexed reliably when rustc bundles
                # a native archive into an rlib used by another crate. Keep
                # standard COFF objects; Rust still optimizes first-party code.
                run([tools["msbuild"], project, f"/m:{args.jobs}", "/p:Configuration=Release", "/p:Platform=x64", "/p:PlatformToolset=v143", "/p:WholeProgramOptimization=false"], build_dir, "vpx-build")
                libraries = list((build_dir / "x64/Release").glob("*.lib"))
                require(len(libraries) == 1, "Expected one freshly built release VP8 library")
                (prefix / "lib").mkdir(exist_ok=True)
                shutil.copyfile(libraries[0], prefix / "lib/vpx.lib")
                (prefix / "include/vpx").mkdir(parents=True)
                for header in (source / "vpx").glob("*.h"):
                    shutil.copyfile(header, prefix / "include/vpx" / header.name)
            else:
                make_command = [tools["make"], f"-j{args.jobs}"]
                if android:
                    make_command.append("STRIP=" + str(tools["strip_compat"]))
                    configuration["libvpx_strip_compat"] = "NDK llvm-objcopy does not accept GNU strip's `-o OUTPUT INPUT`; build passes a local wrapper that converts that invocation to LLVM's positional OUTPUT form."
                run(make_command, build_dir, "vpx-build")
                run([tools["make"], "install"], build_dir, "vpx-install")
        else:
            options = ["-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX=" + str(prefix), "-DCMAKE_INSTALL_LIBDIR=lib", "-DCMAKE_C_COMPILER=" + tools["cc"].as_posix(), "-DCMAKE_MAKE_PROGRAM=" + tools["ninja"].as_posix(), "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DOPUS_PACKAGE_VERSION=" + spec["version"], "-DBUILD_SHARED_LIBS=OFF", "-DOPUS_BUILD_SHARED_LIBRARY=OFF", "-DOPUS_DRED=OFF", "-DOPUS_DEEP_PLC=OFF", "-DOPUS_OSCE=OFF", "-DOPUS_CUSTOM_MODES=OFF", "-DOPUS_BUILD_PROGRAMS=OFF", "-DOPUS_BUILD_TESTING=OFF", "-DBUILD_TESTING=OFF", "-DOPUS_FIXED_POINT=OFF", "-DOPUS_ENABLE_FLOAT_API=ON", "-DOPUS_NONTHREADSAFE_PSEUDOSTACK=OFF", "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"]
            if android:
                android_toolchain = Path(android_info["ndk_path"]) / "build/cmake/android.toolchain.cmake"
                options += ["-DCMAKE_TOOLCHAIN_FILE=" + android_toolchain.as_posix(), "-DANDROID_ABI=" + android_info["abi"], f"-DANDROID_PLATFORM=android-{ANDROID_NDK['api_level']}", "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON"]
            if windows:
                options += ["-DOPUS_STATIC_RUNTIME=OFF", "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL"]
            configuration["opus"] = options
            run([tools["cmake"], "-S", source, "-B", build_dir, "-G", "Ninja", *options], work, "opus-configure")
            run([tools["cmake"], "--build", build_dir, "--config", "Release", "--parallel", str(args.jobs)], work, "opus-build")
            run([tools["cmake"], "--install", build_dir, "--config", "Release"], work, "opus-install")
        for filename in spec["license_files"]:
            safe_relative(filename)
            destination = prefix / "share/licenses" / spec["name"] / filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / filename, destination)
    for record in sources:
        require(tree_digest(tree_manifest(source_paths[record["name"]])) == record["source_tree_sha256"], "Build modified fresh upstream source tree; receipt refused")
    vpx_config = work / "build/libvpx/vpx_config.h"
    opus_cache = work / "build/opus/CMakeCache.txt"
    opus_config = work / "build/opus/config.h"
    compile_commands = json.loads((work / "build/opus/compile_commands.json").read_text(encoding="utf-8"))
    opus_version = next(item["version"] for item in lock["sources"] if item["name"] == "opus")
    checked = check_features(vpx_config.read_text(), opus_cache.read_text(), opus_config.read_text(), compile_commands, args.target, opus_version, android_info)
    config_dir = prefix / "share/nestlink/native-config"
    config_dir.mkdir(parents=True)
    shutil.copyfile(vpx_config, config_dir / "vpx_config.h")
    shutil.copyfile(opus_config, config_dir / "opus_config.h")
    write_json(config_dir / "checked-configuration.json", checked)
    machine = target_machine(args.target)
    archive_architectures = {name: inspect_elf_archive(prefix / relative, machine) for name, relative in lock["targets"][args.target]["libraries"].items()} if machine is not None else {}
    receipt = {"schema_version": 1, "kind": "nestlink-native-codecs", "target": args.target, "profile": "release", "linkage": "static", "crt": lock["targets"][args.target]["crt"], "lock_sha256": file_sha256(args.lock), "sources": sources, "features": lock["features"], "libraries": lock["targets"][args.target]["libraries"], "configuration": configuration, "tools": tool_records, "supplier": {"script_sha256": file_sha256(Path(__file__)), "python_version": platform.python_version(), "python_executable": sys.executable}, "commands": commands, "validation": {"fresh_source_verified_before_and_after_build": True, "configured_features_verified": True, "archive_architectures": archive_architectures, "native_runtime_tests_run": False, "android_ndk": android_info}, "files": install_manifest(prefix, lock["targets"][args.target]["libraries"], args.target)}
    write_json(prefix / RECEIPT, receipt)
    verify_receipt(prefix, args.target, args.lock)
    print("NESTLINK_CODEC_PREFIX=" + str(prefix), flush=True)
    return prefix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch", help="Download and verify the two pinned source archives")
    fetch.add_argument("--cache-dir", type=Path, required=True)
    fetch.add_argument("--offline", action="store_true")
    supply = sub.add_parser("build", help="Build in a new work directory and emit a complete installation receipt")
    supply.add_argument("--target", required=True, choices=SUPPORTED)
    supply.add_argument("--work-dir", type=Path, required=True)
    supply.add_argument("--cache-dir", type=Path, required=True)
    supply.add_argument("--offline", action="store_true")
    supply.add_argument("--jobs", type=int, default=4)
    supply.add_argument("--msys-bin", type=Path, help="Windows MSYS tool directory containing bash, make, perl and POSIX tools")
    supply.add_argument("--nasm", type=Path, help="Explicit NASM executable; otherwise resolve PATH")
    supply.add_argument("--vswhere", type=Path, help="Explicit Visual Studio discovery executable")
    supply.add_argument("--cc", type=Path, help="Explicit native GNU/Linux C compiler matching the requested architecture")
    supply.add_argument("--ndk", type=Path, help="Explicit installed pinned Android NDK directory or SDK root")
    verify = sub.add_parser("verify", help="Verify receipt, source pins, features and every installed byte")
    verify.add_argument("--prefix", type=Path, required=True)
    verify.add_argument("--target", required=True, choices=SUPPORTED)
    args = parser.parse_args()
    try:
        args.lock = args.lock.resolve()
        lock = load_lock(args.lock)
        if args.command == "fetch":
            for spec in lock["sources"]:
                print(get_archive(args.cache_dir.resolve(), spec, args.offline))
        elif args.command == "verify":
            verify_receipt(args.prefix.absolute(), args.target, args.lock)
            print("Native codec installation verified")
        else:
            require(1 <= args.jobs <= 64, "--jobs must be between 1 and 64")
            args.cache_dir = args.cache_dir.resolve()
            build(args, lock)
    except (SupplyError, OSError, ValueError, KeyError, tarfile.TarError) as error:
        print("Native codec supply failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
