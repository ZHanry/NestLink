"""Optional input package boundaries. No real signing, UAC or installation."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packaging/native"))
import release_verify as verify


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


BUILD = module("privileged_native_builder", "scripts/refactor-native-packaging.py")
PRODUCER = module("privileged_release_producer", "scripts/refactor-release-producer.py")
HANDOFF = module("privileged_release_handoff", "scripts/refactor-release-handoff.py")


def payload():
    value = json.loads((ROOT / "config/native-payload.template.json").read_text(encoding="utf-8"))
    value["source_revision"] = "a" * 40
    for index, item in enumerate(value["artifacts"]):
        item.update(bytes=1, sha256=format(index + 1, "064x"), state_compatibility="v15-user-state-1")
        if item["platform"] == "windows":
            item["windows_certificate_sha256"] = "b" * 64
    return value


class PrivilegedPackageTests(unittest.TestCase):
    def test_manifest_limits_broker_to_windows_x64_and_correct_statement(self):
        value = payload()
        verify.validate_manifest(value)
        selected = next(item for item in value["artifacts"] if item["role"] == "privileged")
        for field, change in (("platform", "linux"), ("architecture", "aarch64"), ("format", "asset")):
            wrong = copy.deepcopy(value)
            next(item for item in wrong["artifacts"] if item["role"] == "privileged")[field] = change
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify.validate_manifest(wrong)
        value["artifacts"] = [selected]
        value["purpose"] = "native-packages"
        selected.update(format="inno", path="NestLink-windows-x64-privileged.exe", payload_manifest_sha256="c" * 64)
        verify.validate_manifest(value)

    def test_optional_cohort_requires_all_three_matching_signed_executables(self):
        value = payload()
        selected = BUILD.executable_items(value, "windows", "x86_64", "privileged")
        self.assertEqual({item["role"] for item in selected}, {"desktop", "daemon", "privileged"})
        self.assertEqual(len(BUILD.executable_items(value, "windows", "x86_64", "desktop")), 2)
        for mutate in (
            lambda data: data["artifacts"].remove(next(item for item in data["artifacts"] if item["role"] == "privileged")),
            lambda data: data["artifacts"].append(copy.deepcopy(data["artifacts"][0])),
            lambda data: data["artifacts"][0].update(state_compatibility="different-state"),
            lambda data: data["artifacts"][0].update(path="windows-x86_64/nestlink-daemon.exe"),
        ):
            wrong = copy.deepcopy(value)
            mutate(wrong)
            with self.assertRaises(ValueError):
                BUILD.executable_items(wrong, "windows", "x86_64", "privileged")
        with self.assertRaises(ValueError):
            BUILD.executable_items(value, "linux", "x86_64", "privileged")

    def test_policy_derives_fixed_hashes_and_keeps_signing_identities_separate(self):
        value = payload()
        chosen = BUILD.executable_items(value, "windows", "x86_64", "privileged")
        policy = BUILD.broker_policy(value, chosen, "c" * 64, "d" * 64)
        self.assertEqual(policy["source_revision"], value["source_revision"])
        self.assertEqual(policy["payload_manifest_sha256"], "c" * 64)
        for item in chosen:
            self.assertEqual(policy[item["role"] + "_sha256"], item["sha256"])
        with self.assertRaises(ValueError):
            BUILD.broker_policy(value, chosen, "c" * 64, "b" * 64)
        with self.assertRaises(ValueError):
            BUILD.broker_policy(value, chosen[:2], "c" * 64, "d" * 64)

    def test_build_selects_separate_setup_checks_three_pe_and_authenticates_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = payload()
            for item in data["artifacts"]:
                path = root / item["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"x")
                item["sha256"] = verify.sha256(path)
            manifest = root / "native-payload.json"
            manifest.write_text(json.dumps(data), encoding="utf-8")
            for name in ("payload.p7s", "update.crt"):
                (root / name).write_bytes(b"explicit-mock")
            args = SimpleNamespace(role="privileged", bundle=root, manifest=manifest, signature=root / "payload.p7s",
                certificate=root / "update.crt", certificate_sha256="d" * 64, openssl="mock-openssl",
                output=root / "NestLink-windows-x64-privileged.exe", iscc="mock-iscc", powershell="mock-powershell", inno_sign_command="mock-only")
            signatures = []
            def signing(path, pin, powershell):
                self.assertEqual(pin, "b" * 64)
                signatures.append(path.name)
            def inno(arguments, **unused):
                script = arguments[-1]
                self.assertEqual(script, ROOT / "packaging/windows/nestlink-v15-privileged.iss")
                stage = Path(next(arg.split("=", 1)[1] for arg in arguments if isinstance(arg, str) and arg.startswith("/DPayloadDir=")))
                policy = json.loads((stage / "broker-package.json").read_text())
                self.assertEqual(policy["payload_manifest_sha256"], verify.sha256(manifest))
                self.assertIn("/DMaintenanceHelperSha256=" + verify.sha256(stage / "Manage-NestLinkPrivileged.ps1"), arguments)
                owner = stage / "signed-uninstaller"
                owner.mkdir()
                (owner / "uninstaller.exe").write_bytes(b"MZmock")
                args.output.write_bytes(b"MZmock")
            fake_signer = SimpleNamespace(windows_signature=signing)
            with mock.patch.object(BUILD.sys, "platform", "win32"), mock.patch.object(BUILD, "payload", return_value=data), mock.patch.object(BUILD.verify, "command", side_effect=inno), mock.patch("importlib.util.module_from_spec", return_value=fake_signer), mock.patch("importlib.machinery.SourceFileLoader.exec_module"):
                BUILD.build_windows(args)
            self.assertEqual(signatures, ["nestlink-desktop.exe", "nestlink-daemon.exe", "nestlink-privileged.exe", "uninstaller.exe", args.output.name])

    def test_signed_release_and_handoff_include_the_optional_package(self):
        packages = json.loads((ROOT / "config/native-packages.template.json").read_text())
        entry = next(item for item in packages["artifacts"] if item["role"] == "privileged")
        self.assertEqual(entry["path"], PRODUCER.PACKAGE_PATHS["windows-x64-privileged-setup"])
        self.assertEqual(PRODUCER.NATIVE["windows-x64"][2], ("desktop", "daemon", "privileged"))
        self.assertEqual(PRODUCER.FINAL_ROLES, HANDOFF.CURRENT_ROLES - {"acceptance"})
        handoff = json.loads((ROOT / "config/release-handoff.template.json").read_text())
        self.assertEqual({item["role"] for item in handoff["artifacts"]}, HANDOFF.CURRENT_ROLES | HANDOFF.PRESERVATION_ROLES)
        self.assertEqual({item["id"] for item in handoff["acceptance_cases"]}, HANDOFF.REQUIRED_CASES)
        self.assertIn("windows-privileged-input", HANDOFF.REQUIRED_CASES)

    def test_powershell_owner_rejects_live_cohort_and_replay_without_system_changes(self):
        powershell = shutil.which("powershell.exe")
        if not powershell:
            self.skipTest("PowerShell parser/functions are checked on Windows")
        helper = str(ROOT / "packaging/windows/Manage-NestLinkPrivileged.ps1").replace("'", "''")
        script = r"""
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('HELPER',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Helper parse failed'}
$names=@('Keys','SameAccepted','AcceptUpdate','Quiescent')
$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -cin $names},$true) | ForEach-Object { Invoke-Expression $_.Extent.Text }
$accepted=[pscustomobject]@{directory='15.0.0-r2';version='15.0.0';release_sequence=2;source_revision='a';payload_manifest_sha256='b';update_certificate_sha256='c';windows_certificate_sha256='d';state_compatibility='state1'}
$record=[pscustomobject]@{maximum_sequence=2;maximum_accepted=$accepted;current=$null}
AcceptUpdate $record $accepted
$rejected=0
foreach($field in @('release_sequence','payload_manifest_sha256','update_certificate_sha256')){
 $wrong=$accepted.PSObject.Copy();$wrong.$field=if($field -eq 'release_sequence'){1}else{'changed'}
 try{AcceptUpdate $record $wrong}catch{$rejected++}
}
if($rejected -ne 3){throw 'Replay or trust mutation passed'}
$InstallDir='C:\Program Files\NestLink-v15-Privileged'
$script:processes=@([pscustomobject]@{ExecutablePath='C:\OtherProduct\nestlink-daemon.exe'})
function Get-CimInstance { param($ClassName,$Filter) return $script:processes }
Quiescent
foreach($path in @('C:\Program Files\NestLink-v15-Privileged\versions\15.0.0-r2\nestlink-privileged.exe','')){
 $script:processes=@([pscustomobject]@{ExecutablePath=$path});$rejected=$false
 try{Quiescent}catch{$rejected=$true}
 if(-not $rejected){throw 'Active or unauthenticated process passed'}
}
'pure owner functions passed'
""".replace("HELPER", helper)
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", script], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        self.assertIn(b"pure owner functions passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
