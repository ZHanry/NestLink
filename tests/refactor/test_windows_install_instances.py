"""Execute only helper function definitions against owned temporary files.

No top-level installer action, signer, COM shortcut, process or service runs.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
POWERSHELL = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"


@unittest.skipUnless(sys.platform == "win32" and POWERSHELL.is_file(), "Windows PowerShell 5.1 fixture")
class WindowsInstanceFunctions(unittest.TestCase):
    def test_generation_acceptance_and_interrupted_receipt_recovery(self):
        with tempfile.TemporaryDirectory(prefix="nestlink-instance-functions-") as temporary:
            directory = Path(temporary)
            harness = directory / "fixture.ps1"
            harness.write_text(r'''
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Helper syntax invalid'}
# Deliberately select only top-level function definitions, never the parameter
# block or any action, signing, process-discovery or service statement.
foreach($statement in $ast.EndBlock.Statements) {
  if($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
    . ([scriptblock]::Create($statement.Extent.Text))
  }
}
$InstallDir=Join-Path $args[1] 'install'
$ManagedStateRoot=Join-Path $args[1] 'retained-state'
$null=[IO.Directory]::CreateDirectory($InstallDir)
$null=[IO.Directory]::CreateDirectory($ManagedStateRoot)
$script:pendingRecovery=$null
$script:checks=0
function Require($Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Refused([scriptblock]$Operation,[string]$Message){$failed=$false;try{& $Operation}catch{$failed=$true};Require $failed $Message}
function Shortcut($Current){
  $temporary=Join-Path $InstallDir ('fixture-new-'+[guid]::NewGuid().ToString('N'))
  [IO.File]::WriteAllText($temporary,'fixture shortcut only')
  return [pscustomobject]@{Temporary=$temporary;Final=(Join-Path $InstallDir 'fixture-shortcut')}
}
$record=Receipt
Require ($null -eq $record.current -and $record.maximum_sequence -eq 0) 'First install receipt invalid'
$first=NextInstance $record $null
$current=[pscustomobject]@{directory='15.0.0-r5';version='15.0.0';sequence=5;source_revision=('d'*40);payload_manifest_sha256=('a'*64);update_certificate_sha256=('b'*64);windows_certificate_sha256=('c'*64);state_compatibility='user-state-1'}
AcceptUpdate $record $current $null
$accepted=[ordered]@{schema_version=1;current=$current;previous=$null;maximum_sequence=5;maximum_accepted=$current;instance=$first}
CommitRecord $accepted
$record=Receipt;$instance=InstallationInstance
Require ($instance.instance_id -ceq $first.instance_id -and $instance.active) 'Committed instance differs'
Require ((EffectiveState $instance) -ceq (Join-Path (Join-Path $ManagedStateRoot 'instances') $first.instance_id)) 'Effective path differs'
$same=NextInstance $record $instance
Require ($same.instance_id -ceq $first.instance_id) 'Upgrade changed instance'
Refused {AcceptUpdate $record $current $instance} 'Active replay was accepted'
$retired=[ordered]@{schema_version=1;namespace='NestLink-v15';instance_id=$first.instance_id;active=$false}
$retiredRecord=[ordered]@{schema_version=1;current=$null;previous=$current;maximum_sequence=5;maximum_accepted=$current;instance=$retired}
CommitRecord $retiredRecord
$record=Receipt;$instance=InstallationInstance
AcceptUpdate $record $current $instance
$next=NextInstance $record $instance
Require ($next.instance_id -cne $first.instance_id -and $next.active) 'Reinstall reused retired instance'
$changed=$current.PSObject.Copy();$changed.payload_manifest_sha256='e'*64
Refused {AcceptUpdate $record $changed $instance} 'Changed bytes at same sequence accepted'
$changed=$current.PSObject.Copy();$changed.sequence=4
Refused {AcceptUpdate $record $changed $instance} 'Lower sequence accepted after uninstall'
$changed=$current.PSObject.Copy();$changed.sequence=6;$changed.update_certificate_sha256='e'*64
Refused {AcceptUpdate $record $changed $instance} 'Uninstall reset update trust'
$receiptPath=Join-Path $InstallDir 'installation.json'
$instancePath=Join-Path $InstallDir 'installation-instance.json'
$originalReceipt=[IO.File]::ReadAllBytes($receiptPath)
$originalInstance=[IO.File]::ReadAllBytes($instancePath)
$raw=(Get-Command AtomicJson -CommandType Function).Definition
. ([scriptblock]::Create('function FixtureAtomicJson { '+$raw+' }'))
function AtomicJson([string]$Path,$Value) {
  if($Path -ceq $receiptPath){throw 'Owned fixture failure after marker replacement'}
  FixtureAtomicJson $Path $Value
}
$after=[ordered]@{schema_version=1;current=$current;previous=$null;maximum_sequence=5;maximum_accepted=$current;instance=$next}
Refused {CommitRecord $after} 'Injected receipt failure did not fail'
Require ((Digest ([IO.File]::ReadAllBytes($receiptPath))) -ceq (Digest $originalReceipt)) 'Receipt rollback changed bytes'
Require ((Digest ([IO.File]::ReadAllBytes($instancePath))) -ceq (Digest $originalInstance)) 'Marker rollback changed bytes'
. ([scriptblock]::Create('function AtomicJson { '+$raw+' }'))
WriteNew (Join-Path $InstallDir 'installation-incomplete.json') @{fixture='persistent installation fence'}
WriteNew (Join-Path $InstallDir 'installation-instance-pending.json') @{schema_version=1;purpose='installation-instance-transaction';original_receipt=[Convert]::ToBase64String($originalReceipt);original_instance=[Convert]::ToBase64String($originalInstance)}
AtomicJson $instancePath $next
$record=Receipt;$instance=InstallationInstance
Require ($instance.instance_id -ceq $first.instance_id -and -not $instance.active) 'Crash recovery did not select prior generation'
function EnsureReady { $script:checks++ } # Model the native gate; no process launched.
RecoverInstanceTransaction
Require ((Digest ([IO.File]::ReadAllBytes($receiptPath))) -ceq (Digest $originalReceipt)) 'Crash recovery receipt changed bytes'
Require ((Digest ([IO.File]::ReadAllBytes($instancePath))) -ceq (Digest $originalInstance)) 'Crash recovery marker changed bytes'
Require (Test-Path -LiteralPath (Join-Path $InstallDir 'installation-incomplete.json')) 'Recovery erased install fence'
Require (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'installation-instance-pending.json'))) 'Successful recovery left pending commit'
[Console]::WriteLine('{"powershell":"'+$PSVersionTable.PSVersion.ToString()+'","checks":'+$script:checks+',"top_level_installer_executed":false,"native_gate_modeled":true}')
''', encoding="utf-8")
            result = subprocess.run([str(POWERSHELL),"-NoProfile","-NonInteractive","-File",str(harness),str(ROOT / "packaging/windows/Manage-NestLink.ps1"),str(directory)], stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
            self.assertEqual(result.returncode,0,result.stdout.decode("utf-8",errors="replace")+result.stderr.decode("utf-8",errors="replace"))
            report=json.loads(result.stdout.decode("utf-8-sig").strip())
            self.assertTrue(report["powershell"].startswith("5.1."))
            self.assertGreaterEqual(report["checks"],16)
            self.assertFalse(report["top_level_installer_executed"])


@unittest.skipUnless(sys.platform == "win32" and POWERSHELL.is_file(), "Windows PowerShell 5.1 fixture")
class WindowsMaintenanceFunctions(unittest.TestCase):
    def check_functions(self, body):
        with tempfile.TemporaryDirectory(prefix="nestlink-maintenance-functions-") as temporary:
            directory = Path(temporary)
            harness = directory / "fixture.ps1"
            harness.write_text(r'''
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Helper syntax invalid'}
foreach($statement in $ast.EndBlock.Statements) {
  if($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
    . ([scriptblock]::Create($statement.Extent.Text))
  }
}
$InstallDir=Join-Path $args[1] 'install'
$ManagedStateRoot=Join-Path $args[1] 'state'
$StateDir=$ManagedStateRoot
$ControlDir=Join-Path $StateDir ('maintenance-'+[guid]::NewGuid().ToString())
foreach($directory in @($InstallDir,$StateDir,$ControlDir)){$null=[IO.Directory]::CreateDirectory($directory)}
$script:checks=0
function Require($Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Refused([scriptblock]$Operation,[string]$Message){$failed=$false;try{& $Operation}catch{$failed=$true};Require $failed $Message}
''' + body + r'''
[Console]::WriteLine('{"powershell":"'+$PSVersionTable.PSVersion.ToString()+'","checks":'+$script:checks+',"top_level_installer_executed":false}')
''', encoding="utf-8")
            result = subprocess.run([str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(harness), str(ROOT / "packaging/windows/Manage-NestLink.ps1"), str(directory)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
            self.assertEqual(result.returncode, 0, result.stdout.decode("utf-8", errors="replace") + result.stderr.decode("utf-8", errors="replace"))
            report = json.loads(result.stdout.decode("utf-8-sig").strip())
            self.assertTrue(report["powershell"].startswith("5.1."))
            self.assertFalse(report["top_level_installer_executed"])
            return report

    def test_only_exact_current_generation_may_resume_interrupted_acceptance(self):
        report = self.check_functions(r'''
$instance=[pscustomobject]@{schema_version=1;namespace='NestLink-v15';instance_id=[guid]::NewGuid().ToString();active=$true}
$current=[pscustomobject]@{directory='15.0.0-r5';version='15.0.0';sequence=5;source_revision=('d'*40);payload_manifest_sha256=('a'*64);update_certificate_sha256=('b'*64);windows_certificate_sha256=('c'*64);state_compatibility='user-state-1'}
$prior=$current.PSObject.Copy();$prior.sequence=4;$prior.directory='15.0.0-r4'
$record=[pscustomobject]@{schema_version=1;current=$current;previous=$prior;maximum_sequence=5;maximum_accepted=$current;instance=$instance}
AcceptUpdate $record $current $instance $true
Require $true 'Exact interrupted current setup was not recovered'
Refused {AcceptUpdate $record $current $instance} 'Ordinary active replay was accepted'
foreach($field in @('directory','version','sequence','source_revision','payload_manifest_sha256','update_certificate_sha256','windows_certificate_sha256','state_compatibility')) {
  $changed=$current.PSObject.Copy();$changed.$field=if($field -ceq 'sequence'){4}else{'changed'}
  Refused {AcceptUpdate $record $changed $instance $true} ('Recovery accepted a changed '+$field)
}
$different=$instance.PSObject.Copy();$different.instance_id=[guid]::NewGuid().ToString()
Refused {AcceptUpdate $record $current $different $true} 'Recovery admitted a different generation'
$different=$instance.PSObject.Copy();$different.active=$false
Refused {AcceptUpdate $record $current $different $true} 'Recovery admitted an inactive generation'
$oldRecord=$record.PSObject.Copy();$oldRecord.current=$prior
Refused {AcceptUpdate $oldRecord $prior $instance $true} 'Recovery bypassed the monotonic sequence after binary rollback'
$next=UpdateRecord $record $current $instance $true
Require ($next.previous.directory -ceq $prior.directory) 'Exact recovery replaced rollback history with a duplicate current'
Require ($next.instance.instance_id -ceq $instance.instance_id -and $next.maximum_sequence -eq 5) 'Recovery changed generation or maximum sequence'
''')
        self.assertGreaterEqual(report["checks"], 15)

    def test_ready_requires_the_original_live_controller_and_typed_recovery(self):
        report = self.check_functions(r'''
WriteNew (Join-Path $InstallDir 'installation-incomplete.json') @{fixture='retained'}
$ready=[ordered]@{schema_version=1;control_id=(ControlId);state='ready';installation_recovery=$true}
$owner=[ordered]@{temporary_directory='fixture-only';controller_pid=$PID;controller_start_ticks=(Get-Process -Id $PID).StartTime.ToUniversalTime().Ticks}
WriteNew (Join-Path $ControlDir 'ready.json') $ready
WriteNew (Join-Path $ControlDir 'installer-owner.json') $owner
EnsureReady
Require $script:maintenanceRecovery 'Native held-gate recovery proof was lost'
$ready.installation_recovery=$false;AtomicJson (Join-Path $ControlDir 'ready.json') $ready
EnsureReady
Require (-not $script:maintenanceRecovery) 'Fresh maintenance admitted recovery'
$ready.installation_recovery='true';AtomicJson (Join-Path $ControlDir 'ready.json') $ready
Refused {EnsureReady} 'String recovery flag was accepted as native ownership proof'
$ready.installation_recovery=$true;AtomicJson (Join-Path $ControlDir 'ready.json') $ready
$owner.controller_start_ticks--;AtomicJson (Join-Path $ControlDir 'installer-owner.json') $owner
Refused {EnsureReady} 'Reused PID or changed controller identity was accepted'
$owner.controller_pid=2147483647;AtomicJson (Join-Path $ControlDir 'installer-owner.json') $owner
Refused {EnsureReady} 'A dead native controller was accepted'
''')
        self.assertGreaterEqual(report["checks"], 5)



if __name__ == "__main__":
    unittest.main()
