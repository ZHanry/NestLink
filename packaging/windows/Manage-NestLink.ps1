[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Resolve','Enter','Commit','Rollback','Leave','Abort','Uninstall')][string]$Action,
    [string]$PayloadDir,
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\NestLink-v15'),
    [string]$StateDir = (Join-Path $env:LOCALAPPDATA 'NestLink-v15'),
    [string]$ControlDir,
    [string]$ResolvedStateFile,
    [string]$PayloadManifestSha256,
    [string]$UpdateCertificateSha256,
    [string]$WindowsCertificateSha256
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Security

function Digest([byte[]]$Bytes) {
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
function FixedHash([string]$Value) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw 'A fixed lowercase SHA-256 is required.' }
}
function PlainFile([string]$Path) {
    $file = Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Expected a regular file without a reparse point.' }
    return $file
}
function FileHash([string]$Path) { $null = PlainFile $Path; return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function ReadJson([string]$Path) {
    $file = PlainFile $Path
    if ($file.Length -gt 262144) { throw 'Metadata exceeds its budget.' }
    return [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8) | ConvertFrom-Json
}
function WriteNew([string]$Path, $Value) {
    $raw = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 12 -Compress))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($raw,0,$raw.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
function AtomicJson([string]$Path, $Value) {
    $temporary = $Path + '.new-' + [guid]::NewGuid().ToString('N')
    WriteNew $temporary $Value
    if (Test-Path -LiteralPath $Path) { $null = PlainFile $Path; [IO.File]::Replace($temporary,$Path,[NullString]::Value) }
    else { [IO.File]::Move($temporary,$Path) }
}
function Signature([string]$Path, [string]$Pin) {
    FixedHash $Pin
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or (Digest $signature.SignerCertificate.RawData) -cne $Pin -or $null -eq $signature.TimeStamperCertificate) {
        throw 'Authenticode trust, fixed signer or timestamp did not verify.'
    }
    $codeSigning = $false
    foreach ($extension in $signature.SignerCertificate.Extensions) {
        if ($extension.Oid.Value -eq '2.5.29.37') {
            $usage = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($extension,$extension.Critical)
            $codeSigning = @($usage.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' }).Count -gt 0
        }
    }
    if (-not $codeSigning) { throw 'The signer lacks the code-signing EKU.' }
}
function VerifyPayload([string]$Directory, [string]$Expected, [string]$UpdatePin, [string]$WindowsPin) {
    FixedHash $Expected; FixedHash $UpdatePin; FixedHash $WindowsPin
    if ($UpdatePin -ceq $WindowsPin) { throw 'Update and Authenticode identities must be distinct.' }
    $manifest = Join-Path $Directory 'payload.json'
    $signature = Join-Path $Directory 'payload.p7s'
    if ((FileHash $manifest) -cne $Expected) { throw 'Payload manifest bytes differ from the accepted package.' }
    $null = PlainFile $signature
    $raw = [IO.File]::ReadAllBytes($manifest)
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($raw),$true)
    $cms.Decode([IO.File]::ReadAllBytes($signature))
    if ($cms.SignerInfos.Count -ne 1 -or $null -eq $cms.SignerInfos[0].Certificate -or (Digest $cms.SignerInfos[0].Certificate.RawData) -cne $UpdatePin) { throw 'Independent update signer pin differs.' }
    # Cryptographic CMS verification against the explicit independent pin;
    # certificate-chain trust is the separate Authenticode check above.
    $cms.CheckSignature($true)
    $data = ReadJson $manifest
    if ($data.schema_version -ne 1 -or $data.product -cne 'NestLink-v15' -or $data.purpose -cne 'native-payload' -or $data.version -cnotmatch '^15\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or $data.release_sequence -lt 1 -or $data.source_revision -cnotmatch '^[0-9a-f]{40}$') { throw 'Invalid v15 payload statement.' }
    $selected = @($data.artifacts | Where-Object { $_.platform -ceq 'windows' -and $_.architecture -ceq 'x86_64' -and $_.format -ceq 'executable' -and $_.role -cin @('desktop','daemon') })
    if ($selected.Count -ne 2) { throw 'Expected exactly desktop and daemon Windows executables.' }
    $names = @()
    $compatibility = @()
    foreach ($item in $selected) {
        if ($item.path -match '\\|:|(^|/)\.\.(/|$)|^/' -or $item.windows_certificate_sha256 -cne $WindowsPin) { throw 'Invalid executable identity/path.' }
        $name = ($item.path -split '/')[-1]
        if ($name -cnotin @('nestlink-desktop.exe','nestlink-daemon.exe') -or $name -cin $names) { throw 'Duplicate or unexpected executable.' }
        $names += $name; $compatibility += $item.state_compatibility
        $path = Join-Path $Directory $name
        if ((PlainFile $path).Length -ne $item.bytes -or (FileHash $path) -cne $item.sha256) { throw 'Executable bytes differ from signed payload.' }
        Signature $path $WindowsPin
    }
    if (@($compatibility | Select-Object -Unique).Count -ne 1) { throw 'Inconsistent user-state compatibility.' }
    return [pscustomobject]@{ Data=$data; Compatibility=$compatibility[0] }
}
function Receipt {
    $path = Join-Path $InstallDir 'installation.json'
    $pendingPath = Join-Path $InstallDir 'installation-instance-pending.json'
    if (Test-Path -LiteralPath $pendingPath) {
        if (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'installation-incomplete.json'))) { throw 'An instance recovery record exists without the installation fence; explicit review is required.' }
        $script:pendingRecovery = ReadJson $pendingPath
        if ($script:pendingRecovery.schema_version -ne 1 -or $script:pendingRecovery.purpose -cne 'installation-instance-transaction') { throw 'Invalid instance recovery record.' }
        $value = if ($null -ne $script:pendingRecovery.original_receipt) {
            [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($script:pendingRecovery.original_receipt)) | ConvertFrom-Json
        } else { [pscustomobject]@{schema_version=1; current=$null; previous=$null; maximum_sequence=0; maximum_accepted=$null; instance=$null} }
    } elseif (Test-Path -LiteralPath $path) { $value = ReadJson $path } else { $value = $null }
    if ($null -ne $value) {
        if ($value.schema_version -ne 1 -or $value.maximum_sequence -lt 0) { throw 'Invalid installation receipt.' }
        if (-not ($value.PSObject.Properties.Name -ccontains 'instance')) { $value | Add-Member -NotePropertyName instance -NotePropertyValue $null }
        if (-not ($value.PSObject.Properties.Name -ccontains 'maximum_accepted')) { $value | Add-Member -NotePropertyName maximum_accepted -NotePropertyValue $value.current }
        return $value
    }
    return [pscustomobject]@{ schema_version=1; current=$null; previous=$null; maximum_sequence=0; maximum_accepted=$null; instance=$null }
}
function InstallationInstance {
    if ($null -ne $script:pendingRecovery) { return $record.instance }
    $path = Join-Path $InstallDir 'installation-instance.json'
    if (-not (Test-Path -LiteralPath $path)) {
        if ($null -ne $record.current -or $null -ne $record.instance) { throw 'Accepted installation instance marker is missing.' }
        return $null
    }
    $value = ReadJson $path
    if (@($value.PSObject.Properties.Name).Count -ne 4 -or $value.schema_version -ne 1 -or $value.namespace -cne 'NestLink-v15' -or $value.instance_id -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or $value.instance_id -ceq '00000000-0000-0000-0000-000000000000' -or $value.active -isnot [bool]) { throw 'Invalid public installation generation.' }
    if ($null -eq $record.instance -or $record.instance.instance_id -cne $value.instance_id -or $record.instance.active -ne $value.active -or (($null -ne $record.current) -ne $value.active)) { throw 'Installation instance and accepted receipt differ; recover the interrupted transaction explicitly.' }
    return $value
}
function EffectiveState($Instance) {
    if ($null -ne $Instance -and $Instance.active) { return Join-Path (Join-Path $ManagedStateRoot 'instances') $Instance.instance_id }
    return $ManagedStateRoot
}
function SameAccepted($Left, $Right) {
    if ($null -eq $Left -or $null -eq $Right) { return $false }
    foreach ($field in @('directory','version','sequence','source_revision','payload_manifest_sha256','update_certificate_sha256','windows_certificate_sha256','state_compatibility')) {
        if ($Left.$field -cne $Right.$field) { return $false }
    }
    return $true
}
function NextInstance($Record, $Instance) {
    if ($null -ne $Record.current) {
        if ($null -eq $Instance -or -not $Instance.active) { throw 'Accepted installation has no active generation.' }
        $generation = $Instance.instance_id
    } else {
        if ($null -ne $Instance -and $Instance.active) { throw 'Retired receipt still names an active generation.' }
        $generation = [guid]::NewGuid().ToString()
    }
    return [ordered]@{schema_version=1; namespace='NestLink-v15'; instance_id=$generation; active=$true}
}
function AcceptUpdate($Record, $Current, $Instance, [bool]$Recover=$false) {
    $reinstall = $null -eq $Record.current -and $null -ne $Instance -and -not $Instance.active -and $Current.sequence -eq $Record.maximum_sequence -and (SameAccepted $Current $Record.maximum_accepted)
    $recovery = $Recover -and $null -ne $Instance -and $Instance.active -and $null -ne $Record.instance -and $Record.instance.active -and $Instance.instance_id -ceq $Record.instance.instance_id -and $Current.sequence -eq $Record.maximum_sequence -and (SameAccepted $Current $Record.current) -and (SameAccepted $Current $Record.maximum_accepted)
    if ($Current.sequence -lt $Record.maximum_sequence -or ($Current.sequence -eq $Record.maximum_sequence -and -not $reinstall -and -not $recovery)) { throw 'Replayed/downgraded setup is not an update, exact latest accepted reinstall or held-gate recovery.' }
    if ($null -ne $Record.maximum_accepted -and $Record.maximum_accepted.update_certificate_sha256 -cne $Current.update_certificate_sha256) { throw 'Retained update trust must survive uninstall.' }
}
function UpdateRecord($Record, $Current, $Instance, [bool]$Recover=$false) {
    AcceptUpdate $Record $Current $Instance $Recover
    $previous = if (SameAccepted $Current $Record.current) { $Record.previous } else { $Record.current }
    return [ordered]@{schema_version=1; current=$Current; previous=$previous; maximum_sequence=$Current.sequence; maximum_accepted=$Current; instance=(NextInstance $Record $Instance)}
}
function RestoreBytes([string]$Path, $Original) {
    if ($null -eq $Original) {
        if (Test-Path -LiteralPath $Path) { $null = PlainFile $Path; Remove-Item -LiteralPath $Path }
    } else {
        $restore = $Path + '.restore-' + [guid]::NewGuid().ToString('N')
        $stream = [IO.File]::Open($restore, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($Original,0,$Original.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        if (Test-Path -LiteralPath $Path) { $null = PlainFile $Path; [IO.File]::Replace($restore,$Path,[NullString]::Value) }
        else { [IO.File]::Move($restore,$Path) }
    }
}
function RecoverInstanceTransaction {
    if ($null -eq $script:pendingRecovery) { return }
    EnsureReady
    $oldReceipt = if ($null -eq $script:pendingRecovery.original_receipt) { $null } else { [Convert]::FromBase64String($script:pendingRecovery.original_receipt) }
    $oldInstance = if ($null -eq $script:pendingRecovery.original_instance) { $null } else { [Convert]::FromBase64String($script:pendingRecovery.original_instance) }
    RestoreBytes (Join-Path $InstallDir 'installation.json') $oldReceipt
    RestoreBytes (Join-Path $InstallDir 'installation-instance.json') $oldInstance
    Remove-Item -LiteralPath (Join-Path $InstallDir 'installation-instance-pending.json')
    $script:pendingRecovery = $null
}
function ControlId {
    $parent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($ControlDir)).TrimEnd('\')
    if (-not $parent.Equals([IO.Path]::GetFullPath($StateDir).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { throw 'Control directory must be a direct child of isolated user state.' }
    $name = [IO.Path]::GetFileName($ControlDir)
    if ($name -cnotmatch '^maintenance-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$') { throw 'Invalid maintenance control id.' }
    return $Matches[1]
}
function EnsureReady {
    $id = ControlId
    $ready = ReadJson (Join-Path $ControlDir 'ready.json')
    if ($ready.control_id -cne $id -or $ready.state -cne 'ready' -or $ready.installation_recovery -isnot [bool] -or (Test-Path -LiteralPath (Join-Path $ControlDir 'failed.json')) -or (Test-Path -LiteralPath (Join-Path $ControlDir 'released.json')) -or (Test-Path -LiteralPath (Join-Path $ControlDir 'abandoned.json')) -or (Test-Path -LiteralPath (Join-Path $ControlDir 'release.json'))) { throw 'The original maintenance owner is unavailable.' }
    if (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'installation-incomplete.json'))) { throw 'Installation admission was lost.' }
    $owner = ReadJson (Join-Path $ControlDir 'installer-owner.json')
    $controller = Get-Process -Id $owner.controller_pid -ErrorAction SilentlyContinue
    if ($null -eq $controller -or $controller.StartTime.ToUniversalTime().Ticks -ne $owner.controller_start_ticks -or $controller.HasExited) { throw 'The original native controller no longer holds installation admission.' }
    $script:maintenanceRecovery = $ready.installation_recovery
}
function Shortcut($Current) {
    $target = Join-Path $InstallDir ('versions\' + $Current.directory + '\nestlink-desktop.exe')
    $menu = [Environment]::GetFolderPath('Programs')
    $path = Join-Path $menu 'NestLink v15.lnk'
    $temporary = Join-Path $menu ('NestLink v15.new-' + [guid]::NewGuid().ToString('N') + '.lnk')
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($temporary)
    $link.TargetPath = $target
    $link.Arguments = '--state-dir "' + $ManagedStateRoot + '"'
    $link.WorkingDirectory = [IO.Path]::GetDirectoryName($target)
    $link.Description = 'NestLink v15'
    $link.Save()
    return [pscustomobject]@{Temporary=$temporary; Final=$path}
}
function CommitRecord($Record) {
    $shortcut = if ($null -ne $Record.current) { Shortcut $Record.current } else { $null }
    $path = Join-Path $InstallDir 'installation.json'
    $original = if (Test-Path -LiteralPath $path) { $null = PlainFile $path; [IO.File]::ReadAllBytes($path) } else { $null }
    $instancePath = Join-Path $InstallDir 'installation-instance.json'
    $originalInstance = if (Test-Path -LiteralPath $instancePath) { $null = PlainFile $instancePath; [IO.File]::ReadAllBytes($instancePath) } else { $null }
    $pendingPath = Join-Path $InstallDir 'installation-instance-pending.json'
    WriteNew $pendingPath ([ordered]@{
        schema_version=1; purpose='installation-instance-transaction'
        original_receipt=$(if ($null -eq $original) { $null } else { [Convert]::ToBase64String($original) })
        original_instance=$(if ($null -eq $originalInstance) { $null } else { [Convert]::ToBase64String($originalInstance) })
    })
    try {
        AtomicJson $instancePath $Record.instance
        AtomicJson $path $Record
        if ($null -ne $shortcut) {
            if (Test-Path -LiteralPath $shortcut.Final) { [IO.File]::Replace($shortcut.Temporary,$shortcut.Final,[NullString]::Value) }
            else { [IO.File]::Move($shortcut.Temporary,$shortcut.Final) }
        }
        Remove-Item -LiteralPath $pendingPath
    } catch {
        RestoreBytes $path $original
        RestoreBytes $instancePath $originalInstance
        Remove-Item -LiteralPath $pendingPath
        throw
    } finally {
        if ($null -ne $shortcut -and (Test-Path -LiteralPath $shortcut.Temporary)) { Remove-Item -LiteralPath $shortcut.Temporary }
    }
}

$expectedRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs\NestLink-v15'))
if (-not [IO.Path]::GetFullPath($InstallDir).Equals($expectedRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Installer root must be the isolated per-user NestLink v15 namespace.' }
$ManagedStateRoot = Join-Path $env:LOCALAPPDATA 'NestLink-v15'
$script:pendingRecovery = $null
$record = Receipt
$instance = InstallationInstance
$effective = EffectiveState $instance
if ($Action -cnotin @('Leave','Abort') -and -not [IO.Path]::GetFullPath($StateDir).Equals([IO.Path]::GetFullPath($ManagedStateRoot),[StringComparison]::OrdinalIgnoreCase) -and -not [IO.Path]::GetFullPath($StateDir).Equals([IO.Path]::GetFullPath($effective),[StringComparison]::OrdinalIgnoreCase)) { throw 'The installer manages only the active default v15 instance; stop custom instances explicitly.' }
if ($Action -cin @('Leave','Abort')) {
    if (-not $ControlDir) { throw 'Release or abort requires the original exact control directory.' }
    $originalState = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ControlDir))
    $instancesRoot = [IO.Path]::GetFullPath((Join-Path $ManagedStateRoot 'instances')).TrimEnd('\')
    $isGeneration = [IO.Path]::GetDirectoryName($originalState).Equals($instancesRoot,[StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($originalState) -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    if (-not $originalState.Equals([IO.Path]::GetFullPath($ManagedStateRoot),[StringComparison]::OrdinalIgnoreCase) -and -not $isGeneration) { throw 'Original maintenance state is outside the default instance namespace.' }
    $StateDir = $originalState
} else { $StateDir = $effective }
if ($Action -ceq 'Resolve') {
    if (-not $ResolvedStateFile -or -not [IO.Path]::IsPathRooted($ResolvedStateFile)) { throw 'An absolute create-new state path output is required.' }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($StateDir)
    $stream = [IO.File]::Open($ResolvedStateFile,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    return
}
if (-not $PayloadDir -and $null -ne $record.current) {
    $PayloadDir = Join-Path $InstallDir ('versions\' + $record.current.directory)
    $PayloadManifestSha256 = $record.current.payload_manifest_sha256
    $UpdateCertificateSha256 = $record.current.update_certificate_sha256
    $WindowsCertificateSha256 = $record.current.windows_certificate_sha256
}

switch ($Action) {
    'Enter' {
        $payload = VerifyPayload $PayloadDir $PayloadManifestSha256 $UpdateCertificateSha256 $WindowsCertificateSha256
        if ($record.current -and $record.current.state_compatibility -cne $payload.Compatibility) { throw 'State format migration requires an explicit backed-up procedure.' }
        $candidate = Join-Path $InstallDir ('versions\' + $payload.Data.version + '-r' + $payload.Data.release_sequence)
        if ((Test-Path -LiteralPath $candidate) -and -not [IO.Path]::GetFullPath($candidate).Equals([IO.Path]::GetFullPath($PayloadDir),[StringComparison]::OrdinalIgnoreCase)) {
            # A retry may adopt only byte-identical signed candidate files.
            # Inno's onlyifdoesntexist leaves those immutable files untouched.
            $null = VerifyPayload $candidate $PayloadManifestSha256 $UpdateCertificateSha256 $WindowsCertificateSha256
        }
        $id = ControlId
        $parent = [IO.Path]::GetDirectoryName($InstallDir)
        if (-not (Test-Path -LiteralPath $parent)) { $null = New-Item -ItemType Directory -Path $parent }
        # Copy only the already verified controller so uninstall never keeps
        # an installed executable open. Use a private fresh temporary folder.
        $temporary = Join-Path ([IO.Path]::GetTempPath()) ('NestLink-maintenance-' + $id)
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true,$false)
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $security.SetOwner($sid)
        foreach ($principal in @($sid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        }
        $null = [IO.Directory]::CreateDirectory($temporary,$security)
        $daemon = Join-Path $temporary 'nestlink-daemon.exe'
        [IO.File]::Copy((Join-Path $PayloadDir 'nestlink-daemon.exe'),$daemon,$false)
        Signature $daemon $WindowsCertificateSha256
        # All generated paths are trusted absolute paths without quotes. An
        # installer accepts no path/program/arguments from downloaded metadata.
        foreach ($path in @($StateDir,$ControlDir,$InstallDir,$daemon)) { if ($path.Contains('"')) { throw 'A generated path contains a quote.' } }
        $arguments = 'maintenance --state-dir "' + $StateDir + '" --control-dir "' + $ControlDir + '" --installation-dir "' + $InstallDir + '" --timeout-seconds 90 --hold-seconds 1800'
        $controller = Start-Process -FilePath $daemon -ArgumentList $arguments -WindowStyle Hidden -PassThru
        $deadline = [Diagnostics.Stopwatch]::StartNew()
        while ($deadline.Elapsed.TotalSeconds -lt 100) {
            $controller.Refresh()
            if ($controller.HasExited) { throw 'Native maintenance owner exited before confirming cleanup.' }
            if (Test-Path -LiteralPath (Join-Path $ControlDir 'ready.json')) { break }
            Start-Sleep -Milliseconds 100
        }
        WriteNew (Join-Path $ControlDir 'installer-owner.json') ([ordered]@{temporary_directory=$temporary; controller_pid=$controller.Id; controller_start_ticks=$controller.StartTime.ToUniversalTime().Ticks})
        EnsureReady
        # State/receipt reads before the native gate were only discovery. A
        # concurrent completed installer may have changed their generation.
        $script:pendingRecovery = $null
        $record = Receipt
        $instance = InstallationInstance
        if (-not [IO.Path]::GetFullPath((EffectiveState $instance)).Equals([IO.Path]::GetFullPath($StateDir),[StringComparison]::OrdinalIgnoreCase)) { throw 'Installation generation changed before maintenance admission.' }
        if ($record.current -and $record.current.state_compatibility -cne $payload.Compatibility) { throw 'State format changed before maintenance admission.' }
        RecoverInstanceTransaction
        $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.Name -cin @('nestlink-desktop.exe','nestlink-daemon.exe') -and $_.ExecutablePath -and $_.ExecutablePath.StartsWith($InstallDir + '\',[StringComparison]::OrdinalIgnoreCase) })
        if ($processes.Count) { throw 'Another custom v15 instance is still running; stop it before changing this installation.' }
    }
    'Commit' {
        EnsureReady
        $payload = VerifyPayload $PayloadDir $PayloadManifestSha256 $UpdateCertificateSha256 $WindowsCertificateSha256
        if ($record.current -and $record.current.update_certificate_sha256 -cne $UpdateCertificateSha256) { throw 'Implicit update-key rotation is forbidden.' }
        $directory = $payload.Data.version + '-r' + $payload.Data.release_sequence
        if (-not [IO.Path]::GetFullPath($PayloadDir).Equals((Join-Path $InstallDir ('versions\' + $directory)),[StringComparison]::OrdinalIgnoreCase)) { throw 'Payload is outside the fixed version directory.' }
        $current = [ordered]@{directory=$directory; version=$payload.Data.version; sequence=$payload.Data.release_sequence; source_revision=$payload.Data.source_revision; payload_manifest_sha256=$PayloadManifestSha256; update_certificate_sha256=$UpdateCertificateSha256; windows_certificate_sha256=$WindowsCertificateSha256; state_compatibility=$payload.Compatibility}
        CommitRecord (UpdateRecord $record $current $instance $script:maintenanceRecovery)
    }
    'Rollback' {
        if (-not $record.previous -or -not $record.current -or $record.previous.state_compatibility -cne $record.current.state_compatibility) { throw 'No compatible previously accepted version is available.' }
        $ControlDir = Join-Path $StateDir ('maintenance-' + [guid]::NewGuid().ToString())
        & $PSCommandPath -Action Enter -StateDir $StateDir -ControlDir $ControlDir
        $completed = $false
        try {
            EnsureReady
            $script:pendingRecovery = $null
            $record = Receipt
            $instance = InstallationInstance
            if (-not [IO.Path]::GetFullPath((EffectiveState $instance)).Equals([IO.Path]::GetFullPath($StateDir),[StringComparison]::OrdinalIgnoreCase) -or -not $record.previous -or -not $record.current -or $record.previous.state_compatibility -cne $record.current.state_compatibility) { throw 'Accepted rollback generation or payload changed before maintenance admission.' }
            $old = $record.previous
            $directory = Join-Path $InstallDir ('versions\' + $old.directory)
            $null = VerifyPayload $directory $old.payload_manifest_sha256 $old.update_certificate_sha256 $old.windows_certificate_sha256
            EnsureReady
            CommitRecord ([ordered]@{schema_version=1; current=$old; previous=$record.current; maximum_sequence=$record.maximum_sequence; maximum_accepted=$record.maximum_accepted; instance=$instance})
            $completed = $true
        } finally {
            $releaseAction = if ($completed) { 'Leave' } else { 'Abort' }
            & $PSCommandPath -Action $releaseAction -StateDir $StateDir -ControlDir $ControlDir
        }
    }
    'Uninstall' {
        EnsureReady
        if ($null -eq $instance -or -not $instance.active) { throw 'No active accepted installation to uninstall.' }
        $retired = [ordered]@{schema_version=1; namespace='NestLink-v15'; instance_id=$instance.instance_id; active=$false}
        CommitRecord ([ordered]@{schema_version=1; current=$null; previous=$record.current; maximum_sequence=$record.maximum_sequence; maximum_accepted=$record.maximum_accepted; instance=$retired})
        $shortcut = Join-Path ([Environment]::GetFolderPath('Programs')) 'NestLink v15.lnk'
        if (Test-Path -LiteralPath $shortcut) { Remove-Item -LiteralPath $shortcut }
        # Inno removes only its registered binaries. User state, immutable
        # receipts, pinned trust and backups are deliberately retained.
    }
    { $_ -cin @('Leave','Abort') } {
        $id = ControlId
        $abandon = $Action -ceq 'Abort'
        $message = if ($abandon) { 'abandon' } else { 'release' }
        $statusName = if ($abandon) { 'abandoned' } else { 'released' }
        $statusPath = Join-Path $ControlDir ($statusName + '.json')
        WriteNew (Join-Path $ControlDir 'release.json') ([ordered]@{schema_version=1; control_id=$id; action=$message})
        $deadline = [Diagnostics.Stopwatch]::StartNew()
        while ($deadline.Elapsed.TotalSeconds -lt 10 -and -not (Test-Path -LiteralPath $statusPath)) { Start-Sleep -Milliseconds 100 }
        $released = ReadJson $statusPath
        if ($released.control_id -cne $id -or $released.state -cne $statusName) { throw 'Native maintenance completion was not confirmed.' }
        $owner = ReadJson (Join-Path $ControlDir 'installer-owner.json')
        # Wait for the exact process created by Enter, without killing it.
        $controller = Get-Process -Id $owner.controller_pid -ErrorAction SilentlyContinue
        if ($controller -and $controller.StartTime.ToUniversalTime().Ticks -eq $owner.controller_start_ticks -and -not $controller.WaitForExit(10000)) { throw 'Controller process exit is still pending.' }
        if ($abandon) { break } # Keep the control evidence and both durable fences.
        $temporary = [IO.Path]::GetFullPath($owner.temporary_directory)
        if (-not $temporary.Equals((Join-Path ([IO.Path]::GetTempPath()) ('NestLink-maintenance-' + $id)),[StringComparison]::OrdinalIgnoreCase)) { throw 'Temporary owner path differs.' }
        Remove-Item -LiteralPath (Join-Path $temporary 'nestlink-daemon.exe')
        Remove-Item -LiteralPath $temporary
        foreach ($name in @('ready.json','release.json','released.json','installer-owner.json')) { $null = PlainFile (Join-Path $ControlDir $name); Remove-Item -LiteralPath (Join-Path $ControlDir $name) }
        Remove-Item -LiteralPath $ControlDir
    }
}
