[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Prepare','Commit','Abort','BeginUninstall','Uninstall','Rollback')][string]$Action,
    [Parameter(Mandatory=$true)][string]$InstallDir,
    [Parameter(Mandatory=$true)][string]$MaintenanceHelperSha256,
    [string]$PayloadDir,
    [string]$PayloadManifestSha256,
    [string]$UpdateCertificateSha256,
    [string]$WindowsCertificateSha256
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Security

# This helper is authenticated in memory by the signed setup before invocation.
# It never starts a daemon, broker, service, command from metadata, or user UI.
function Digest([byte[]]$Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
function FixedHash([string]$Value) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw 'A fixed lowercase SHA-256 is required.' }
}
function Plain([string]$Path, [bool]$Directory=$false) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -ne $Directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'A fixed plain file/directory is required.' }
    return $item
}
function ReadJson([string]$Path) {
    $file = Plain $Path
    if ($file.Length -lt 1 -or $file.Length -gt 262144) { throw 'Metadata exceeds its budget.' }
    return [IO.File]::ReadAllText($Path,[Text.Encoding]::UTF8) | ConvertFrom-Json
}
function FileHash([string]$Path) {
    $null = Plain $Path
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function AtomicJson([string]$Path, $Value) {
    $temporary = $Path + '.new-' + [guid]::NewGuid().ToString('N')
    $raw = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 16 -Compress))
    $stream = [IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($raw,0,$raw.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    SecureFile $temporary
    if (Test-Path -LiteralPath $Path) { $null = Plain $Path; [IO.File]::Replace($temporary,$Path,[NullString]::Value) }
    else { [IO.File]::Move($temporary,$Path) }
    SecureFile $Path
}
function Keys($Value, [string[]]$Expected) {
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count -or @($actual | Where-Object { $_ -cnotin $Expected }).Count -ne 0) { throw 'Unknown or missing fixed metadata fields.' }
}
function Protected([string]$Path, [bool]$Directory=$false) {
    $null = Plain $Path $Directory
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $administrators = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($owner -cnotin $administrators) { throw 'The protected installation must have an administrative owner.' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if (([long]$rule.FileSystemRights -band 0x500D0156) -ne 0 -and $rule.IdentityReference.Value -cnotin $administrators) { throw 'A non-administrator can change the protected installation.' }
    }
}
function SecureDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { Protected $Path $true; return }
    $null = [IO.Directory]::CreateDirectory($Path)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true,$false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::ReadAndExecute,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $Path -AclObject $acl
    Protected $Path $true
}
function SecureFile([string]$Path) {
    $null = Plain $Path
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow)) }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::ReadAndExecute,[Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $Path -AclObject $acl
    Protected $Path
}
function Signature([string]$Path, [string]$Pin) {
    FixedHash $Pin
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or (Digest $signature.SignerCertificate.RawData) -cne $Pin -or $null -eq $signature.TimeStamperCertificate) { throw 'Authenticode trust, fixed signer or timestamp did not verify.' }
    $codeSigning = $false
    foreach ($extension in $signature.SignerCertificate.Extensions) {
        if ($extension.Oid.Value -eq '2.5.29.37') {
            $usage = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($extension,$extension.Critical)
            $codeSigning = @($usage.EnhancedKeyUsages | Where-Object { $_.Value -ceq '1.3.6.1.5.5.7.3.3' }).Count -gt 0
        }
    }
    if (-not $codeSigning) { throw 'The signer lacks the code-signing EKU.' }
}
function VerifyPayload([string]$Directory, [string]$Expected, [string]$UpdatePin, [string]$WindowsPin) {
    FixedHash $Expected; FixedHash $UpdatePin; FixedHash $WindowsPin
    if ($UpdatePin -ceq $WindowsPin) { throw 'Update and Windows signing identities must be distinct.' }
    $null = Plain $Directory $true
    $manifest = Join-Path $Directory 'payload.json'
    if ((FileHash $manifest) -cne $Expected) { throw 'Payload statement differs from the signed setup.' }
    $raw = [IO.File]::ReadAllBytes($manifest)
    if ($raw.Length -gt 262144) { throw 'Payload statement exceeds its budget.' }
    $signature = Join-Path $Directory 'payload.p7s'
    if ((Plain $signature).Length -gt 262144) { throw 'CMS signature exceeds its budget.' }
    $certificate = Join-Path $Directory 'update.crt'
    if ((Plain $certificate).Length -gt 32768) { throw 'Public certificate exceeds its budget.' }
    $public = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate)
    try { if ((Digest $public.RawData) -cne $UpdatePin -or $public.HasPrivateKey) { throw 'Public update certificate differs from the enrolled identity.' } }
    finally { $public.Dispose() }
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($raw),$true)
    $cms.Decode([IO.File]::ReadAllBytes($signature))
    if ($cms.SignerInfos.Count -ne 1 -or $null -eq $cms.SignerInfos[0].Certificate -or (Digest $cms.SignerInfos[0].Certificate.RawData) -cne $UpdatePin) { throw 'Independent CMS update signer differs.' }
    $cms.CheckSignature($true)
    $data = ReadJson $manifest
    Keys $data @('schema_version','product','purpose','version','release_sequence','source_revision','artifacts')
    if ($data.schema_version -ne 1 -or $data.product -cne 'NestLink-v15' -or $data.purpose -cne 'native-payload' -or $data.version -cnotmatch '^15\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or $data.release_sequence -is [bool] -or $data.release_sequence -lt 1 -or $data.release_sequence -gt 9007199254740991 -or $data.source_revision -cnotmatch '^[0-9a-f]{40}$') { throw 'Invalid fixed v15 payload identity.' }
    $selected = @($data.artifacts | Where-Object { $_.platform -ceq 'windows' -and $_.architecture -ceq 'x86_64' -and $_.format -ceq 'executable' -and $_.role -cin @('desktop','daemon','privileged') })
    if ($selected.Count -ne 3) { throw 'Exactly desktop, daemon and input broker are required.' }
    $names = @(); $compatibility = @(); $hashes = @{}
    foreach ($item in $selected) {
        $name = 'nestlink-' + $item.role + '.exe'
        if ($item.path -cne ('windows-x86_64/' + $name) -or $name -cin $names -or $item.windows_certificate_sha256 -cne $WindowsPin) { throw 'Unexpected or duplicated Windows executable identity.' }
        FixedHash $item.sha256
        if ($item.state_compatibility -cnotmatch '^[a-z0-9][a-z0-9._-]{0,95}$' -or $item.bytes -lt 1 -or $item.bytes -gt 536870912) { throw 'Invalid executable size or state compatibility.' }
        $path = Join-Path $Directory $name
        if ((Plain $path).Length -ne $item.bytes -or (FileHash $path) -cne $item.sha256) { throw 'Executable bytes differ from the CMS payload.' }
        Signature $path $WindowsPin
        $names += $name; $compatibility += $item.state_compatibility; $hashes[$item.role] = $item.sha256
    }
    if (@($compatibility | Select-Object -Unique).Count -ne 1) { throw 'Inconsistent protected cohort state compatibility.' }
    $policy = ReadJson (Join-Path $Directory 'broker-package.json')
    $expectedPolicy = [ordered]@{schema_version=1;version=$data.version;release_sequence=$data.release_sequence;source_revision=$data.source_revision;desktop_sha256=$hashes.desktop;daemon_sha256=$hashes.daemon;privileged_sha256=$hashes.privileged;payload_manifest_sha256=$Expected;update_certificate_sha256=$UpdatePin;windows_certificate_sha256=$WindowsPin}
    Keys $policy @($expectedPolicy.Keys)
    foreach ($field in $expectedPolicy.Keys) { if ($policy.$field -cne $expectedPolicy[$field]) { throw 'Broker package policy differs from the independently verified payload.' } }
    if ((FileHash $manifest) -cne $Expected) { throw 'Payload changed during verification.' }
    return [pscustomobject]@{directory=($data.version + '-r' + $data.release_sequence);version=$data.version;release_sequence=$data.release_sequence;source_revision=$data.source_revision;payload_manifest_sha256=$Expected;update_certificate_sha256=$UpdatePin;windows_certificate_sha256=$WindowsPin;state_compatibility=$compatibility[0]}
}
function Receipt {
    $path = Join-Path $InstallDir 'installation.json'
    if (-not (Test-Path -LiteralPath $path)) { return [pscustomobject]@{schema_version=1;current=$null;previous=$null;maximum_sequence=0;maximum_accepted=$null;instance_id=$null;active=$false} }
    Protected $path
    $value = ReadJson $path
    Keys $value @('schema_version','current','previous','maximum_sequence','maximum_accepted','instance_id','active')
    if ($value.schema_version -ne 1 -or $value.maximum_sequence -lt 0 -or $value.maximum_sequence -gt 9007199254740991 -or $value.active -isnot [bool] -or ($null -ne $value.instance_id -and $value.instance_id -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')) { throw 'Invalid protected installation receipt.' }
    if ($value.active -and ($null -eq $value.current -or $null -eq $value.instance_id)) { throw 'An active protected installation needs its accepted cohort and generation.' }
    foreach ($entry in @($value.current,$value.previous,$value.maximum_accepted)) {
        if ($null -eq $entry) { continue }
        Keys $entry @('directory','version','release_sequence','source_revision','payload_manifest_sha256','update_certificate_sha256','windows_certificate_sha256','state_compatibility')
        if ($entry.version -cnotmatch '^15\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or $entry.release_sequence -lt 1 -or $entry.release_sequence -gt $value.maximum_sequence -or $entry.directory -cne ($entry.version + '-r' + $entry.release_sequence) -or $entry.source_revision -cnotmatch '^[0-9a-f]{40}$') { throw 'Invalid accepted version identity.' }
        FixedHash $entry.payload_manifest_sha256; FixedHash $entry.update_certificate_sha256; FixedHash $entry.windows_certificate_sha256
    }
    if ($value.maximum_sequence -gt 0 -and ($null -eq $value.maximum_accepted -or $value.maximum_accepted.release_sequence -ne $value.maximum_sequence)) { throw 'The latest accepted sequence has no retained exact identity.' }
    return $value
}
function SameAccepted($Left, $Right) {
    if ($null -eq $Left -or $null -eq $Right) { return $false }
    foreach ($field in @('directory','version','release_sequence','source_revision','payload_manifest_sha256','update_certificate_sha256','windows_certificate_sha256','state_compatibility')) { if ($Left.$field -cne $Right.$field) { return $false } }
    return $true
}
function AcceptUpdate($Record, $Current) {
    if ($Current.release_sequence -lt $Record.maximum_sequence -or ($Current.release_sequence -eq $Record.maximum_sequence -and -not (SameAccepted $Current $Record.maximum_accepted))) { throw 'A replayed or downgraded package cannot replace the accepted protected cohort.' }
    if ($null -ne $Record.maximum_accepted -and $Record.maximum_accepted.update_certificate_sha256 -cne $Current.update_certificate_sha256) { throw 'The retained independent update trust anchor changed.' }
}
function Quiescent {
    $prefix = $InstallDir.TrimEnd('\') + '\versions\'
    foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='nestlink-desktop.exe' OR Name='nestlink-daemon.exe' OR Name='nestlink-privileged.exe'")) {
        if ([string]::IsNullOrEmpty($process.ExecutablePath)) { throw 'A matching process image could not be authenticated; close NestLink normally and retry.' }
        if ($process.ExecutablePath.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'A protected NestLink cohort is still running. Exit NestLink normally in each session before retrying; no process was forced to exit.' }
    }
}
function Fence {
    $path = Join-Path $InstallDir 'installation-incomplete.json'
    AtomicJson $path ([ordered]@{schema_version=1;namespace='NestLink-v15'})
    Protected $path
}
function Unfence { Remove-Item -LiteralPath (Join-Path $InstallDir 'installation-incomplete.json') -ErrorAction Stop }
function Instance($Record) {
    AtomicJson (Join-Path $InstallDir 'installation-instance.json') ([ordered]@{schema_version=1;namespace='NestLink-v15';instance_id=$Record.instance_id;active=$Record.active})
    Protected (Join-Path $InstallDir 'installation-instance.json')
}
function Shortcut($Entry) {
    $menu = [Environment]::GetFolderPath('CommonPrograms')
    $path = Join-Path $menu 'NestLink v15 (privileged input).lnk'
    if ($null -eq $Entry) { if (Test-Path -LiteralPath $path) { $null = Plain $path; Remove-Item -LiteralPath $path }; return }
    $temporary = Join-Path $menu ('NestLink-privileged-new-' + [guid]::NewGuid().ToString('N') + '.lnk')
    $shell = New-Object -ComObject WScript.Shell
    $link = $null
    try {
        $link = $shell.CreateShortcut($temporary)
        $link.TargetPath = Join-Path $InstallDir ('versions\' + $Entry.directory + '\nestlink-desktop.exe')
        $link.WorkingDirectory = [IO.Path]::GetDirectoryName($link.TargetPath)
        $link.Description = 'NestLink v15 with optional local UAC input approval'
        $link.Save()
    } finally { if ($null -ne $link) { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($link) }; $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
    if (Test-Path -LiteralPath $path) { $null = Plain $path; [IO.File]::Replace($temporary,$path,[NullString]::Value) }
    else { [IO.File]::Move($temporary,$path) }
}
function VerifyInstalled($Entry) {
    $directory = Join-Path $InstallDir ('versions\' + $Entry.directory)
    Protected (Join-Path $InstallDir 'versions') $true
    Protected $directory $true
    foreach ($name in @('nestlink-desktop.exe','nestlink-daemon.exe','nestlink-privileged.exe','payload.json','payload.p7s','update.crt','broker-package.json')) { Protected (Join-Path $directory $name) }
    $actual = VerifyPayload $directory $Entry.payload_manifest_sha256 $Entry.update_certificate_sha256 $Entry.windows_certificate_sha256
    if (-not (SameAccepted $actual $Entry)) { throw 'Installed protected cohort differs from its accepted record.' }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if (-not [Environment]::Is64BitProcess -or -not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'This optional protected package requires an explicit administrator install.' }
} finally { $identity.Dispose() }
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$expectedRoot = [IO.Path]::Combine($programFiles,'NestLink-v15-Privileged')
if (-not [IO.Path]::GetFullPath($InstallDir).TrimEnd('\').Equals($expectedRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'The protected install path is fixed by the operating system.' }
$InstallDir = $expectedRoot
FixedHash $MaintenanceHelperSha256
Protected $programFiles $true
$incoming = $null
if ($Action -cin @('Prepare','Commit')) { $incoming = VerifyPayload $PayloadDir $PayloadManifestSha256 $UpdateCertificateSha256 $WindowsCertificateSha256 }
SecureDirectory $InstallDir
SecureDirectory (Join-Path $InstallDir 'versions')
SecureDirectory (Join-Path $InstallDir 'tools')
$lockPath = Join-Path $InstallDir 'installation-admission.lock'
$lock = [IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
try {
    SecureFile $lockPath
    $lock.Lock(0,1)
    Protected $lockPath
    if ($lock.Length -ne 0) { throw 'Installation admission lock changed.' }
    AtomicJson (Join-Path $InstallDir 'installation-v15.json') ([ordered]@{schema_version=1;namespace='NestLink-v15'})
    $record = Receipt
    if ($Action -cin @('Prepare','Commit')) { AcceptUpdate $record $incoming }
    if ($Action -eq 'Prepare' -or $Action -eq 'BeginUninstall') {
        $alreadyFenced = Test-Path -LiteralPath (Join-Path $InstallDir 'installation-incomplete.json')
        Fence
        try { Quiescent }
        catch { if (-not $alreadyFenced) { Unfence }; throw }
        if ($Action -eq 'Prepare') { SecureDirectory (Join-Path $InstallDir ('versions\' + $incoming.directory)) }
        if ($Action -eq 'BeginUninstall') { if ($null -eq $record.current) { throw 'No accepted protected installation exists.' }; VerifyInstalled $record.current }
    } elseif ($Action -eq 'Commit') {
        if (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'installation-incomplete.json'))) { throw 'The protected installation fence was lost.' }
        $target = Join-Path $InstallDir ('versions\' + $incoming.directory)
        if (-not [IO.Path]::GetFullPath($PayloadDir).Equals($target,[StringComparison]::OrdinalIgnoreCase)) { throw 'Activation must inspect the exact installed protected version.' }
        Quiescent
        foreach ($name in @('nestlink-desktop.exe','nestlink-daemon.exe','nestlink-privileged.exe','payload.json','payload.p7s','update.crt','broker-package.json')) { SecureFile (Join-Path $target $name) }
        $installedHelper = Join-Path $InstallDir 'tools\Manage-NestLinkPrivileged.ps1'
        SecureFile $installedHelper
        if ((FileHash $installedHelper) -cne $MaintenanceHelperSha256) { throw 'Installed maintenance helper differs from the authenticated setup owner.' }
        VerifyInstalled $incoming
        $instance = if ($record.active) { $record.instance_id } else { [guid]::NewGuid().ToString() }
        $previous = if (SameAccepted $record.current $incoming) { $record.previous } else { $record.current }
        $next = [pscustomobject]@{schema_version=1;current=$incoming;previous=$previous;maximum_sequence=$incoming.release_sequence;maximum_accepted=$incoming;instance_id=$instance;active=$true}
        AtomicJson (Join-Path $InstallDir 'installation.json') $next
        Instance $next
        Shortcut $incoming
        Unfence
    } elseif ($Action -eq 'Abort') {
        if ($null -ne $record.current -and $record.active) { Quiescent; VerifyInstalled $record.current; Instance $record; Shortcut $record.current; Unfence }
        # A cancelled first install remains fenced until the signed setup retries.
    } elseif ($Action -eq 'Rollback') {
        if (-not $record.active -or $null -eq $record.previous -or $record.current.state_compatibility -cne $record.previous.state_compatibility) { throw 'No compatible accepted rollback cohort exists.' }
        Fence; Quiescent; VerifyInstalled $record.previous
        $old = $record.current; $record.current = $record.previous; $record.previous = $old
        AtomicJson (Join-Path $InstallDir 'installation.json') $record
        Instance $record; Shortcut $record.current; Unfence
    } elseif ($Action -eq 'Uninstall') {
        if (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'installation-incomplete.json'))) { throw 'Uninstall admission was lost.' }
        Quiescent
        if ($null -eq $record.current) { throw 'No accepted protected cohort exists.' }
        VerifyInstalled $record.current
        $record.active = $false
        AtomicJson (Join-Path $InstallDir 'installation.json') $record
        Instance $record
        Shortcut $null
        # Retain the admission fence, public generations and trust receipt.
        # Inno deletes only files installed by this AppId, never user data.
    }
    [ordered]@{action=$Action;result='verified';business_process_started=$false;forced_exit=$false} | ConvertTo-Json -Compress
} finally { $lock.Dispose() }
