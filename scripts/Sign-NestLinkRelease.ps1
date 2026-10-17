[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Path)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# This entry point is invoked only by the protected manual release workflow.
# Secret values remain in process memory; the SDK receives a public thumbprint.
$resolved = (Resolve-Path -LiteralPath $Path).ProviderPath
if (-not [IO.File]::Exists($resolved) -or ([IO.File]::GetAttributes($resolved) -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'A regular, non-reparse PE file is required.'
}
$pfx = [Environment]::GetEnvironmentVariable('NESTLINK_WINDOWS_PFX')
$passwordText = [Environment]::GetEnvironmentVariable('NESTLINK_WINDOWS_PFX_PASSWORD')
$expected = [Environment]::GetEnvironmentVariable('NESTLINK_WINDOWS_CERTIFICATE_SHA256')
$timestamp = [Environment]::GetEnvironmentVariable('NESTLINK_WINDOWS_TIMESTAMP_URL')
if (-not $pfx -or -not $passwordText -or $expected -cnotmatch '^[0-9a-f]{64}$' -or $timestamp -cnotmatch '^https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._/-]*)?$') {
    throw 'Fixed Windows signing input, certificate pin, and HTTPS timestamp endpoint must be enrolled.'
}
if (-not [IO.File]::Exists($pfx) -or ([IO.File]::GetAttributes($pfx) -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'The enrolled PFX is not a regular file.'
}
$sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$sdkVersions = @(Get-ChildItem -LiteralPath $sdkRoot -Directory | Where-Object { $_.Name -match '^10\.0\.[0-9]+\.0$' } | Sort-Object { [version]$_.Name } -Descending)
$signTool = $null
foreach ($version in $sdkVersions) {
    $candidate = Join-Path $version.FullName 'x64\signtool.exe'
    if ([IO.File]::Exists($candidate)) { $signTool = $candidate; break }
}
if (-not $signTool) { throw 'The Windows SDK x64 signtool is unavailable.' }
$collection = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
try {
    # .NET Framework's collection Import overload accepts String, not
    # SecureString. Keep the value in memory only, clear it immediately, and
    # never pass a PFX password to the SDK command line.
    $collection.Import($pfx, $passwordText, [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
}
finally { $passwordText = $null }
$selected = $null
$hasher = [Security.Cryptography.SHA256]::Create()
try {
    foreach ($certificate in $collection) {
        $actual = ([BitConverter]::ToString($hasher.ComputeHash($certificate.RawData))).Replace('-', '').ToLowerInvariant()
        if ($actual -ceq $expected -and $certificate.HasPrivateKey) {
            if ($selected) { throw 'The PFX contains duplicate signing identities.' }
            $selected = $certificate
        }
    }
    if (-not $selected) { throw 'The PFX does not contain the independently pinned signing identity.' }
    $codeSigning = $false
    foreach ($extension in $selected.Extensions) {
        if ($extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($oid in $extension.EnhancedKeyUsages) {
                if ($oid.Value -eq '1.3.6.1.5.5.7.3.3') { $codeSigning = $true }
            }
        }
    }
    if (-not $codeSigning) { throw 'The fixed certificate has no Code Signing EKU.' }
    $thumbprint = $selected.Thumbprint
    $existed = Test-Path -LiteralPath (Join-Path 'Cert:\CurrentUser\My' $thumbprint)
    $store = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        $store.Add($selected)
        & $signTool sign /fd SHA256 /td SHA256 /tr $timestamp /sha1 $thumbprint /s My $resolved | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'SDK signing or RFC3161 timestamping failed.' }
        $signature = Get-AuthenticodeSignature -LiteralPath $resolved
        if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or -not $signature.TimeStamperCertificate) {
            throw 'The signed PE does not have trusted Authenticode and a timestamp.'
        }
        $actual = ([BitConverter]::ToString($hasher.ComputeHash($signature.SignerCertificate.RawData))).Replace('-', '').ToLowerInvariant()
        if ($actual -cne $expected) { throw 'The signed PE signer differs from the fixed identity.' }
    }
    finally {
        # Preserve a pre-existing enrollment if an operator intentionally uses
        # this script outside a fresh runner; remove only our new store entry.
        if (-not $existed) { $store.Remove($selected) }
        $store.Close()
    }
}
finally {
    $hasher.Dispose()
    foreach ($certificate in $collection) { $certificate.Dispose() }
}
