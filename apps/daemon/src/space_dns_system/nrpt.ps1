$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::Error.WriteLine('NestLink NRPT: script entered')
# Set the constrained module path before the first cmdlet can trigger module
# discovery. BCL constructors need no inherited user/module search settings.
$env:PSModulePath = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\Modules')
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::Error.WriteLine('NestLink NRPT: bootstrap complete')
$request = $env:NESTLINK_DNS_REQUEST | ConvertFrom-Json
Remove-Item Env:NESTLINK_DNS_REQUEST
[Console]::Error.WriteLine('NestLink NRPT: request parsed')
# Import only the Microsoft provider used by this operation. Importing the
# aggregate DnsClient manifest also loads every unrelated DNS adapter/cache/DoH
# module and type/format file on each short-lived owner command. Keep the same
# DNS cmdlets, trusted absolute system paths and bounded cold-start deadline.
$dnsDirectory = Join-Path $env:PSModulePath 'DnsClient'
[Console]::Error.WriteLine('NestLink NRPT: importing constrained provider')
if ([string]$request.action -ceq 'query') {
    Import-Module -Name (Join-Path $dnsDirectory 'DnsLookup.dll') -ErrorAction Stop
} else {
    Import-Module -Name (Join-Path $dnsDirectory 'PS_DnsClientNRPTRule_v1.0.0.cdxml') -ErrorAction Stop
    if ([string]$request.action -cin @('preflight', 'install')) {
        Import-Module -Name (Join-Path $dnsDirectory 'PS_DnsClientNrptPolicy_v1.0.0.cdxml') -ErrorAction Stop
    }
}
[Console]::Error.WriteLine('NestLink NRPT: provider imported')
function Emit($value) { ConvertTo-Json -InputObject $value -Depth 20 -Compress }
function View($rule) {
    [ordered]@{
        name = [string]$rule.Name
        namespace = @($rule.Namespace | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object)
        name_servers = @($rule.NameServers | ForEach-Object { [string]$_ } | Sort-Object)
        display_name = [string]$rule.DisplayName
        comment = [string]$rule.Comment
        da_enable = [bool]$rule.DAEnable
        da_name_servers = @($rule.DANameServers | ForEach-Object { [string]$_ } | Sort-Object)
        da_proxy_type = [string]$rule.DAProxyType
        da_proxy_server = [string]$rule.DAProxyServerName
        da_ipsec = [bool]$rule.DAIPsecRequired
        da_encryption = [string]$rule.DAIPsecEncryptionType
        dnssec_enable = [bool]$rule.DnsSecEnable
        dnssec_validation = [bool]$rule.DnsSecValidationRequired
        dnssec_ipsec = [bool]$rule.DnsSecIPsecRequired
        dnssec_encryption = [string]$rule.DnsSecIPsecEncryptionType
        name_encoding = [string]$rule.NameEncoding
        ipsec_authority = [string]$rule.IPsecTrustAuthority
    }
}
function Same-Json($left, $right) {
    # Both objects use the fixed View property order. The expected object is
    # rebuilt in that order before comparison, independent of JSON key order.
    $normalized = [ordered]@{}
    foreach ($key in $left.Keys) { $normalized[$key] = $right.$key }
    (ConvertTo-Json -InputObject $left -Depth 20 -Compress) -ceq (ConvertTo-Json -InputObject $normalized -Depth 20 -Compress)
}
function Safe-Owned($view) {
    $marker = 'NestLink:split-dns:v1:' + $request.plan.owner_id
    ($view.display_name -ceq $marker) -and ($view.comment -ceq $marker) -and
    ($view.namespace.Count -eq 1) -and ($view.namespace[0] -ceq ('.' + $request.plan.suffix)) -and
    ($view.name_servers.Count -eq 1) -and ($view.name_servers[0] -ceq '127.0.0.1') -and
    (-not $view.da_enable) -and (-not $view.dnssec_enable) -and (-not $view.dnssec_validation) -and
    (-not $view.da_ipsec) -and (-not $view.dnssec_ipsec) -and
    ($view.name -match '^\{?[0-9a-fA-F-]{36}\}?$')
}
function Owned-Rules {
    $marker = 'NestLink:split-dns:v1:' + $request.plan.owner_id
    @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object {
        ([string]$_.DisplayName -ceq $marker) -or
        (($null -ne $request.expected) -and ([string]$_.Name -ceq [string]$request.expected.name))
    })
}
function Conflicts {
    $suffix = [string]$request.plan.suffix
    $rules = @(Get-DnsClientNrptRule -ErrorAction Stop)
    $effective = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
    if (($rules.Count + $effective.Count) -gt 256) { throw 'NRPT policy observation limit exceeded' }
    foreach ($rule in @($rules) + @($effective)) {
        foreach ($entry in @($rule.Namespace)) {
            $domain = ([string]$entry).Trim('.').ToLowerInvariant()
            if (($domain.Length -gt 0) -and (($domain -ceq $suffix) -or $domain.EndsWith('.' + $suffix) -or $suffix.EndsWith('.' + $domain))) {
                throw 'Another local/GPO/VPN NRPT namespace overlaps this private suffix; no existing rule is replaced'
            }
        }
    }
}
[Console]::Error.WriteLine('NestLink NRPT: dispatching native operation')
switch ([string]$request.action) {
    'baseline' { Emit @(Get-DnsClientNrptRule -ErrorAction Stop | Sort-Object Name | ForEach-Object { View $_ }) }
    'query' {
        $answer = Resolve-DnsName -Name ('os-probe.' + $request.plan.suffix) -Type A -DnsOnly -NoHostsFile -ErrorAction Stop
        # IPAddress is only an alias from DnsCmdlets.Types.ps1xml. This narrow
        # DnsLookup.dll import deliberately omits unrelated manifest modules
        # and type files, so read the actual A record's native IP4Address.
        $addresses = @($answer | Where-Object { [string]$_.Type -eq 'A' } | ForEach-Object {
            $address = [System.Net.IPAddress]::Parse([string]$_.IP4Address)
            if ($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                throw 'System DNS query returned a non-IPv4 A record'
            }
            $address.ToString()
        })
        if ($addresses.Count -eq 0) { throw 'System DNS query returned no IPv4 A records' }
        Emit $addresses
    }
    'test-change' {
        $rules = @(Owned-Rules)
        if ($rules.Count -ne 1) { throw 'Owned rule missing for isolated test' }
        Set-DnsClientNrptRule -Name ([string]$rules[0].Name) -Comment 'isolated-external-change' -ErrorAction Stop
        Emit $true
    }
    'test-restore' {
        $rules = @(Owned-Rules)
        if ($rules.Count -ne 1) { throw 'Owned rule missing for isolated test' }
        Set-DnsClientNrptRule -Name ([string]$rules[0].Name) -Comment ('NestLink:split-dns:v1:' + $request.plan.owner_id) -ErrorAction Stop
        Emit $true
    }
    'preflight' { Conflicts; Emit $true }
    'inspect' {
        $rules = @(Owned-Rules)
        if ($rules.Count -gt 1) { throw 'Duplicate owned NRPT rules; recovery requires operator review' }
        if ($rules.Count -eq 0) { Emit $null } else { Emit (View $rules[0]) }
    }
    'install' {
        Conflicts
        $marker = 'NestLink:split-dns:v1:' + $request.plan.owner_id
        $rule = Add-DnsClientNrptRule -Namespace @('.' + $request.plan.suffix) -NameServers @('127.0.0.1') -DisplayName $marker -Comment $marker -PassThru -ErrorAction Stop
        Emit (View $rule)
    }
    'remove' {
        $rules = @(Owned-Rules)
        if ($rules.Count -gt 1) { throw 'Duplicate owned NRPT rules; no rules were deleted' }
        if ($rules.Count -eq 0) { Emit $true; break }
        $view = View $rules[0]
        if (-not (Safe-Owned $view)) { throw 'NRPT identity or settings changed; preserving rule and recovery journal' }
        if (($null -ne $request.expected) -and (-not (Same-Json $view $request.expected))) { throw 'NRPT settings changed; preserving rule and recovery journal' }
        # Re-read the precise GUID before deletion and compare all policy fields.
        $again = Get-DnsClientNrptRule -Name ([string]$view.name) -ErrorAction Stop
        if (-not (Same-Json $view (View $again))) { throw 'NRPT changed during cleanup; journal retained' }
        Remove-DnsClientNrptRule -Name ([string]$view.name) -Confirm:$false -ErrorAction Stop
        if (@(Owned-Rules).Count -ne 0) { throw 'NRPT removal was not confirmed' }
        Emit $true
    }
    default { throw 'Unsupported constrained DNS operation' }
}
