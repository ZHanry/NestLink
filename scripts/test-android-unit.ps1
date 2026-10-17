param(
    [switch]$RerunTasks,
    [switch]$NoIncremental,
    [string]$InitScript,
    [string[]]$TestFilter = @(),
    [ValidatePattern('^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$')]
    [string]$UpdateDependencyLocksFor
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$androidProject = Join-Path $repositoryRoot 'apps/android'
$windows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
$gradleArguments = @(
    '-p', 'apps/android',
    ':app:testDebugUnitTest',
    '-x', ':app:buildNestlinkArm64',
    '-x', ':app:buildNestlinkX86_64',
    '-x', ':app:verifyNestlinkArm64',
    '-x', ':app:verifyNestlinkX86_64',
    # Keep compiler lifetime inside this check so its daemon cannot retain a
    # lock on the wrapper's temporary logs after Gradle exits.
    '-Pkotlin.compiler.execution.strategy=in-process',
    '--max-workers=1',
    '--no-daemon'
)
if ($RerunTasks) {
    $gradleArguments += '--rerun-tasks'
}
if ($NoIncremental) {
    # Kotlin caches created before moving a build directory or mapping SUBST
    # can retain the old compilation module. Recompile Kotlin in one module.
    $gradleArguments += '-Pkotlin.incremental=false'
}
if ($InitScript) {
    $resolvedInitScript = [System.IO.Path]::GetFullPath($InitScript)
    if (-not [System.IO.File]::Exists($resolvedInitScript)) {
        throw "Gradle init script does not exist: $resolvedInitScript"
    }
    $gradleArguments += @('--init-script', $resolvedInitScript)
}
if ($UpdateDependencyLocksFor) {
    $gradleArguments += @('--update-locks', $UpdateDependencyLocksFor)
}
foreach ($filter in $TestFilter) {
    if ([string]::IsNullOrWhiteSpace($filter)) {
        throw 'Test filters must not be empty.'
    }
    $gradleArguments += @('--tests', $filter)
}

$exitCode = 1
$pushedLocation = $false
$temporaryDrive = $null
try {
    if ($windows) {
        $occupiedLetters = [System.IO.Directory]::GetLogicalDrives() |
            ForEach-Object { $_.Substring(0, 1).ToUpperInvariant() }
        $temporaryDrive = @('Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S', 'R', 'Q', 'P', 'O', 'N', 'M', 'L', 'K', 'J', 'I', 'H', 'G', 'F', 'E', 'D') |
            Where-Object { $_ -notin $occupiedLetters } |
            Select-Object -First 1
        if (-not $temporaryDrive) {
            throw 'No unused drive letter is available for the temporary Gradle path mapping.'
        }

        $subst = Join-Path $env:SystemRoot 'System32/subst.exe'
        & $subst "${temporaryDrive}:" $repositoryRoot
        if ($LASTEXITCODE -ne 0) {
            throw "Could not create a temporary drive mapping for $repositoryRoot."
        }

        Push-Location -LiteralPath "${temporaryDrive}:\"
        $pushedLocation = $true
        $gradle = 'apps/android/gradlew.bat'
        Write-Host 'Running Android unit tests with native Cargo build tasks excluded; CARGO_TARGET_DIR is inherited unchanged.'
        & $gradle @gradleArguments
        $exitCode = $LASTEXITCODE
    }
    else {
        Push-Location -LiteralPath $repositoryRoot
        $pushedLocation = $true
        $gradle = 'apps/android/gradlew'
        Write-Host 'Running Android unit tests with native Cargo build tasks excluded; CARGO_TARGET_DIR is inherited unchanged.'
        & bash $gradle @gradleArguments
        $exitCode = $LASTEXITCODE
    }
}
catch {
    Write-Error $_
    $exitCode = 1
}
finally {
    if ($pushedLocation) {
        Pop-Location
    }
    if ($temporaryDrive) {
        $subst = Join-Path $env:SystemRoot 'System32/subst.exe'
        & $subst "${temporaryDrive}:" '/D'
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not remove temporary drive mapping ${temporaryDrive}:."
            if ($exitCode -eq 0) {
                $exitCode = 1
            }
        }
    }
}

exit $exitCode
