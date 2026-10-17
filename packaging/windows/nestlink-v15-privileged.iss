; Optional machine-protected cohort. Business still starts as the local user.
; The installer never launches the daemon, broker, services or network business.
#ifndef Version
  #error Final Version must be provided
#endif
#ifndef ReleaseSequence
  #error Fixed ReleaseSequence must be provided
#endif
#ifndef PayloadDir
  #error Verified PayloadDir must be provided
#endif
#ifndef PayloadManifestSha256
  #error Fixed payload hash must be provided
#endif
#ifndef UpdateCertificateSha256
  #error Independent update signer pin must be provided
#endif
#ifndef WindowsCertificateSha256
  #error Authenticode signer pin must be provided
#endif
#ifndef MaintenanceHelperSha256
  #error Fixed maintenance helper hash must be provided
#endif
#define VersionDirectory Version + "-r" + Str(ReleaseSequence)

[Setup]
AppId={{70BB39CA-15BF-43DE-B851-45525F0B15B0}
AppName=NestLink (optional privileged input)
AppVersion={#Version}
AppPublisher=NestLink
DefaultDirName={commonpf64}\NestLink-v15-Privileged
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBase}
Compression=lzma2
SolidCompression=yes
SetupLogging=yes
UninstallDisplayName=NestLink v15 (optional privileged input)
UninstallFilesDir={app}\uninstall
UninstallLogMode=append
CloseApplications=no
RestartApplications=no
WizardStyle=modern
SignTool=NestLinkSigning
SignedUninstaller=yes
SignedUninstallerDir={#PayloadDir}\signed-uninstaller

[Files]
Source: "{#PayloadDir}\nestlink-daemon.exe"; Flags: dontcopy
Source: "{#PayloadDir}\nestlink-desktop.exe"; Flags: dontcopy
Source: "{#PayloadDir}\nestlink-privileged.exe"; Flags: dontcopy
Source: "{#PayloadDir}\payload.json"; Flags: dontcopy
Source: "{#PayloadDir}\payload.p7s"; Flags: dontcopy
Source: "{#PayloadDir}\update.crt"; Flags: dontcopy
Source: "{#PayloadDir}\broker-package.json"; Flags: dontcopy
Source: "{#PayloadDir}\Manage-NestLinkPrivileged.ps1"; Flags: dontcopy
Source: "{#PayloadDir}\nestlink-daemon.exe"; DestDir: "{app}\versions\{#VersionDirectory}"; Flags: onlyifdoesntexist
Source: "{#PayloadDir}\nestlink-desktop.exe"; DestDir: "{app}\versions\{#VersionDirectory}"; Flags: onlyifdoesntexist
Source: "{#PayloadDir}\nestlink-privileged.exe"; DestDir: "{app}\versions\{#VersionDirectory}"; Flags: onlyifdoesntexist
Source: "{#PayloadDir}\payload.json"; DestDir: "{app}\versions\{#VersionDirectory}"; Flags: onlyifdoesntexist
Source: "{#PayloadDir}\payload.p7s"; DestDir: "{app}\versions\{#VersionDirectory}"; Flags: onlyifdoesntexist
Source: "{#PayloadDir}\update.crt"; DestDir: "{app}\versions\{#VersionDirectory}"; Flags: onlyifdoesntexist
Source: "{#PayloadDir}\broker-package.json"; DestDir: "{app}\versions\{#VersionDirectory}"; Flags: onlyifdoesntexist
Source: "{#PayloadDir}\Manage-NestLinkPrivileged.ps1"; DestDir: "{app}\tools"; Flags: ignoreversion

[Code]
var
  Helper: String;
  Entered, Completed, Uninstalling: Boolean;
  InstallMutex: THandle;

function CreateMutex(Attributes: Integer; InitialOwner: Boolean; Name: String): THandle;
  external 'CreateMutexW@kernel32.dll stdcall';
function CloseHandle(Handle: THandle): Boolean;
  external 'CloseHandle@kernel32.dll stdcall';

function Admission: Boolean;
begin
  InstallMutex := CreateMutex(0, False, 'Global\NestLink.v15.Privileged.Install');
  Result := (InstallMutex <> 0) and (DLLGetLastError <> 183);
end;

function InitializeSetup: Boolean;
begin
  Result := Admission;
end;

function PS(Value: String): String;
begin
  StringChangeEx(Value, '''', '''''', True);
  Result := '''' + Value + '''';
end;

function RunHelper(Action, Payload: String; WithPins: Boolean): Boolean;
var
  Script, Arguments: String;
  Code: Integer;
begin
  { Authenticate the exact bounded bytes read into memory before executing
    them. A path hash followed by a second PowerShell read would allow a
    caller-writable temporary file to change between those operations. }
  Script := '$ErrorActionPreference=''Stop'';$f=[IO.File]::Open(' + PS(Helper) +
    ',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{' +
    '$r=[IO.BinaryReader]::new($f);$b=$r.ReadBytes(262145);' +
    'if($b.Length -lt 1 -or $b.Length -gt 262144){throw ''helper budget''};' +
    '$h=[Security.Cryptography.SHA256]::Create();try{' +
    '$v=([BitConverter]::ToString($h.ComputeHash($b))).Replace(''-'','''').ToLowerInvariant()' +
    '}finally{$h.Dispose()};if($v -cne ''{#MaintenanceHelperSha256}''){throw ''helper identity''};' +
    '& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($b))) -Action ' + PS(Action) +
    ' -InstallDir ' + PS(ExpandConstant('{app}')) +
    ' -MaintenanceHelperSha256 ''{#MaintenanceHelperSha256}''';
  if Payload <> '' then Script := Script + ' -PayloadDir ' + PS(Payload);
  if WithPins then Script := Script +
    ' -PayloadManifestSha256 ''{#PayloadManifestSha256}''' +
    ' -UpdateCertificateSha256 ''{#UpdateCertificateSha256}''' +
    ' -WindowsCertificateSha256 ''{#WindowsCertificateSha256}''';
  Script := Script + '}finally{$f.Dispose()}';
  Arguments := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Script + '"';
  Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    Arguments, '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  ExtractTemporaryFile('nestlink-desktop.exe');
  ExtractTemporaryFile('nestlink-daemon.exe');
  ExtractTemporaryFile('nestlink-privileged.exe');
  ExtractTemporaryFile('payload.json');
  ExtractTemporaryFile('payload.p7s');
  ExtractTemporaryFile('update.crt');
  ExtractTemporaryFile('broker-package.json');
  ExtractTemporaryFile('Manage-NestLinkPrivileged.ps1');
  Helper := ExpandConstant('{tmp}\Manage-NestLinkPrivileged.ps1');
  Entered := RunHelper('Prepare', ExpandConstant('{tmp}'), True);
  if not Entered then Result := 'Close NestLink normally in all sessions, then retry. The protected cohort, independent signatures and inactive processes must verify before installation. No process is forced to exit.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    if not RunHelper('Commit', ExpandConstant('{app}\versions\{#VersionDirectory}'), True) then
      RaiseException('Protected package activation failed. The installation remains fenced until the signed setup recovers it.');
    Completed := True;
    MsgBox('NestLink is installed. Open it from the Start menu as your normal user. Approve the optional input broker only through an explicit local UAC action in NestLink.', mbInformation, MB_OK);
  end;
end;

procedure DeinitializeSetup;
begin
  if Entered and not Completed then RunHelper('Abort', '', False);
  if InstallMutex <> 0 then CloseHandle(InstallMutex);
end;

function InitializeUninstall: Boolean;
begin
  Result := Admission;
  if not Result then Exit;
  Helper := ExpandConstant('{app}\tools\Manage-NestLinkPrivileged.ps1');
  Result := RunHelper('BeginUninstall', '', False);
  Entered := Result;
  Uninstalling := True;
  if not Result then MsgBox('Close NestLink normally in every session and retry. The accepted protected cohort could not be verified as stopped.', mbError, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then begin
    if not RunHelper('Uninstall', '', False) then RaiseException('Uninstall admission was lost; installed files and retained user data are preserved.');
    Completed := True;
  end;
end;

procedure DeinitializeUninstall;
begin
  if Uninstalling and Entered and not Completed then RunHelper('Abort', '', False);
  if InstallMutex <> 0 then CloseHandle(InstallMutex);
end;
