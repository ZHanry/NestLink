; v15 per-user setup. Every version is immutable; the signed setup contains
; the verified payload, independent CMS statement and maintenance controller.
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
#define VersionDirectory Version + "-r" + Str(ReleaseSequence)

[Setup]
AppId={{6EF10E6F-15D2-43BF-9EA0-E2F65A2B0D15}
AppName=NestLink
AppVersion={#Version}
AppPublisher=NestLink
DefaultDirName={localappdata}\Programs\NestLink-v15
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBase}
Compression=lzma2
SolidCompression=yes
SetupLogging=yes
UninstallDisplayName=NestLink v15
UninstallFilesDir={app}\uninstall
UninstallLogMode=append
CloseApplications=no
RestartApplications=no
WizardStyle=modern
SetupIconFile=..\..\brand\nestlink.ico
WizardImageFile=..\..\brand\wizard-large.bmp
WizardSmallImageFile=..\..\brand\wizard-small.bmp
ShowLanguageDialog=yes
LanguageDetectionMethod=uilanguage
SignTool=NestLinkSigning
SignedUninstaller=yes
SignedUninstallerDir={#PayloadDir}\signed-uninstaller

[Languages]
Name: "chinesesimp"; MessagesFile: "..\windows\languages\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#PayloadDir}\nestlink-daemon.exe"; Flags: dontcopy
Source: "{#PayloadDir}\nestlink-desktop.exe"; Flags: dontcopy
Source: "{#PayloadDir}\payload.json"; Flags: dontcopy
Source: "{#PayloadDir}\payload.p7s"; Flags: dontcopy
Source: "{#PayloadDir}\update.crt"; Flags: dontcopy
Source: "{#PayloadDir}\Manage-NestLink.ps1"; Flags: dontcopy
Source: "{#PayloadDir}\nestlink-daemon.exe"; DestDir: "{app}\versions\{#VersionDirectory}"; Flags: onlyifdoesntexist
Source: "{#PayloadDir}\nestlink-desktop.exe"; DestDir: "{app}\versions\{#VersionDirectory}"; Flags: onlyifdoesntexist
Source: "{#PayloadDir}\payload.json"; DestDir: "{app}\versions\{#VersionDirectory}"; Flags: onlyifdoesntexist
Source: "{#PayloadDir}\payload.p7s"; DestDir: "{app}\versions\{#VersionDirectory}"; Flags: onlyifdoesntexist
Source: "{#PayloadDir}\update.crt"; DestDir: "{app}\versions\{#VersionDirectory}"; Flags: onlyifdoesntexist
Source: "{#PayloadDir}\Manage-NestLink.ps1"; DestDir: "{app}\tools"; Flags: ignoreversion

[Run]
Filename: "{app}\versions\{#VersionDirectory}\nestlink-desktop.exe"; Parameters: "--state-dir ""{localappdata}\NestLink-v15"""; Description: "Open NestLink"; Flags: nowait postinstall skipifsilent

[Code]
var
  ControlDirectory, Helper, StateDirectory: String;
  Entered, Released, Completed: Boolean;

function Q(Value: String): String;
begin
  Result := '"' + Value + '"';
end;

function NewControlDirectory: String;
var
  Value: String;
begin
  { Uniqueness only; this is not a credential or signing identity. The native
    owner creates the leaf with a protected user/SYSTEM-only DACL. }
  Value := GetMD5OfString(ExpandConstant('{tmp}') + GetDateTimeString('yyyymmddhhnnsszzz', '', ''));
  Result := StateDirectory + '\maintenance-' +
    Copy(Value,1,8) + '-' + Copy(Value,9,4) + '-' + Copy(Value,13,4) + '-' +
    Copy(Value,17,4) + '-' + Copy(Value,21,12);
end;

function RunHelper(Action, Payload: String; WithPins: Boolean): Boolean;
var
  Arguments: String;
  Code: Integer;
begin
  Arguments := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + Q(Helper) +
    ' -Action ' + Action + ' -InstallDir ' + Q(ExpandConstant('{app}')) +
    ' -StateDir ' + Q(StateDirectory) +
    ' -ControlDir ' + Q(ControlDirectory);
  if Payload <> '' then Arguments := Arguments + ' -PayloadDir ' + Q(Payload);
  if WithPins then Arguments := Arguments +
    ' -PayloadManifestSha256 {#PayloadManifestSha256}' +
    ' -UpdateCertificateSha256 {#UpdateCertificateSha256}' +
    ' -WindowsCertificateSha256 {#WindowsCertificateSha256}';
  Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    Arguments, '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

function ResolveStateDirectory: Boolean;
var
  Arguments, Output: String;
  Raw: AnsiString;
  Code: Integer;
begin
  StateDirectory := ExpandConstant('{localappdata}\NestLink-v15');
  Output := ExpandConstant('{tmp}\nestlink-state-path-') + GetMD5OfString(GetDateTimeString('yyyymmddhhnnsszzz', '', '')) + '.txt';
  Arguments := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + Q(Helper) +
    ' -Action Resolve -InstallDir ' + Q(ExpandConstant('{app}')) +
    ' -StateDir ' + Q(StateDirectory) + ' -ResolvedStateFile ' + Q(Output);
  Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    Arguments, '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
  if Result then Result := LoadStringFromFile(Output, Raw);
  if Result then begin
    StateDirectory := UTF8Decode(Raw);
    Result := (StateDirectory <> '') and (Pos(#13, StateDirectory) = 0) and (Pos(#10, StateDirectory) = 0);
  end;
  if FileExists(Output) then DeleteFile(Output);
end;

procedure ReleaseMaintenance;
var
  Action: String;
begin
  if not Released and FileExists(ControlDirectory + '\ready.json') then begin
    if Completed then Action := 'Leave' else Action := 'Abort';
    if not RunHelper(Action, '', False) then
      RaiseException('Maintenance release is pending. The protected v15 installation remains stopped; retry the signed installer to recover.');
    Released := True;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  ExtractTemporaryFile('nestlink-daemon.exe');
  ExtractTemporaryFile('nestlink-desktop.exe');
  ExtractTemporaryFile('payload.json');
  ExtractTemporaryFile('payload.p7s');
  ExtractTemporaryFile('update.crt');
  ExtractTemporaryFile('Manage-NestLink.ps1');
  Helper := ExpandConstant('{tmp}\Manage-NestLink.ps1');
  if not ResolveStateDirectory then begin
    Result := 'The accepted installation generation is invalid; recover the installation receipt first.';
    Exit;
  end;
  ControlDirectory := NewControlDirectory;
  Entered := RunHelper('Enter', ExpandConstant('{tmp}'), True);
  if not Entered then
    Result := 'NestLink could not confirm graceful cleanup or the fixed signed payload. No process was forced to exit.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    if not RunHelper('Commit', ExpandConstant('{app}\versions\{#VersionDirectory}'), True) then
      RaiseException('Signed payload activation failed. The previous accepted version and user data are retained.');
    Completed := True;
    ReleaseMaintenance;
  end;
end;

procedure DeinitializeSetup;
begin
  ReleaseMaintenance;
end;

function InitializeUninstall: Boolean;
begin
  Helper := ExpandConstant('{tmp}\Manage-NestLink.ps1');
  Result := CopyFile(ExpandConstant('{app}\tools\Manage-NestLink.ps1'), Helper, True);
  if Result then Result := ResolveStateDirectory;
  if Result then begin
    ControlDirectory := NewControlDirectory;
    Result := RunHelper('Enter', '', False);
  end;
  Entered := Result;
  if not Result then
    MsgBox('Graceful cleanup was not confirmed. Use the signed v15 installer to recover; user data and other products are retained.', mbError, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then begin
    if not RunHelper('Uninstall', '', False) then
      RaiseException('The exact maintenance owner was lost; uninstall stopped.');
  end;
  if CurUninstallStep = usPostUninstall then begin
    Completed := True;
    ReleaseMaintenance;
  end;
end;

procedure DeinitializeUninstall;
begin
  ReleaseMaintenance;
end;
