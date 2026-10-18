; Independent unsigned acceptance installer. Formal v15 installers, their
; Authenticode checks and signed maintenance/update protocol are unchanged.
#ifndef Version
  #error Candidate Version is required
#endif
#ifndef PayloadDir
  #error Candidate PayloadDir is required
#endif
#ifndef OutputDir
  #error Candidate OutputDir is required
#endif
#ifndef OutputBase
  #error Candidate OutputBase is required
#endif
#ifndef Privileged
  #error Explicit candidate installer role is required
#endif
[Setup]
#if Privileged == "1"
AppId={{4FA00357-4E53-495E-AB25-F5A18C15CA02}
AppName=NestLink Candidate (optional broker bytes)
DefaultDirName={commonpf64}\NestLink-RC-Privileged
PrivilegesRequired=admin
#else
AppId={{4FA00357-4E53-495E-AB25-F5A18C15CA01}
AppName=NestLink Candidate
DefaultDirName={localappdata}\Programs\NestLink-RC
PrivilegesRequired=lowest
#endif
AppVersion={#Version}
VersionInfoVersion=0.3.0.1
AppPublisher=NestLink development candidate
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBase}
Compression=lzma2
SolidCompression=yes
SetupLogging=yes
CloseApplications=no
RestartApplications=no
DisableProgramGroupPage=yes
WizardStyle=modern
InfoBeforeFile={#PayloadDir}\README.candidate.txt

[Files]
Source: "{#PayloadDir}\nestlink-desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\nestlink-daemon.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\README.candidate.txt"; DestDir: "{app}"; Flags: ignoreversion
#if Privileged == "1"
Source: "{#PayloadDir}\nestlink-privileged.exe"; DestDir: "{app}"; Flags: ignoreversion
#endif

[Icons]
Name: "{autoprograms}\NestLink RC"; Filename: "{app}\nestlink-desktop.exe"; Parameters: "--state-dir ""{localappdata}\NestLink-RC"""

; Explicit local-user launch only; never starts a system service or broker.
[Run]
Filename: "{app}\nestlink-desktop.exe"; Parameters: "--state-dir ""{localappdata}\NestLink-RC"""; Description: "Open development candidate"; Flags: nowait postinstall skipifsilent unchecked runasoriginaluser
