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
AppName=NestLink RC (optional components)
DefaultDirName={commonpf64}\NestLink-RC-Privileged
PrivilegesRequired=admin
#else
AppId={{4FA00357-4E53-495E-AB25-F5A18C15CA01}
AppName=NestLink RC
DefaultDirName={localappdata}\Programs\NestLink-RC
PrivilegesRequired=lowest
#endif
AppVersion={#Version}
VersionInfoVersion=0.5.0.1
UninstallDisplayIcon={app}\nestlink.ico
AppPublisher=NestLink
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
SetupIconFile=..\..\brand\nestlink.ico
WizardImageFile=..\..\brand\wizard-large.bmp
WizardSmallImageFile=..\..\brand\wizard-small.bmp
ShowLanguageDialog=yes
LanguageDetectionMethod=uilanguage
InfoBeforeFile={#PayloadDir}\README.candidate.txt

[Languages]
Name: "chinesesimp"; MessagesFile: "..\windows\languages\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\..\brand\nestlink.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\windows\languages\LICENSE.Inno-Setup.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion
Source: "..\windows\languages\README.md"; DestDir: "{app}\licenses"; DestName: "ChineseSimplified-translation.md"; Flags: ignoreversion
Source: "{#PayloadDir}\nestlink-desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\nestlink-daemon.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\README.candidate.txt"; DestDir: "{app}"; Flags: ignoreversion
#if Privileged == "1"
Source: "{#PayloadDir}\nestlink-privileged.exe"; DestDir: "{app}"; Flags: ignoreversion
#endif

[CustomMessages]
chinesesimp.LaunchNestLink=启动 NestLink
english.LaunchNestLink=Open NestLink
chinesesimp.DesktopShortcut=创建桌面快捷方式
english.DesktopShortcut=Create a desktop shortcut

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopShortcut}"; Flags: unchecked

[Icons]
Name: "{autoprograms}\NestLink RC"; Filename: "{app}\nestlink-desktop.exe"; Parameters: "--state-dir ""{localappdata}\NestLink-RC"""; IconFilename: "{app}\nestlink.ico"

Name: "{autodesktop}\NestLink RC"; Filename: "{app}\nestlink-desktop.exe"; Parameters: "--state-dir ""{localappdata}\NestLink-RC"""; IconFilename: "{app}\nestlink.ico"; Tasks: desktopicon

; Explicit local-user launch only; never starts a system service or broker.
[Run]
Filename: "{app}\nestlink-desktop.exe"; Parameters: "--state-dir ""{localappdata}\NestLink-RC"""; Description: "{cm:LaunchNestLink}"; Flags: nowait postinstall skipifsilent unchecked runasoriginaluser
