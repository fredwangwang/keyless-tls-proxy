; Fred Proxy Key Storage Provider - Inno Setup Installer Script
; Bundles fredprx_ksp.dll, ksp-install-ui.exe, ksp-register.exe, and ksp-install-cert.exe.
; Automatically registers the CNG KSP provider on install and unregisters it on uninstall.

#ifndef MyAppVersion
#define MyAppVersion "1.0.0"
#endif

#define KspDllFile "..\..\build\fredprx_ksp.dll"
#if FileExists(KspDllFile)
  #define KspDllHash GetSHA256OfFile(KspDllFile)
#else
  #define KspDllHash ""
#endif

#define MyAppName "Fred Proxy Key Storage Provider"
#define MyAppShortName "FredProxyKSP"
#define MyAppPublisher "Fred Wang"
#define MyAppURL "https://github.com/fredwangwang/keyless-tls-proxy"
#define MyAppExeName "ksp-install-ui.exe"

[Setup]
; Unique application ID
AppId={{C8E11075-8D63-4DB8-9E16-92F27E9F4F6A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Fred Proxy KSP
DefaultGroupName=Fred Proxy KSP
AllowNoIcons=yes
OutputDir=..\..\build
OutputBaseFilename=FredProxyKSP-Setup
SetupIconFile=..\..\assets\AppIcon.ico
UninstallDisplayIcon={app}\AppIcon.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

; 64-bit architecture requirements
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Elevated administrator privileges are required to install into System32 and register with CNG
PrivilegesRequired=admin
DisableProgramGroupPage=yes
CloseApplications=force

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Deploy 64-bit KSP DLL into System32 for Windows CNG discovery (only if hash differs or file missing)
Source: "..\..\build\fredprx_ksp.dll"; DestDir: "{sys}"; Flags: 64bit restartreplace uninsrestartdelete ignoreversion; Check: KspDllNeedsUpdate
; Keep a copy in the application folder
Source: "..\..\build\fredprx_ksp.dll"; DestDir: "{app}"; Flags: 64bit ignoreversion
; GUI Certificate Manager
Source: "..\..\build\ksp-install-ui.exe"; DestDir: "{app}"; Flags: 64bit ignoreversion
; Provider Registration Tool
Source: "..\..\build\ksp-register.exe"; DestDir: "{app}"; Flags: 64bit ignoreversion
; Certificate Installation CLI Utility
Source: "..\..\build\ksp-install-cert.exe"; DestDir: "{app}"; Flags: 64bit ignoreversion
; Application Icon
Source: "..\..\assets\AppIcon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Fred Proxy Certificate Manager"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\AppIcon.ico"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Fred Proxy Certificate Manager"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\AppIcon.ico"; Tasks: desktopicon

[Run]
; 1. Register Fred Proxy Key Storage Provider with Windows CNG
Filename: "{app}\ksp-register.exe"; Parameters: "-register"; StatusMsg: "Registering Fred Proxy Key Storage Provider with Windows CNG..."; Flags: runhidden waituntilterminated
; 2. Offer to launch Certificate Manager post-install
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,Fred Proxy Certificate Manager}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Unregister the KSP provider from CNG before files are removed
Filename: "{app}\ksp-register.exe"; Parameters: "-unregister"; Flags: runhidden waituntilterminated

[Code]
// Checks if the KSP DLL in System32 needs to be updated by comparing SHA-256 hashes
function KspDllNeedsUpdate(): Boolean;
var
  InstalledPath: String;
  InstalledHash: String;
  TargetHash: String;
begin
  InstalledPath := ExpandConstant('{sys}\fredprx_ksp.dll');
  TargetHash := Lowercase('{#KspDllHash}');

  // If fredprx_ksp.dll does not exist in System32 yet, install it
  if not FileExists(InstalledPath) then
  begin
    Log('KSP DLL not found in System32. Installation required.');
    Result := True;
    Exit;
  end;

  // If no precomputed hash was passed at compile time, default to installing
  if TargetHash = '' then
  begin
    Log('No precomputed target hash provided. Defaulting to install.');
    Result := True;
    Exit;
  end;

  // Compute SHA256 of the DLL currently residing in System32
  InstalledHash := Lowercase(GetSHA256OfFile(InstalledPath));
  Log(Format('Installed System32 KSP DLL SHA-256: %s', [InstalledHash]));
  Log(Format('Installer package KSP DLL SHA-256:   %s', [TargetHash]));

  // If hashes match, skip replacing the file (prevents unnecessary file in-use / reboot prompts)
  if InstalledHash = TargetHash then
  begin
    Log('Installed KSP DLL matches installer version. Skipping replacement.');
    Result := False;
  end
  else
  begin
    Log('Installed KSP DLL hash differs from installer version. Updating file.');
    Result := True;
  end;
end;
