#define AppName "DNS Shunt"
#define AppVersion "0.1.0"
#define AppPublisher "DNS Shunt"
#define AppExe "dns-shunt.exe"
#ifndef SourceDir
#define SourceDir "..\dist\stage"
#endif

[Setup]
AppId={{7E394261-C5B4-44F3-9E7D-AD9857D64115}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\DNS Shunt
DefaultGroupName=DNS Shunt
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=DNS-Shunt-Setup
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0
PrivilegesRequired=admin
Uninstallable=yes
WizardStyle=modern
SetupIconFile=..\assets\dns-shunt.ico
CloseApplications=yes
RestartApplications=no

[Files]
Source: "{#SourceDir}\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion notimestamp
Source: "{#SourceDir}\{#AppExe}"; DestDir: "{tmp}"; Flags: dontcopy notimestamp
Source: "{#SourceDir}\WinDivert.dll"; DestDir: "{tmp}"; Flags: dontcopy notimestamp
Source: "{#SourceDir}\WinDivert.dll"; DestDir: "{app}"; Flags: ignoreversion notimestamp
Source: "{#SourceDir}\WinDivert64.sys"; DestDir: "{app}"; Flags: ignoreversion notimestamp
Source: "{#SourceDir}\dns-shunt.example.toml"; DestDir: "{app}"; Flags: ignoreversion notimestamp

[Icons]
Name: "{group}\DNS Shunt Dashboard"; Filename: "{sys}\explorer.exe"; Parameters: "http://dns-shunt.local:53080"; IconFilename: "{app}\{#AppExe}"

[Code]
function InitializeSetup(): Boolean;
var
  Consent: Integer;
begin
  Consent := MsgBox(
    'Installing DNS Shunt enables machine-wide DNS capture. The service ' +
    'starts automatically as LocalSystem and inspects outbound IPv4 UDP ' +
    'DNS traffic. Only matching configured A records are overridden; other ' +
    'traffic continues to the resolver selected by Windows. Adapter DNS ' +
    'settings and resolver selection are not changed.' + #13#10 + #13#10 +
    'Install and start the DNS capture service?',
    mbConfirmation, MB_YESNO or MB_DEFBUTTON2);
  Result := Consent = IDYES;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ExitCode: Integer;
begin
  Result := '';
  ExtractTemporaryFile('{#AppExe}');
  ExtractTemporaryFile('WinDivert.dll');
  if not Exec(
    ExpandConstant('{tmp}\{#AppExe}'),
    '--stop-service', '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
  begin
    Result := 'Could not run the native service stop command.';
    Exit;
  end;
  if ExitCode <> 0 then
    Result := 'Could not stop the existing DNS Shunt service. Setup was not changed.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ExitCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    if not Exec(
      ExpandConstant('{app}\{#AppExe}'),
      '--install-service', '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
      RaiseException('Could not run the native service installation command.');
    if ExitCode <> 0 then
      RaiseException(
        'The DNS Shunt service could not be installed and started. ' +
        'Configuration and rules in ProgramData were preserved.');
  end;
end;

function InitializeUninstall(): Boolean;
var
  ExitCode: Integer;
begin
  Result := False;
  if not FileExists(ExpandConstant('{app}\{#AppExe}')) then
  begin
    MsgBox(
      'The DNS Shunt executable is missing, so the service cannot be safely ' +
      'removed. Restore the application files and retry.',
      mbError, MB_OK);
    Exit;
  end;
  if not Exec(
    ExpandConstant('{app}\{#AppExe}'),
    '--uninstall-service', '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
  begin
    MsgBox('Could not run the native service uninstall command.', mbError, MB_OK);
    Exit;
  end;
  if ExitCode <> 0 then
  begin
    MsgBox(
      'The DNS Shunt service could not be removed. Existing configuration and ' +
      'rules were preserved; uninstall has been cancelled.',
      mbError, MB_OK);
    Exit;
  end;
  Result := True;
end;
