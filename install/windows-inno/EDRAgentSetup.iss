; Inno Setup 6 — Windows x64 安装向导骨架（选项 B）。
; 平台 setup_exe 默认对象键：installers/setup-exe/<os_type>/<agent_version>/EDRAgentSetup.exe
; 本地编译示例（在 edr-agent 仓库根）：
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /DEDR_AGENT_EXE=build\Release\edr_agent.exe /DMyAppVersion=1.0.1 install\windows-inno\EDRAgentSetup.iss

#define MyAppName "EDR Agent"
#define MyAppPublisher "EDR"
#define MyAppExeName "edr_agent.exe"
#ifndef EDR_AGENT_EXE
  #define EDR_AGENT_EXE "..\..\build\Release\edr_agent.exe"
#endif
#ifndef EDR_AGENT_TOML_EXAMPLE
  #define EDR_AGENT_TOML_EXAMPLE "..\..\agent.toml.example"
#endif
#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif

[Setup]
AppId={{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=Output
OutputBaseFilename=EDRAgentSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "enrollinsecure"; Description: "Skip TLS certificate verification during enrollment (self-signed / lab only)"; GroupDescription: "Enrollment:"; Flags: unchecked

[Files]
Source: "{#EDR_AGENT_EXE}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#EDR_AGENT_TOML_EXAMPLE}"; DestDir: "{app}"; DestName: "agent.toml.example"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\scripts\edr_agent_install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "edr_install_wizard_enroll.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Parameters: "--config ""{app}\agent.toml"""
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Parameters: "--config ""{app}\agent.toml"""; Tasks: desktopicon

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\edr_install_wizard_enroll.ps1"" ""{tmp}\edr_wizard_enroll.json"" ""{app}\agent.toml"""; StatusMsg: "Registering with platform..."; Flags: waituntilterminated; Check: EnrollParamsFileExists

[Code]
var
  EnrollPage: TInputQueryWizardPage;

function JsonEscape(const S: string): string;
var
  I, L: Integer;
  Ch, BS, QU: string;
begin
  BS := '\';
  QU := '"';
  Result := QU;
  L := Length(S);
  for I := 1 to L do
  begin
    Ch := Copy(S, I, 1);
    if Ch = BS then
      Result := Result + BS + BS
    else if Ch = QU then
      Result := Result + BS + QU
    else
      Result := Result + Ch;
  end;
  Result := Result + QU;
end;

procedure InitializeWizard;
begin
  EnrollPage := CreateInputQueryPage(wpWelcome,
    'Platform enrollment',
    'Enter your platform REST base URL and enrollment token. Your administrator issues the token after creating the endpoint.',
    'Leave both fields empty to skip: you can run edr_agent_install.ps1 from the install folder later, or edit agent.toml.example.');
  EnrollPage.Add('Platform API base URL (example: https://platform.example:8080):', False);
  EnrollPage.Add('Enrollment token:', False);
  EnrollPage.Values[0] := '';
  EnrollPage.Values[1] := '';
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = EnrollPage.ID) and WizardSilent;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  U, T: string;
begin
  Result := True;
  if CurPageID = EnrollPage.ID then
  begin
    U := Trim(EnrollPage.Values[0]);
    T := Trim(EnrollPage.Values[1]);
    if ((U <> '') and (T = '')) or ((U = '') and (T <> '')) then
    begin
      MsgBox('Provide both the API base URL and the enrollment token, or leave both empty to skip registration.', mbInformation, MB_OK);
      Result := False;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Path, U, T, Json, AppToml, ExToml: string;
begin
  if CurStep <> ssPostInstall then
    Exit;
  U := Trim(EnrollPage.Values[0]);
  T := Trim(EnrollPage.Values[1]);
  if (U <> '') and (T <> '') then
  begin
    Path := ExpandConstant('{tmp}\edr_wizard_enroll.json');
    Json := Chr(123) + Chr(34) + 'api_base' + Chr(34) + ':' + JsonEscape(U) + ',' + Chr(34) + 'token' + Chr(34) + ':' + JsonEscape(T) + ',' +
      Chr(34) + 'insecure_tls' + Chr(34) + ':';
    if WizardIsTaskSelected('enrollinsecure') then
      Json := Json + 'true' + Chr(125)
    else
      Json := Json + 'false' + Chr(125);
    SaveStringToFile(Path, Json, False);
  end
  else
  begin
    AppToml := ExpandConstant('{app}\agent.toml');
    ExToml := ExpandConstant('{app}\agent.toml.example');
    if (not FileExists(AppToml)) and FileExists(ExToml) then
      FileCopy(ExToml, AppToml, False);
  end;
end;

function EnrollParamsFileExists: Boolean;
begin
  Result := FileExists(ExpandConstant('{tmp}\edr_wizard_enroll.json'));
end;
