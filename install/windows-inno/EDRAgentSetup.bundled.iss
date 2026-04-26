; EDR Agent — 完整/本地暂存版安装脚本（Inno 6, x64）
; 与 EDRAgentSetup.iss 行为一致（注册/开机任务等），但主程序与 DLL 来自**单独目录**（如 CI/本机
; 输出目录 monorepo\edr-agent-win_2-2），并打齐：models、agent_preprocess 规则、脚本、data 说明。
;
; 默认 EDR_BIN_DIR=..\..\..\edr-agent-win_2-2（相对本 .iss 所在位置，即 monorepo 根下常见暂存名）
;
; 编译（在 Windows 上，路径按本机 monorepo 根调整）:
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /DMyAppVersion=2.2.0 EDRAgentSetup.bundled.iss
; 覆盖暂存目录（推荐绝对路径、无空格时亦可相对路径）:
;   ISCC.exe /DEDR_BIN_DIR=C:\staged\edr-bin /DMyAppVersion=2.2.0 EDRAgentSetup.bundled.iss
; 或运行:  .\Build-BundledInstaller.ps1
;
; 说明: ONNX .onnx 应事先放入 edr-agent\models\（本仓库内 models 常仅含 README，需从流水线复制）；
; 证书/IOC 等 SQLite 为可选，若 agent.toml 未指路径可不带库文件；{app}\data\README_OPTIONAL_DBS.txt 有说明。

#define MyAppName "EDR Agent"
#define MyAppPublisher "EDR"
#define MyAppExeName "edr_agent.exe"
; 与 build\Release\ 相对位置不同：指向 monorepo 根下 edr-agent-win_2-2
#ifndef EDR_BIN_DIR
  #define EDR_BIN_DIR "..\..\..\edr-agent-win_2-2"
#endif
#ifndef EDR_AGENT_TOML_EXAMPLE
  #define EDR_AGENT_TOML_EXAMPLE "..\..\agent.toml.example"
#endif
#ifndef EDR_MODELS_GLOB
  #define EDR_MODELS_GLOB "..\..\models\*"
#endif
#ifndef EDR_AGENT_PREPROCESS_TOML
  #define EDR_AGENT_PREPROCESS_TOML "..\..\..\edr-backend\platform\config\agent_preprocess_rules_v1.toml"
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
OutputBaseFilename=EDRAgentSetup-bundled
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "enrollinsecure"; Description: "Skip TLS certificate verification during enrollment (self-signed / lab only)"; GroupDescription: "Enrollment:"; Flags: unchecked
Name: "windowsautorun"; Description: "Run at startup (scheduled task as SYSTEM, survives reboot)"; GroupDescription: "Runtime:"; Flags: checkedonce
Name: "hardeninstalldir"; Description: "Harden install folder ACL (SYSTEM/Admin full, Users read+execute; use Add/Remove Programs to uninstall)"; GroupDescription: "Runtime:"; Flags: unchecked

[Files]
Source: "{#EDR_BIN_DIR}\edr_agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#EDR_BIN_DIR}\edr_monitor.exe"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#EDR_BIN_DIR}\*.dll"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#EDR_MODELS_GLOB}"; DestDir: "{app}\models"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#EDR_AGENT_PREPROCESS_TOML}"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#EDR_AGENT_TOML_EXAMPLE}"; DestDir: "{app}"; DestName: "agent.toml.example"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\scripts\edr_agent_install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "edr_install_wizard_enroll.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "edr_windows_autorun.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "bundle_extra\README_OPTIONAL_DBS.txt"; DestDir: "{app}\data"; DestName: "README_OPTIONAL_DBS.txt"; Flags: ignoreversion skipifsourcedoesntexist
Source: "bundle_extra\BUNDLE_README.txt"; DestDir: "{app}"; DestName: "BUNDLE_README.txt"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Parameters: "--config ""{app}\agent.toml"""
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Parameters: "--config ""{app}\agent.toml"""; Tasks: desktopicon

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\edr_install_wizard_enroll.ps1"" ""{tmp}\edr_wizard_enroll.json"" ""{app}\agent.toml"""; StatusMsg: "Registering with platform..."; Flags: waituntilterminated; Check: EnrollParamsFileExists
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""if ((-not (Test-Path -LiteralPath '{app}\agent.toml')) -and (Test-Path -LiteralPath '{app}\agent.toml.example')) {{ Copy-Item -LiteralPath '{app}\agent.toml.example' -Destination '{app}\agent.toml' -Force }}"""; StatusMsg: "Ensuring agent.toml..."; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Parameters: "--config ""{app}\agent.toml"""; WorkingDir: "{app}"; Description: "Start EDR Agent now (console window; skip if startup task is enabled)"; Flags: postinstall nowait skipifsilent; Check: ShouldPostinstallStartExe
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "{code:AutorunInstallPsParameters}"; StatusMsg: "Configuring startup task..."; Flags: waituntilterminated; Check: ShouldInstallAutorun

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\edr_windows_autorun.ps1"" -Action Remove"; RunOnceId: "EdrAutorunRemove"; Flags: runhidden waituntilterminated; Check: AutorunScriptPresentForUninstall

[Code]
var
  EnrollPage: TInputQueryWizardPage;
  EdrCmdApiBase: string;
  EdrCmdToken: string;
  EdrCmdInsecureTls: Boolean;

function EdrCmdLineParamValue(const Flag: string): string;
var
  I, EqPos: Integer;
  S, Prefix: string;
begin
  Result := '';
  Prefix := UpperCase(Flag);
  for I := 1 to ParamCount do
  begin
    S := ParamStr(I);
    if UpperCase(Copy(S, 1, Length(Prefix))) <> Prefix then
      Continue;
    EqPos := Pos('=', S);
    if EqPos < 2 then
      Continue;
    Result := Copy(S, EqPos + 1, MaxInt);
    Result := Trim(Result);
    if (Length(Result) >= 2) and (Result[1] = '"') and (Result[Length(Result)] = '"') then
      Result := Copy(Result, 2, Length(Result) - 2);
    Exit;
  end;
end;

function EdrParseTruthyParam(const LongFlag, ShortFlag: string): Boolean;
var
  V: string;
begin
  V := UpperCase(Trim(EdrCmdLineParamValue(LongFlag)));
  if V = '' then
    V := UpperCase(Trim(EdrCmdLineParamValue(ShortFlag)));
  Result := (V = '1') or (V = 'TRUE') or (V = 'YES');
end;

procedure EdrLoadCmdlineEnroll;
begin
  EdrCmdApiBase := Trim(EdrCmdLineParamValue('/EDR_API_BASE'));
  if EdrCmdApiBase = '' then
    EdrCmdApiBase := Trim(EdrCmdLineParamValue('/API'));
  EdrCmdToken := Trim(EdrCmdLineParamValue('/EDR_ENROLL_TOKEN'));
  if EdrCmdToken = '' then
    EdrCmdToken := Trim(EdrCmdLineParamValue('/TOK'));
  EdrCmdInsecureTls := EdrParseTruthyParam('/EDR_INSECURE_TLS', '/TLS');
end;

function EdrHasCmdlineEnroll: Boolean;
begin
  Result := (EdrCmdApiBase <> '') and (EdrCmdToken <> '');
end;

function InitializeSetup(): Boolean;
var
  A, T: string;
begin
  EdrCmdApiBase := '';
  EdrCmdToken := '';
  EdrCmdInsecureTls := False;
  EdrLoadCmdlineEnroll;
  A := EdrCmdApiBase;
  T := EdrCmdToken;
  if ((A <> '') and (T = '')) or ((A = '') and (T <> '')) then
  begin
    MsgBox('EDR: provide both API base and enroll token (/EDR_API_BASE= + /EDR_ENROLL_TOKEN= or /API= + /TOK=), or omit both.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  Result := True;
end;

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
    'When both fields are filled, the installer calls POST /api/v1/enroll and writes a complete agent.toml next to edr_agent.exe (bundled template + your server/tenant/endpoint). Leave both empty to skip and start from a copy of agent.toml.example instead.');
  EnrollPage.Add('Platform API base URL (example: https://platform.example:8080):', False);
  EnrollPage.Add('Enrollment token:', False);
  if EdrHasCmdlineEnroll then
  begin
    EnrollPage.Values[0] := EdrCmdApiBase;
    EnrollPage.Values[1] := EdrCmdToken;
  end
  else
  begin
    EnrollPage.Values[0] := '';
    EnrollPage.Values[1] := '';
  end;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = EnrollPage.ID) and (WizardSilent or EdrHasCmdlineEnroll);
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
  Insecure: Boolean;
begin
  if CurStep <> ssPostInstall then
    Exit;
  if EdrHasCmdlineEnroll then
  begin
    U := EdrCmdApiBase;
    T := EdrCmdToken;
  end
  else
  begin
    U := Trim(EnrollPage.Values[0]);
    T := Trim(EnrollPage.Values[1]);
  end;
  if (U <> '') and (T <> '') then
  begin
    Path := ExpandConstant('{tmp}\edr_wizard_enroll.json');
    Json := Chr(123) + Chr(34) + 'api_base' + Chr(34) + ':' + JsonEscape(U) + ',' + Chr(34) + 'token' + Chr(34) + ':' + JsonEscape(T) + ',' +
      Chr(34) + 'insecure_tls' + Chr(34) + ':';
    Insecure := EdrCmdInsecureTls or WizardIsTaskSelected('enrollinsecure');
    if Insecure then
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
    begin
      if not FileCopy(ExToml, AppToml, False) then
        Log('CurStepChanged: FileCopy agent.toml.example -> agent.toml failed');
    end;
  end;
end;

function EnrollParamsFileExists: Boolean;
begin
  Result := FileExists(ExpandConstant('{tmp}\edr_wizard_enroll.json'));
end;

function AgentTomlExistsForRun: Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\agent.toml'));
end;

function ShouldPostinstallStartExe: Boolean;
begin
  Result := AgentTomlExistsForRun and (not WizardIsTaskSelected('windowsautorun'));
end;

function ShouldInstallAutorun: Boolean;
begin
  Result := WizardIsTaskSelected('windowsautorun') and AgentTomlExistsForRun;
end;

function AutorunInstallPsParameters(Param: string): string;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\edr_windows_autorun.ps1') + '" -Action Install';
  if WizardIsTaskSelected('hardeninstalldir') then
    Result := Result + ' -HardenAcl';
end;

function AutorunScriptPresentForUninstall: Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\edr_windows_autorun.ps1'));
end;
