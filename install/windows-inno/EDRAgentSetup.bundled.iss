; FDSecurity — 完整/本地暂存版安装脚本（Inno 6, x64）
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

#define MyAppName "FDSecurity"
#define MyAppPublisher "FDSecurity"
#define MyAppExeName "FDSensor.exe"
#define MyServiceName "FDSecurityAgent"
#define MyLegacyServiceName "EdrAgent"
#define MyLegacyProcessName "edr_agent"
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
#ifndef EDR_VERSION_FILE
  #define EDR_VERSION_FILE EDR_BIN_DIR + "\VERSION"
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
LicenseFile=bundle_extra\EULA.txt
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=Output
OutputBaseFilename=FDSecuritySetup-bundled
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "enrollinsecure"; Description: "Skip TLS certificate verification during enrollment (self-signed / lab only)"; GroupDescription: "Enrollment:"; Flags: unchecked
Name: "windowsautorun"; Description: "Run at startup (scheduled task as SYSTEM, survives reboot)"; GroupDescription: "Runtime:"; Flags: checkedonce
Name: "windowsservice"; Description: "Run as native Windows service (advanced)"; GroupDescription: "Runtime:"; Flags: unchecked
Name: "hardeninstalldir"; Description: "Harden install folder ACL (SYSTEM/Admin full, Users read+execute; use Add/Remove Programs to uninstall)"; GroupDescription: "Runtime:"; Flags: unchecked
Name: "keepofflinequeue"; Description: "Keep existing offline event queue during upgrade"; GroupDescription: "Upgrade cleanup:"; Flags: unchecked
Name: "keepevidencecache"; Description: "Keep existing local evidence cache during upgrade"; GroupDescription: "Upgrade cleanup:"; Flags: unchecked
Name: "stricthealthcheck"; Description: "Fail setup if bootstrap health check fails"; GroupDescription: "Validation:"; Flags: unchecked

[Files]
Source: "{#EDR_BIN_DIR}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#EDR_BIN_DIR}\*.dll"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#EDR_VERSION_FILE}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#EDR_MODELS_GLOB}"; DestDir: "{app}\models"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
Source: "{#EDR_AGENT_PREPROCESS_TOML}"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#EDR_AGENT_TOML_EXAMPLE}"; DestDir: "{app}"; DestName: "agent.toml.example"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\config\agent_windows_production.example.toml"; DestDir: "{app}\config"; Flags: ignoreversion
Source: "..\..\config\p0_rule_bundle_ir_v1.json.enc"; DestDir: "{app}\edr_config"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\config\sensor_interest_manifest.json"; DestDir: "{app}\edr_config"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\scripts\edr_agent_install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\scripts\edr_agent_preflight.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\scripts\edr_agent_postinstall_verify.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\scripts\windows_service_install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\scripts\windows_isolate_host.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "edr_install_wizard_enroll.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "edr_windows_autorun.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "bundle_extra\README_OPTIONAL_DBS.txt"; DestDir: "{app}\data"; DestName: "README_OPTIONAL_DBS.txt"; Flags: ignoreversion skipifsourcedoesntexist
Source: "bundle_extra\BUNDLE_README.txt"; DestDir: "{app}"; DestName: "BUNDLE_README.txt"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Parameters: "--config ""{app}\agent.toml"""
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Parameters: "--config ""{app}\agent.toml"""; Tasks: desktopicon

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\windows_service_install.ps1"" -Action Uninstall -InstallDir ""{app}"" -DataDir ""{app}"""; RunOnceId: "EdrServiceRemove"; Flags: runhidden waituntilterminated; Check: ServiceScriptPresentForUninstall
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\edr_windows_autorun.ps1"" -Action Remove"; RunOnceId: "EdrAutorunRemove"; Flags: runhidden waituntilterminated; Check: AutorunScriptPresentForUninstall

[UninstallDelete]
Type: files; Name: "{app}\*.pid"
Type: files; Name: "{app}\FDSensorTaskLaunch.ps1"
Type: files; Name: "{app}\edr_queue.db*"
Type: files; Name: "{app}\local_evidence_cache.db*"
Type: files; Name: "{app}\command_state.jsonl*"
Type: files; Name: "{app}\state\command_state.jsonl*"
Type: filesandordirs; Name: "{app}\agent.toml"
Type: filesandordirs; Name: "{app}\certs"
Type: filesandordirs; Name: "{app}\queue"
Type: filesandordirs; Name: "{app}\evidence"
Type: filesandordirs; Name: "{app}\state"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\forensic"
Type: filesandordirs; Name: "{app}\isolation"
Type: filesandordirs; Name: "{app}\diagnostics"
Type: filesandordirs; Name: "{app}\upload_outbox"
Type: filesandordirs; Name: "{commonappdata}\FDSecurity\setup-ui"
Type: dirifempty; Name: "{commonappdata}\FDSecurity"

[Code]
var
  EnrollPage: TInputQueryWizardPage;
  ReviewPage: TOutputMsgWizardPage;
  EdrProgressPage: TOutputProgressWizardPage;
  EdrCmdApiBase: string;
  EdrCmdToken: string;
  EdrCmdParamsFile: string;
  EdrCmdProxyMode: string;
  EdrCmdProxyUrl: string;
  EdrCmdRelayUrl: string;
  EdrCmdInsecureTls: Boolean;
  EdrCmdKeepOfflineQueue: Boolean;
  EdrCmdKeepEvidenceCache: Boolean;
  EdrInstallFailed: Boolean;
  EdrFailureReason: string;
  EdrDiagnosticsDir: string;
  EdrDiagnosticsBundle: string;
  EdrStageLog: string;
  EdrCurrentStage: string;

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

function EdrBoolJson(B: Boolean): string;
begin
  if B then
    Result := 'true'
  else
    Result := 'false';
end;

function EdrPsBool(B: Boolean): string;
begin
  if B then
    Result := '$true'
  else
    Result := '$false';
end;

function EdrNormalizeProxyMode(const S: string): string;
var
  V: string;
begin
  V := UpperCase(Trim(S));
  if (V = '') or (V = 'AUTO') or (V = 'SYSTEM') or (V = 'WPAD') then
    Result := 'auto'
  else if (V = 'OFF') or (V = 'DIRECT') or (V = 'NONE') then
    Result := 'off'
  else if (V = 'EXPLICIT') or (V = 'MANUAL') or (V = 'PROXY') then
    Result := 'explicit'
  else
    Result := 'auto';
end;

function ShouldKeepOfflineQueue: Boolean;
begin
  Result := EdrCmdKeepOfflineQueue or WizardIsTaskSelected('keepofflinequeue');
end;

function ShouldKeepEvidenceCache: Boolean;
begin
  Result := EdrCmdKeepEvidenceCache or WizardIsTaskSelected('keepevidencecache');
end;

procedure EdrLoadCmdlineEnroll;
begin
  EdrCmdApiBase := Trim(EdrCmdLineParamValue('/EDR_API_BASE'));
  if EdrCmdApiBase = '' then
    EdrCmdApiBase := Trim(EdrCmdLineParamValue('/API'));
  EdrCmdToken := Trim(EdrCmdLineParamValue('/EDR_ENROLL_TOKEN'));
  if EdrCmdToken = '' then
    EdrCmdToken := Trim(EdrCmdLineParamValue('/TOK'));
  EdrCmdParamsFile := Trim(EdrCmdLineParamValue('/EDR_ENROLL_PARAMS_FILE'));
  if EdrCmdParamsFile = '' then
    EdrCmdParamsFile := Trim(EdrCmdLineParamValue('/EDR_PARAMS_FILE'));
  EdrCmdProxyMode := EdrNormalizeProxyMode(EdrCmdLineParamValue('/EDR_PROXY_MODE'));
  EdrCmdProxyUrl := Trim(EdrCmdLineParamValue('/EDR_PROXY_URL'));
  EdrCmdRelayUrl := Trim(EdrCmdLineParamValue('/EDR_RELAY_URL'));
  EdrCmdInsecureTls := EdrParseTruthyParam('/EDR_INSECURE_TLS', '/TLS');
  EdrCmdKeepOfflineQueue := EdrParseTruthyParam('/EDR_KEEP_OFFLINE_QUEUE', '/KEEPQ');
  EdrCmdKeepEvidenceCache := EdrParseTruthyParam('/EDR_KEEP_EVIDENCE_CACHE', '/KEEPE');
end;

function EdrHasCmdlineEnroll: Boolean;
begin
  Result := (EdrCmdParamsFile <> '') or ((EdrCmdApiBase <> '') and (EdrCmdToken <> ''));
end;

function InitializeSetup(): Boolean;
var
  A, T: string;
begin
  EdrCmdApiBase := '';
  EdrCmdToken := '';
  EdrCmdParamsFile := '';
  EdrCmdProxyMode := 'auto';
  EdrCmdProxyUrl := '';
  EdrCmdRelayUrl := '';
  EdrCmdInsecureTls := False;
  EdrCmdKeepOfflineQueue := False;
  EdrCmdKeepEvidenceCache := False;
  EdrLoadCmdlineEnroll;
  A := EdrCmdApiBase;
  T := EdrCmdToken;
  if EdrCmdParamsFile <> '' then
  begin
    if (A <> '') or (T <> '') then
    begin
      MsgBox('EDR: use either /EDR_ENROLL_PARAMS_FILE or /EDR_API_BASE + /EDR_ENROLL_TOKEN, not both.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if not FileExists(EdrCmdParamsFile) then
    begin
      MsgBox('EDR: enroll params file not found: ' + EdrCmdParamsFile, mbError, MB_OK);
      Result := False;
      Exit;
    end;
    Result := True;
    Exit;
  end;
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

function SaveEnrollParamsFileIfNeeded: Boolean;
var
  Path, U, T, ProxyMode, ProxyUrl, RelayUrl, Json: string;
  JsonFromFile: AnsiString;
  Insecure, KeepQueue, KeepEvidence, StrictHealth: Boolean;
begin
  Result := False;
  Path := ExpandConstant('{tmp}\edr_wizard_enroll.json');
  if EdrCmdParamsFile <> '' then
  begin
    if not LoadStringFromFile(EdrCmdParamsFile, JsonFromFile) then
    begin
      Log('SaveEnrollParamsFileIfNeeded: failed to read params file ' + EdrCmdParamsFile);
      Exit;
    end;
    Json := JsonFromFile;
    Result := SaveStringToFile(Path, Json, False);
    if not Result then
      Log('SaveEnrollParamsFileIfNeeded: failed to copy params file to ' + Path);
    Exit;
  end;

  if EdrHasCmdlineEnroll then
  begin
    U := EdrCmdApiBase;
    T := EdrCmdToken;
    ProxyMode := EdrCmdProxyMode;
    ProxyUrl := EdrCmdProxyUrl;
    RelayUrl := EdrCmdRelayUrl;
    KeepQueue := ShouldKeepOfflineQueue;
    KeepEvidence := ShouldKeepEvidenceCache;
  end
  else
  begin
    U := Trim(EnrollPage.Values[0]);
    T := Trim(EnrollPage.Values[1]);
    ProxyMode := EdrNormalizeProxyMode(EnrollPage.Values[2]);
    ProxyUrl := Trim(EnrollPage.Values[3]);
    RelayUrl := Trim(EnrollPage.Values[4]);
    KeepQueue := ShouldKeepOfflineQueue;
    KeepEvidence := ShouldKeepEvidenceCache;
  end;
  if (U = '') or (T = '') then
    Exit;
  Insecure := EdrCmdInsecureTls or WizardIsTaskSelected('enrollinsecure');
  StrictHealth := WizardIsTaskSelected('stricthealthcheck');

  Json := Chr(123)
    + Chr(34) + 'api_base' + Chr(34) + ':' + JsonEscape(U) + ','
    + Chr(34) + 'token' + Chr(34) + ':' + JsonEscape(T) + ','
    + Chr(34) + 'insecure_tls' + Chr(34) + ':' + EdrBoolJson(Insecure) + ','
    + Chr(34) + 'proxy_mode' + Chr(34) + ':' + JsonEscape(ProxyMode) + ','
    + Chr(34) + 'proxy_url' + Chr(34) + ':' + JsonEscape(ProxyUrl) + ','
    + Chr(34) + 'relay_url' + Chr(34) + ':' + JsonEscape(RelayUrl) + ','
    + Chr(34) + 'key_provider' + Chr(34) + ':' + JsonEscape('pem') + ','
    + Chr(34) + 'keep_offline_queue' + Chr(34) + ':' + EdrBoolJson(KeepQueue) + ','
    + Chr(34) + 'keep_evidence_cache' + Chr(34) + ':' + EdrBoolJson(KeepEvidence) + ','
    + Chr(34) + 'strict_health_check' + Chr(34) + ':' + EdrBoolJson(StrictHealth) + ','
    + Chr(34) + 'health_report' + Chr(34) + ':' + JsonEscape(ExpandConstant('{commonappdata}\FDSecurity\setup-ui\agent-diagnostics\install_health_report.json'))
    + Chr(125);

  Result := SaveStringToFile(Path, Json, False);
  if not Result then
    Log('SaveEnrollParamsFileIfNeeded: failed to write ' + Path);
end;

function PrepareToInstall(var NeedsRestart: Boolean): string;
var
  Code: Integer;
  Cmd: string;
begin
  Result := '';
  SaveEnrollParamsFileIfNeeded;
  Cmd := '-NoProfile -ExecutionPolicy Bypass -Command "'
    + '$d=''' + ExpandConstant('{app}') + ''';'
    + 'Stop-Service -Name ''{#MyServiceName}'' -Force -ErrorAction SilentlyContinue;'
    + 'Stop-Service -Name ''{#MyLegacyServiceName}'' -Force -ErrorAction SilentlyContinue;'
    + 'Stop-Process -Name ''FDSensor'' -Force -ErrorAction SilentlyContinue;'
    + 'Stop-Process -Name ''{#MyLegacyProcessName}'' -Force -ErrorAction SilentlyContinue;'
    + 'Remove-Item -LiteralPath (Join-Path $d ''FDSensor.pid'') -Force -ErrorAction SilentlyContinue;'
    + 'Remove-Item -LiteralPath (Join-Path $d ''edr_agent.pid'') -Force -ErrorAction SilentlyContinue;'
    + '"';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Cmd, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Result := 'Failed to run EDR preflight cleanup before installing.';
end;

function EdrDeploymentPlanText: string;
var
  DiagnosticsPath: string;
begin
  DiagnosticsPath := ExpandConstant('{commonappdata}\FDSecurity\setup-ui\agent-diagnostics');

  Result :=
    'FDSecurity setup will run the following controlled stages:' + #13#10 + #13#10 +
    '  01  Stop old FDSecurity process and legacy runtime' + #13#10 +
    '  02  Clean runtime cache and stale queue locks' + #13#10 +
    '  03  Enroll endpoint and write agent.toml' + #13#10 +
    '  04  Validate and normalize configuration paths' + #13#10 +
    '  05  Install service/startup task according to selected options' + #13#10 +
    '  06  Start Agent runtime' + #13#10 +
    '  07  Pull runtime policy with endpoint identity' + #13#10 +
    '  08  Write health summary and diagnostics' + #13#10 + #13#10 +
    'Diagnostics will be written under:' + #13#10 +
    '  ' + DiagnosticsPath + #13#10 + #13#10 +
    'If setup fails, the error dialog will include the failed stage and a copyable diagnostics bundle path.';
end;

procedure InitializeWizard;
begin
  EnrollPage := CreateInputQueryPage(wpSelectDir,
    'Platform enrollment and network',
    'Enter the platform connection settings issued by the EDR management center.',
    'When API base URL and token are filled, setup enrolls this endpoint and writes a complete agent.toml. Leave both empty only for offline lab packaging.');
  EnrollPage.Add('Platform API base URL (example: https://platform.example:8080):', False);
  EnrollPage.Add('Enrollment token:', False);
  EnrollPage.Add('Proxy mode (auto, off, explicit):', False);
  EnrollPage.Add('Explicit proxy URL (optional, example: http://proxy.corp:8080):', False);
  EnrollPage.Add('Relay/Gateway URL (optional, example: https://relay.corp:443/api/v1):', False);
  if EdrHasCmdlineEnroll then
  begin
    EnrollPage.Values[0] := EdrCmdApiBase;
    EnrollPage.Values[1] := EdrCmdToken;
    EnrollPage.Values[2] := EdrCmdProxyMode;
    EnrollPage.Values[3] := EdrCmdProxyUrl;
    EnrollPage.Values[4] := EdrCmdRelayUrl;
  end
  else
  begin
    EnrollPage.Values[0] := '';
    EnrollPage.Values[1] := '';
    EnrollPage.Values[2] := 'auto';
    EnrollPage.Values[3] := '';
    EnrollPage.Values[4] := '';
  end;

  ReviewPage := CreateOutputMsgPage(wpSelectTasks,
    'Deployment plan',
    'Review the controlled installation stages before setup changes the endpoint.',
    EdrDeploymentPlanText);

  EdrProgressPage := CreateOutputProgressPage('Installing FDSecurity', 'Preparing controlled deployment...');
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = EnrollPage.ID) and (WizardSilent or EdrHasCmdlineEnroll);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  U, T, ProxyMode, ProxyUrl: string;
begin
  Result := True;
  if CurPageID = EnrollPage.ID then
  begin
    U := Trim(EnrollPage.Values[0]);
    T := Trim(EnrollPage.Values[1]);
    ProxyMode := EdrNormalizeProxyMode(EnrollPage.Values[2]);
    ProxyUrl := Trim(EnrollPage.Values[3]);
    if ((U <> '') and (T = '')) or ((U = '') and (T <> '')) then
    begin
      MsgBox('Provide both the API base URL and the enrollment token, or leave both empty to skip registration.', mbInformation, MB_OK);
      Result := False;
    end;
    if Result and (ProxyMode = 'explicit') and (ProxyUrl = '') then
    begin
      MsgBox('Proxy mode is explicit, so provide a proxy URL or change proxy mode to auto/off.', mbInformation, MB_OK);
      Result := False;
    end;
    if Result then
      SaveEnrollParamsFileIfNeeded;
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

function EdrPowerShellPath: string;
begin
  Result := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
end;

function EdrPsSq(const S: string): string;
var
  V: string;
begin
  V := S;
  StringChange(V, '''', '''''');
  Result := '''' + V + '''';
end;

function EdrDiagnosticsFile(const FileName: string): string;
begin
  if EdrDiagnosticsDir <> '' then
    Result := EdrDiagnosticsDir + '\' + FileName
  else
    Result := ExpandConstant('{commonappdata}\FDSecurity\setup-ui\agent-diagnostics\') + FileName;
end;

procedure EdrAppendStageLog(const Message: string);
var
  Line: string;
begin
  Line := GetDateTimeString('yyyy-mm-dd hh:nn:ss', '-', ':') + ' ' + Message + #13#10;
  Log('EDR setup: ' + Message);
  if EdrStageLog <> '' then
    SaveStringToFile(EdrStageLog, Line, True);
end;

procedure EdrInitDiagnostics;
begin
  EdrDiagnosticsDir := ExpandConstant('{commonappdata}\FDSecurity\setup-ui\agent-diagnostics');
  if not DirExists(EdrDiagnosticsDir) then
    ForceDirectories(EdrDiagnosticsDir);
  EdrDiagnosticsBundle := ExpandConstant('{commonappdata}\FDSecurity\setup-ui\install-diagnostics.zip');
  EdrStageLog := EdrDiagnosticsDir + '\install-stage.log';
  SaveStringToFile(EdrStageLog, 'FDSecurity setup diagnostics' + #13#10, False);
  EdrAppendStageLog('diagnostics_dir=' + EdrDiagnosticsDir);
end;

procedure EdrSetProgress(StageNo, StageTotal: Integer; const Title, Detail: string);
begin
  EdrCurrentStage := Title;
  EdrProgressPage.SetText(Title, Detail);
  EdrProgressPage.SetProgress(StageNo - 1, StageTotal);
  WizardForm.StatusLabel.Caption := Title;
end;

procedure EdrCreateDiagnosticsBundle;
var
  Code: Integer;
  Cmd: string;
begin
  if EdrDiagnosticsDir = '' then
    Exit;
  Cmd := '-NoProfile -ExecutionPolicy Bypass -Command "'
    + 'if(Test-Path -LiteralPath ' + EdrPsSq(EdrDiagnosticsBundle) + '){Remove-Item -LiteralPath ' + EdrPsSq(EdrDiagnosticsBundle) + ' -Force -ErrorAction SilentlyContinue};'
    + 'Compress-Archive -Path ' + EdrPsSq(EdrDiagnosticsDir + '\*') + ' -DestinationPath ' + EdrPsSq(EdrDiagnosticsBundle) + ' -Force'
    + '"';
  if Exec(EdrPowerShellPath, Cmd, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    EdrAppendStageLog('diagnostics_bundle=' + EdrDiagnosticsBundle + ' exit=' + IntToStr(Code))
  else
    EdrAppendStageLog('diagnostics_bundle_failed path=' + EdrDiagnosticsBundle);
end;

procedure EdrAbortInstall;
var
  Msg: string;
begin
  EdrInstallFailed := True;
  EdrCreateDiagnosticsBundle;
  EdrProgressPage.Hide;
  Msg := 'FDSecurity setup failed.' + #13#10 + #13#10
    + 'Stage: ' + EdrCurrentStage + #13#10
    + 'Reason: ' + EdrFailureReason + #13#10 + #13#10
    + 'Diagnostics bundle:' + #13#10 + EdrDiagnosticsBundle + #13#10 + #13#10
    + 'Stage log:' + #13#10 + EdrStageLog;
  MsgBox(Msg, mbError, MB_OK);
  RaiseException(EdrFailureReason);
end;

function EdrRunCommandStage(StageNo, StageTotal: Integer; const Title, Detail, FileName, Params: string; Critical: Boolean): Boolean;
var
  Code: Integer;
  Ok: Boolean;
begin
  Result := True;
  EdrSetProgress(StageNo, StageTotal, Title, Detail);
  EdrAppendStageLog('START [' + Title + '] ' + FileName + ' ' + Params);
  Ok := Exec(FileName, Params, '', SW_HIDE, ewWaitUntilTerminated, Code);
  if Ok and (Code = 0) then
  begin
    EdrAppendStageLog('OK [' + Title + '] exit=0');
    EdrProgressPage.SetProgress(StageNo, StageTotal);
    Exit;
  end;

  if Ok then
    EdrFailureReason := Title + ' failed with exit code ' + IntToStr(Code)
  else
    EdrFailureReason := Title + ' could not be started';
  if Title = 'Enroll and write configuration' then
    EdrFailureReason := EdrFailureReason + '; enroll log: ' + EdrDiagnosticsFile('enroll-output.log');
  if Critical then
  begin
    EdrAppendStageLog('FAILED [' + Title + '] ' + EdrFailureReason);
    Result := False;
    Exit;
  end;
  EdrAppendStageLog('WARN [' + Title + '] ' + EdrFailureReason);
  EdrAppendStageLog('NONCRITICAL [' + Title + '] continuing');
  EdrProgressPage.SetProgress(StageNo, StageTotal);
end;

function EdrRunPowerShellStage(StageNo, StageTotal: Integer; const Title, Detail, Params: string; Critical: Boolean): Boolean;
begin
  Result := EdrRunCommandStage(StageNo, StageTotal, Title, Detail, EdrPowerShellPath, Params, Critical);
end;

function EdrRunNoWaitStage(StageNo, StageTotal: Integer; const Title, Detail, FileName, Params, WorkDir: string; Critical: Boolean): Boolean;
var
  Code: Integer;
  Ok: Boolean;
begin
  Result := True;
  EdrSetProgress(StageNo, StageTotal, Title, Detail);
  EdrAppendStageLog('START_NOWAIT [' + Title + '] ' + FileName + ' ' + Params);
  Ok := Exec(FileName, Params, WorkDir, SW_HIDE, ewNoWait, Code);
  if Ok then
  begin
    EdrAppendStageLog('OK_NOWAIT [' + Title + ']');
    EdrProgressPage.SetProgress(StageNo, StageTotal);
    Exit;
  end;
  EdrFailureReason := Title + ' could not be started';
  EdrAppendStageLog('FAILED [' + Title + '] ' + EdrFailureReason);
  if Critical then
  begin
    Result := False;
    Exit;
  end;
  EdrAppendStageLog('NONCRITICAL [' + Title + '] continuing');
  EdrProgressPage.SetProgress(StageNo, StageTotal);
end;

procedure EdrSkipStage(StageNo, StageTotal: Integer; const Title, Detail: string);
begin
  EdrSetProgress(StageNo, StageTotal, Title, Detail);
  EdrAppendStageLog('SKIP [' + Title + '] ' + Detail);
  EdrProgressPage.SetProgress(StageNo, StageTotal);
end;

function EdrStopRuntimePsParameters: string;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -Command "'
    + '$ErrorActionPreference=''SilentlyContinue'';'
    + 'try { $svc=Get-Service -Name ''{#MyServiceName}'' -ErrorAction SilentlyContinue; if($svc -and $svc.Status -ne ''Stopped''){Stop-Service -Name ''{#MyServiceName}'' -Force -ErrorAction SilentlyContinue} } catch {};'
    + 'try { $svc=Get-Service -Name ''{#MyLegacyServiceName}'' -ErrorAction SilentlyContinue; if($svc -and $svc.Status -ne ''Stopped''){Stop-Service -Name ''{#MyLegacyServiceName}'' -Force -ErrorAction SilentlyContinue} } catch {};'
    + 'try { Get-Process -Name ''FDSensor'' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {};'
    + 'try { Get-Process -Name ''{#MyLegacyProcessName}'' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {};'
    + 'try { Remove-Item -LiteralPath ' + EdrPsSq(ExpandConstant('{app}\edr_agent.pid')) + ' -Force -ErrorAction SilentlyContinue } catch {};'
    + 'try { Remove-Item -LiteralPath ' + EdrPsSq(ExpandConstant('{app}\FDSensor.pid')) + ' -Force -ErrorAction SilentlyContinue } catch {};'
    + 'exit 0'
    + '"';
end;

function PreflightPsParameters(Param: string): string;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\edr_agent_preflight.ps1') + '"'
    + ' -InstallDir "' + ExpandConstant('{app}') + '"'
    + ' -SkipStop'
    + ' -ReportPath "' + EdrDiagnosticsFile('install_preflight_report.json') + '"';
  if ShouldKeepOfflineQueue then
    Result := Result + ' -KeepOfflineQueue';
  if ShouldKeepEvidenceCache then
    Result := Result + ' -KeepEvidenceCache';
end;

function EdrEnrollPsParameters: string;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\edr_install_wizard_enroll.ps1') + '" "'
    + ExpandConstant('{tmp}\edr_wizard_enroll.json') + '" "' + ExpandConstant('{app}\agent.toml') + '" "'
    + EdrDiagnosticsDir + '"';
end;

function EdrEnsureTomlPsParameters: string;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -Command "'
    + '$app=''' + ExpandConstant('{app}') + ''';'
    + '$cfg=Join-Path $app ''agent.toml'';'
    + 'if(-not (Test-Path -LiteralPath $cfg)){throw ''agent.toml was not generated''};'
    + '$takeown=Get-Command ''takeown.exe'' -ErrorAction SilentlyContinue;'
    + 'if($takeown){try { & $takeown.Source /F $cfg /A | Out-Null } catch {}};'
    + '$icacls=Get-Command ''icacls.exe'' -ErrorAction SilentlyContinue;'
    + 'if($icacls){try { & $icacls.Source $cfg /inheritance:r /grant:r ''*S-1-5-18:F'' /grant:r ''*S-1-5-32-544:F'' /C /Q | Out-Null } catch {}};'
    + '$raw=[System.IO.File]::ReadAllText($cfg);'
    + 'if([string]::IsNullOrWhiteSpace($raw)){throw ''agent.toml is empty''};'
    + '$sha=(Get-FileHash -Algorithm SHA256 -LiteralPath $cfg -ErrorAction SilentlyContinue).Hash;'
    + 'Write-Host (''agent.toml present size=''+(Get-Item -LiteralPath $cfg).Length+'' sha256=''+$sha);'
    + 'if($icacls){try { & $icacls.Source $cfg /inheritance:r /grant:r ''*S-1-5-18:F'' /grant:r ''*S-1-5-32-544:F'' /C /Q | Out-Null } catch {}}'
    + '"';
end;

function EdrPolicyVerifyPsParameters: string;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -Command "'
    + '$out=' + EdrPsSq(EdrDiagnosticsFile('install_runtime_verify.output.log')) + ';'
    + '$script=' + EdrPsSq(ExpandConstant('{app}\edr_agent_postinstall_verify.ps1')) + ';'
    + '$env:EDR_VERIFY_REPORT_PATH=' + EdrPsSq(EdrDiagnosticsFile('install_runtime_verify.json')) + ';'
    + '$env:EDR_VERIFY_LOG_PATH=' + EdrPsSq(EdrDiagnosticsFile('install_runtime_verify.log')) + ';'
    + 'try{New-Item -ItemType File -Path $out -Force | Out-Null;Add-Content -LiteralPath $out -Value ((Get-Date).ToString(''o'')+'' wrapper_start script=''+$script) -Encoding UTF8}catch{};'
    + '$takeown=Get-Command ''takeown.exe'' -ErrorAction SilentlyContinue;'
    + '$icacls=Get-Command ''icacls.exe'' -ErrorAction SilentlyContinue;'
    + 'try{if((Test-Path -LiteralPath $script) -and $takeown){& $takeown.Source /F $script /A | Out-Null}}catch{};'
    + 'try{if((Test-Path -LiteralPath $script) -and $icacls){& $icacls.Source $script /grant:r ''*S-1-5-18:F'' /grant:r ''*S-1-5-32-544:F'' /grant:r ''*S-1-5-32-545:RX'' /C /Q | Out-Null}}catch{};'
    + 'try{if(Test-Path -LiteralPath $script){Unblock-File -LiteralPath $script -ErrorAction SilentlyContinue}}catch{};'
    + 'try{'
    + '& $script -InstallDir ' + EdrPsSq(ExpandConstant('{app}')) + ' -ConfigPath ' + EdrPsSq(ExpandConstant('{app}\agent.toml')) + ' -PolicyTimeoutSec 15 *>> $out;'
    + '$ok=$?;'
    + '$code=1;if($ok){$code=0};'
    + 'if($LASTEXITCODE -ne $null){$code=$LASTEXITCODE};'
    + 'try{Add-Content -LiteralPath $out -Value ((Get-Date).ToString(''o'')+'' wrapper_exit_code=''+$code) -Encoding UTF8}catch{};'
    + '}catch{'
    + '$code=1;'
    + 'try{Add-Content -LiteralPath $out -Value ((Get-Date).ToString(''o'')+'' wrapper_exception=''+$_.Exception.Message) -Encoding UTF8}catch{};'
    + '};'
    + 'try{Get-Content -LiteralPath $out -Tail 80 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }}catch{};'
    + 'exit $code'
    + '"';
end;

function EdrHealthSummaryPsParameters: string;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -Command "'
    + 'if(Test-Path -LiteralPath ' + EdrPsSq(EdrDiagnosticsFile('install_runtime_verify.json')) + '){'
    + 'Write-Host ''runtime verification report ready: ' + EdrDiagnosticsFile('install_runtime_verify.json') + ''''
    + '}else{Write-Warning ''runtime verification report missing; install will continue and endpoint health can be checked from console''};'
    + 'exit 0'
    + '"';
end;

function EdrCopyLocalConfigStage(StageNo, StageTotal: Integer): Boolean;
var
  AppToml, ExToml: string;
begin
  Result := True;
  EdrSetProgress(StageNo, StageTotal, 'Write local configuration', 'No enrollment token was provided; copying bundled template.');
  AppToml := ExpandConstant('{app}\agent.toml');
  ExToml := ExpandConstant('{app}\agent.toml.example');
  if FileExists(AppToml) then
  begin
    EdrAppendStageLog('OK [Write local configuration] existing agent.toml=' + AppToml);
    EdrProgressPage.SetProgress(StageNo, StageTotal);
    Exit;
  end;
  if FileExists(ExToml) and CopyFile(ExToml, AppToml, False) then
  begin
    EdrAppendStageLog('OK [Write local configuration] copied agent.toml.example');
    EdrProgressPage.SetProgress(StageNo, StageTotal);
    Exit;
  end;
  EdrFailureReason := 'agent.toml was not generated and agent.toml.example is missing';
  EdrAppendStageLog('FAILED [Write local configuration] ' + EdrFailureReason);
  Result := False;
end;

function AutorunInstallPsParameters(Param: string): string;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\edr_windows_autorun.ps1') + '" -Action Install -NoStart';
  if WizardIsTaskSelected('hardeninstalldir') then
    Result := Result + ' -HardenAcl';
end;

function WindowsServiceInstallPsParameters(Param: string): string;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\windows_service_install.ps1') + '"'
    + ' -Action Install'
    + ' -ExePath "' + ExpandConstant('{app}\{#MyAppExeName}') + '"'
    + ' -ServiceName "{#MyServiceName}"'
    + ' -DisplayName "FDSecurity Endpoint Agent"'
    + ' -ConfigPath "' + ExpandConstant('{app}\agent.toml') + '"'
    + ' -InstallDir "' + ExpandConstant('{app}') + '"'
    + ' -DataDir "' + ExpandConstant('{app}') + '"'
    + ' -SkipPreflight'
    + ' -NoStart';
  if ShouldKeepOfflineQueue then
    Result := Result + ' -KeepOfflineQueue';
  if ShouldKeepEvidenceCache then
    Result := Result + ' -KeepEvidenceCache';
end;

function EdrStartServicePsParameters: string;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -Command "'
    + '$ErrorActionPreference=''SilentlyContinue'';'
    + '$log=' + EdrPsSq(EdrDiagnosticsFile('start-runtime.log')) + ';'
    + 'function L($m){try{Add-Content -LiteralPath $log -Value ((Get-Date).ToString(''o'')+'' ''+$m) -Encoding UTF8}catch{}};'
    + 'Start-Sleep -Seconds 1;'
    + 'try { Start-Service -Name ''{#MyServiceName}'' -ErrorAction SilentlyContinue; L ''Start-Service invoked'' } catch { L (''Start-Service error: ''+$_.Exception.Message) };'
    + 'Start-Sleep -Seconds 3;'
    + 'Get-Process -Name ''FDSensor'' -ErrorAction SilentlyContinue | ForEach-Object { try { $_.PriorityClass = ''BelowNormal'' } catch {} };'
    + 'try { $svc=Get-Service -Name ''{#MyServiceName}'' -ErrorAction SilentlyContinue; if($svc){L (''service_status=''+$svc.Status)} } catch {};'
    + 'exit 0'
    + '"';
end;

function EdrStartScheduledTaskPsParameters: string;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -Command "'
    + '$ErrorActionPreference=''SilentlyContinue'';'
    + '$log=' + EdrPsSq(EdrDiagnosticsFile('start-runtime.log')) + ';'
    + 'function L($m){try{Add-Content -LiteralPath $log -Value ((Get-Date).ToString(''o'')+'' ''+$m) -Encoding UTF8}catch{}};'
    + '$exe=' + EdrPsSq(ExpandConstant('{app}\{#MyAppExeName}')) + ';'
    + '$cfg=' + EdrPsSq(ExpandConstant('{app}\agent.toml')) + ';'
    + '$wd=' + EdrPsSq(ExpandConstant('{app}')) + ';'
    + '$takeown=Get-Command ''takeown.exe'' -ErrorAction SilentlyContinue;'
    + '$icacls=Get-Command ''icacls.exe'' -ErrorAction SilentlyContinue;'
    + 'function FixAcl{param($p,$cfgOnly) if(-not (Test-Path -LiteralPath $p)){L (''missing=''+$p);return};try{if($takeown){& $takeown.Source /F $p /A | Out-Null}}catch{L (''takeown_failed=''+$p+'' msg=''+$_.Exception.Message)};try{if($icacls){if($cfgOnly){& $icacls.Source $p /inheritance:r /grant:r ''*S-1-5-18:F'' /grant:r ''*S-1-5-32-544:F'' /C /Q | Out-Null}else{& $icacls.Source $p /grant:r ''*S-1-5-18:F'' /grant:r ''*S-1-5-32-544:F'' /grant:r ''*S-1-5-32-545:RX'' /C /Q | Out-Null}}}catch{L (''icacls_failed=''+$p+'' msg=''+$_.Exception.Message)}};'
    + 'FixAcl $exe $false;'
    + 'FixAcl $cfg $true;'
    + '$certDir=Join-Path $wd ''certs'';'
    + '$logDir=Join-Path $wd ''logs'';'
    + 'try { if(-not (Test-Path -LiteralPath $logDir)){New-Item -ItemType Directory -Path $logDir -Force | Out-Null} } catch {};'
    + 'try { if($icacls -and (Test-Path -LiteralPath $certDir)){& $icacls.Source $certDir /inheritance:r /grant:r ''*S-1-5-18:(OI)(CI)F'' /grant:r ''*S-1-5-32-544:(OI)(CI)F'' /T /C /Q | Out-Null} } catch { L (''cert_acl_failed msg=''+$_.Exception.Message) };'
    + 'try { if($icacls -and (Test-Path -LiteralPath $logDir)){& $icacls.Source $logDir /inheritance:r /grant:r ''*S-1-5-18:(OI)(CI)F'' /grant:r ''*S-1-5-32-544:(OI)(CI)F'' /T /C /Q | Out-Null} } catch { L (''log_acl_failed msg=''+$_.Exception.Message) };'
    + 'foreach($scriptName in @(''edr_agent_postinstall_verify.ps1'',''FDSensorTaskLaunch.ps1'')){try{$sp=Join-Path $wd $scriptName;if((Test-Path -LiteralPath $sp) -and $icacls){& $icacls.Source $sp /grant:r ''*S-1-5-18:F'' /grant:r ''*S-1-5-32-544:F'' /grant:r ''*S-1-5-32-545:RX'' /C /Q | Out-Null;Unblock-File -LiteralPath $sp -ErrorAction SilentlyContinue}}catch{}};'
    + 'try { Unblock-File -LiteralPath $exe -ErrorAction SilentlyContinue } catch {};'
    + 'try { L (''whoami=''+(& whoami.exe)) } catch {};'
    + 'try { L (''dir_acl=''+((& icacls.exe $wd) -join '' | '')) } catch {};'
    + 'try { L (''exe_acl=''+((& icacls.exe $exe) -join '' | '')) } catch {};'
    + 'try { L (''cfg_acl=''+((& icacls.exe $cfg) -join '' | '')) } catch {};'
    + 'foreach($n in @(''libcrypto-3-x64.dll'',''libssl-3-x64.dll'',''libcurl.dll'',''sqlite3.dll'',''onnxruntime.dll'',''pcre2-8.dll'',''edr_agent_postinstall_verify.ps1'',''certs\ca.pem'',''certs\client.pem'',''certs\client-key.pem'')){try{$fp=Join-Path $wd $n;if(Test-Path -LiteralPath $fp){L (''dep_acl ''+$n+''=''+((& icacls.exe $fp) -join '' | ''))}}catch{}};'
    + 'try { $task0=Get-ScheduledTask -TaskName ''{#MyServiceName}'' -ErrorAction SilentlyContinue; if($task0){foreach($a in @($task0.Actions)){L (''task_action execute=''+$a.Execute+'' args=''+$a.Arguments+'' wd=''+$a.WorkingDirectory)}; L (''task_principal user=''+$task0.Principal.UserId+'' logon=''+$task0.Principal.LogonType+'' runlevel=''+$task0.Principal.RunLevel)} } catch {};'
    + 'Start-Sleep -Seconds 1;'
    + 'try { Start-ScheduledTask -TaskName ''{#MyServiceName}'' -ErrorAction Stop; L ''Start-ScheduledTask invoked'' } catch { L (''Start-ScheduledTask error: ''+$_.Exception.Message) };'
    + 'Start-Sleep -Seconds 5;'
    + '$startupLog=Join-Path $wd ''logs\startup-task.log'';'
    + 'try { if(Test-Path -LiteralPath $startupLog){Get-Content -LiteralPath $startupLog -Tail 30 -ErrorAction SilentlyContinue | ForEach-Object { L (''task_launcher ''+$_) }} } catch {};'
    + '$p=Get-Process -Name ''FDSensor'' -ErrorAction SilentlyContinue;'
    + 'if(-not $p -and (Test-Path -LiteralPath $exe) -and (Test-Path -LiteralPath $cfg)){'
    + 'try { $agentArgs=''--config ''+(''"''+($cfg -replace ''"'',''\"'')+''"''); $p=Start-Process -FilePath $exe -ArgumentList $agentArgs -WorkingDirectory $wd -WindowStyle Hidden -PassThru -ErrorAction Stop; L (''manual fallback pid=''+$p.Id+'' args=''+$agentArgs) } catch { L (''manual fallback error: ''+$_.Exception.Message) };'
    + 'Start-Sleep -Seconds 2;'
    + '};'
    + 'Get-Process -Name ''FDSensor'' -ErrorAction SilentlyContinue | ForEach-Object { try { $_.PriorityClass = ''BelowNormal'' } catch {}; L (''process_pid=''+$_.Id) };'
    + 'try { $task=Get-ScheduledTask -TaskName ''{#MyServiceName}'' -ErrorAction SilentlyContinue; if($task){L (''task_state=''+$task.State)}; $info=Get-ScheduledTaskInfo -TaskName ''{#MyServiceName}'' -ErrorAction SilentlyContinue; if($info){L (''task_last_result=''+$info.LastTaskResult)} } catch {};'
    + 'if(-not (Get-Process -Name ''FDSensor'' -ErrorAction SilentlyContinue)){L ''runtime_not_started''};'
    + 'exit 0'
    + '"';
end;

function EdrStartManualPsParameters: string;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -Command "'
    + '$ErrorActionPreference=''SilentlyContinue'';'
    + '$exe=' + EdrPsSq(ExpandConstant('{app}\{#MyAppExeName}')) + ';'
    + '$cfg=' + EdrPsSq(ExpandConstant('{app}\agent.toml')) + ';'
    + '$takeown=Get-Command ''takeown.exe'' -ErrorAction SilentlyContinue;'
    + '$icacls=Get-Command ''icacls.exe'' -ErrorAction SilentlyContinue;'
    + 'try { if($takeown){& $takeown.Source /F $exe /A | Out-Null} } catch {};'
    + 'try { if($icacls){& $icacls.Source $exe /grant:r ''*S-1-5-18:F'' /grant:r ''*S-1-5-32-544:F'' /grant:r ''*S-1-5-32-545:RX'' /C /Q | Out-Null} } catch {};'
    + 'try { if($takeown){& $takeown.Source /F $cfg /A | Out-Null} } catch {};'
    + 'try { if($icacls){& $icacls.Source $cfg /inheritance:r /grant:r ''*S-1-5-18:F'' /grant:r ''*S-1-5-32-544:F'' /C /Q | Out-Null} } catch {};'
    + 'try { Unblock-File -LiteralPath $exe -ErrorAction SilentlyContinue } catch {};'
    + 'Start-Sleep -Seconds 1;'
    + '$agentArgs=''--config ''+(''"''+($cfg -replace ''"'',''\"'')+''"'');'
    + '$p=Start-Process -FilePath $exe'
    + ' -ArgumentList $agentArgs'
    + ' -WorkingDirectory ' + EdrPsSq(ExpandConstant('{app}'))
    + ' -WindowStyle Hidden -PassThru -ErrorAction Stop;'
    + 'try { $p.PriorityClass = ''BelowNormal'' } catch {};'
    + 'exit 0'
    + '"';
end;

function EdrHardenAclPsParameters: string;
begin
  Result := '-NoProfile -ExecutionPolicy Bypass -Command "'
    + '$d=' + EdrPsSq(ExpandConstant('{app}')) + ';'
    + 'if(Test-Path -LiteralPath $d){'
    + '& icacls.exe $d /inheritance:r /grant:r ''*S-1-5-18:(OI)(CI)F'' /grant:r ''*S-1-5-32-544:(OI)(CI)F'' /grant:r ''*S-1-5-32-545:(OI)(CI)RX'' /T /C /Q | Out-Null'
    + '};'
    + '$cfg=Join-Path $d ''agent.toml'';'
    + 'if(Test-Path -LiteralPath $cfg){'
    + 'try { & takeown.exe /F $cfg /A | Out-Null } catch {};'
    + '& icacls.exe $cfg /inheritance:r /grant:r ''*S-1-5-18:F'' /grant:r ''*S-1-5-32-544:F'' /C /Q | Out-Null'
    + '};'
    + 'exit 0'
    + '"';
end;

procedure EdrRunInstallWorkflow;
var
  Total: Integer;
  Enrolled: Boolean;
begin
  Total := 8;
  EdrInstallFailed := False;
  EdrFailureReason := '';
  EdrInitDiagnostics;
  SaveEnrollParamsFileIfNeeded;
  Enrolled := EnrollParamsFileExists;

  EdrProgressPage.Show;
  if not EdrRunPowerShellStage(1, Total, 'Stop old Agent runtime', 'Stopping service/process and removing stale PID files.', EdrStopRuntimePsParameters, True) then
    EdrAbortInstall;

  if not EdrRunPowerShellStage(2, Total, 'Clean runtime cache', 'Cleaning queue locks and local evidence cache according to selected options.', PreflightPsParameters(''), True) then
    EdrAbortInstall;

  if Enrolled then
  begin
    if not EdrRunPowerShellStage(3, Total, 'Enroll and write configuration', 'Calling platform enrollment API and writing agent.toml.', EdrEnrollPsParameters, True) then
      EdrAbortInstall;
  end
  else
  begin
    if not EdrCopyLocalConfigStage(3, Total) then
      EdrAbortInstall;
  end;

  if not EdrRunPowerShellStage(4, Total, 'Validate configuration', 'Ensuring agent.toml exists and applying protected ACLs.', EdrEnsureTomlPsParameters, True) then
    EdrAbortInstall;

  if WizardIsTaskSelected('windowsservice') then
  begin
    if not EdrRunPowerShellStage(5, Total, 'Install service/startup task', 'Installing native Windows service for FDSecurity.', WindowsServiceInstallPsParameters(''), True) then
      EdrAbortInstall;
  end
  else if WizardIsTaskSelected('windowsautorun') then
  begin
    if not EdrRunPowerShellStage(5, Total, 'Install service/startup task', 'Installing SYSTEM startup task for FDSecurity.', AutorunInstallPsParameters(''), True) then
      EdrAbortInstall;
  end
  else if WizardIsTaskSelected('hardeninstalldir') then
  begin
    if not EdrRunPowerShellStage(5, Total, 'Install service/startup task', 'Applying install directory ACL hardening.', EdrHardenAclPsParameters, True) then
      EdrAbortInstall;
  end
  else
    EdrSkipStage(5, Total, 'Install service/startup task', 'Startup task disabled by installer option.');

  if WizardIsTaskSelected('windowsservice') then
  begin
    if not EdrRunPowerShellStage(6, Total, 'Start Agent runtime', 'Starting FDSecurityAgent Windows service.', EdrStartServicePsParameters, False) then
      EdrAbortInstall;
  end
  else if WizardIsTaskSelected('windowsautorun') then
  begin
    if not EdrRunPowerShellStage(6, Total, 'Start Agent runtime', 'Starting FDSecurityAgent scheduled task.', EdrStartScheduledTaskPsParameters, False) then
      EdrAbortInstall;
  end
  else
  begin
    if not EdrRunPowerShellStage(6, Total, 'Start Agent runtime', 'Starting FDSensor.exe with generated agent.toml.', EdrStartManualPsParameters, False) then
      EdrAbortInstall;
  end;

  if not EdrRunPowerShellStage(7, Total, 'Pull runtime policy', 'Verifying endpoint identity and pulling runtime policy when reachable.', EdrPolicyVerifyPsParameters, False) then
    EdrAbortInstall;

  if not EdrRunPowerShellStage(8, Total, 'Write health summary', 'Writing installation health report and diagnostics bundle.', EdrHealthSummaryPsParameters, False) then
    EdrAbortInstall;

  EdrCreateDiagnosticsBundle;
  EdrProgressPage.SetProgress(Total, Total);
  EdrAppendStageLog('INSTALL_WORKFLOW_OK');
  EdrProgressPage.Hide;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    EdrRunInstallWorkflow;
end;

procedure CurPageChanged(CurPageID: Integer);
var
  HealthReport, PreflightReport, RuntimeReport, S, Msg: string;
  RawHealthReport: AnsiString;
begin
  if CurPageID = ReviewPage.ID then
    ReviewPage.MsgLabel.Caption := EdrDeploymentPlanText;

  if CurPageID <> wpFinished then
    Exit;

  HealthReport := EdrDiagnosticsFile('install_health_report.json');
  PreflightReport := EdrDiagnosticsFile('install_preflight_report.json');
  RuntimeReport := EdrDiagnosticsFile('install_runtime_verify.json');
  if LoadStringFromFile(HealthReport, RawHealthReport) then
  begin
    S := RawHealthReport;
    if (Pos('"status":"ok"', S) > 0) or (Pos('"status": "ok"', S) > 0) then
      WizardForm.FinishedHeadingLabel.Caption := 'FDSecurity installed and bootstrap checks passed'
    else
      WizardForm.FinishedHeadingLabel.Caption := 'FDSecurity installed; review bootstrap health report';
    Msg := 'agent.toml: ' + ExpandConstant('{app}\agent.toml') + #13#10
      + 'Health report: ' + HealthReport + #13#10
      + 'Preflight report: ' + PreflightReport + #13#10
      + 'Runtime report: ' + RuntimeReport + #13#10
      + 'Diagnostics bundle: ' + EdrDiagnosticsBundle;
    WizardForm.FinishedLabel.Caption := Msg;
  end
  else if AgentTomlExistsForRun then
  begin
    WizardForm.FinishedHeadingLabel.Caption := 'FDSecurity installed';
    WizardForm.FinishedLabel.Caption := 'agent.toml: ' + ExpandConstant('{app}\agent.toml') + #13#10
      + 'No bootstrap health report was generated. Check enrollment settings if the agent cannot connect.' + #13#10
      + 'Diagnostics directory: ' + EdrDiagnosticsDir;
  end;
end;

function AutorunScriptPresentForUninstall: Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\edr_windows_autorun.ps1'));
end;

function ServiceScriptPresentForUninstall: Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\windows_service_install.ps1'));
end;
