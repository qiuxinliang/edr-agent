; Inno Setup 6 — Windows x64 安装向导骨架（选项 B）。
; 平台 setup_exe 默认对象键：installers/setup-exe/<os_type>/<agent_version>/FDSecuritySetup.exe
; 本地编译示例（在 edr-agent 仓库根）：
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /DEDR_AGENT_EXE=build\Release\FDSensor.exe /DMyAppVersion=1.0.1 install\windows-inno\EDRAgentSetup.iss
;
; 静默 + 命令行注册（与向导页二选一；Token 会出现在进程命令行，见 docs/AGENT_INSTALLER.md）：
;   长参数：/EDR_API_BASE=... /EDR_ENROLL_TOKEN=...  可选 /EDR_INSECURE_TLS=1
;   短参数：/API=... /TOK=...  可选 /TLS=1（与长参数等价；长参数优先）
;   示例：... /VERYSILENT /API=https://host:8080 /TOK=your-token
;   /MERGETASKS=enrollinsecure 与 /TLS=1 同类效果

; 该脚本仅保留给实验室兼容验证。生产安装包必须使用
; Build-BundledInstaller.ps1 + EDRAgentSetup.bundled.iss，以确保携带原生 worker
; 并对 ACL、服务/计划任务启动及 Agent 进程存活执行强校验。
#ifndef EDR_ALLOW_LEGACY_INSTALLER
  #error Legacy installer disabled. Use Build-BundledInstaller.ps1, or define EDR_ALLOW_LEGACY_INSTALLER=1 for lab-only compatibility testing.
#endif

#define MyAppName "FDSecurity"
#define MyAppPublisher "FDSecurity"
#define MyAppExeName "FDSensor.exe"
#ifndef EDR_AGENT_EXE
  #define EDR_AGENT_EXE "..\..\build\Release\FDSensor.exe"
#endif
#ifndef EDR_AGENT_TOML_EXAMPLE
  #define EDR_AGENT_TOML_EXAMPLE "..\..\agent.toml.example"
#endif
#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif
#ifndef EDR_TARGET_ARCH
  #define EDR_TARGET_ARCH "amd64"
#endif
#ifdef EDR_TARGET_ARM64
  #define EDR_SETUP_ARCH "arm64"
#else
  #define EDR_SETUP_ARCH "x64os"
  #define EDR_WINDIVERT_RUNTIME_DIR "..\..\third_party\windivert\runtime\amd64"
#endif
#define EDR_WINDIVERT_LICENSE "..\..\third_party\windivert\LICENSE"
#define EDR_WINDIVERT_SOURCE "..\..\third_party\windivert\SOURCE.json"

[Setup]
AppId={{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed={#EDR_SETUP_ARCH}
ArchitecturesInstallIn64BitMode={#EDR_SETUP_ARCH}
OutputDir=Output
OutputBaseFilename=FDSecuritySetup
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
Source: "{#EDR_AGENT_EXE}"; DestDir: "{app}"; Flags: ignoreversion
; 与 FDSensor.exe 同目录：ONNX + vcpkg 运行时 DLL（发布 CI 在 ISCC 前 stage 到 build\Release\）
Source: "..\..\build\Release\*.dll"; DestDir: "{app}"; Excludes: "WinDivert.dll,onnxruntime*.dll,*.pdb,*.ilk,*.exp,*.lib,*.xml"; Flags: ignoreversion skipifsourcedoesntexist
#ifndef EDR_TARGET_ARM64
Source: "{#EDR_WINDIVERT_RUNTIME_DIR}\WinDivert.dll"; DestDir: "{app}"; Flags: ignoreversion; Check: not IsArm64
Source: "{#EDR_WINDIVERT_RUNTIME_DIR}\WinDivert64.sys"; DestDir: "{app}"; Flags: ignoreversion; Check: not IsArm64
#endif
Source: "{#EDR_WINDIVERT_LICENSE}"; DestDir: "{app}\licenses"; DestName: "WinDivert-LICENSE.txt"; Flags: ignoreversion
Source: "{#EDR_WINDIVERT_SOURCE}"; DestDir: "{app}\licenses"; DestName: "WinDivert-SOURCE.json"; Flags: ignoreversion
; models\：与 config.c 中「exe 同目录\models」及 agent.toml.example [ave] 约定一致；占位文件便于空目录随包安装
Source: "..\..\models\*"; DestDir: "{app}\models"; Excludes: "behavior.onnx,static_fp32.onnx,*.training.*,*.tmp"; Flags: ignoreversion recursesubdirs createallsubdirs
; 第一版动态前置规则包（由 edr-backend/platform/config/generate_agent_preprocess_rules.py 生成）
Source: "..\..\..\edr-backend\platform\config\agent_preprocess_rules_v1.toml"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#EDR_AGENT_TOML_EXAMPLE}"; DestDir: "{app}"; DestName: "agent.toml.example"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\config\agent_windows_production.example.toml"; DestDir: "{app}\config"; Flags: ignoreversion
Source: "..\..\config\p0_rule_bundle_ir_v1.json.enc"; DestDir: "{app}\edr_config"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\config\sensor_interest_manifest.json"; DestDir: "{app}\edr_config"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\scripts\edr_agent_install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\scripts\edr_agent_preflight.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\scripts\windows_service_install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\scripts\windows_isolate_host.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "edr_install_wizard_enroll.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "edr_windows_autorun.ps1"; DestDir: "{app}"; Flags: ignoreversion
; 取证采集器(发布 CI 在 ISCC 前 stage 到 build\Release\collector\):
;   forensic_collector.exe(Go/主) + forensic_collector_builtin.exe(C 兜底)。
;   非 bundled 安装包**不内置 velociraptor.exe**(体积大):autorun 根据 agent.toml 的
;   rest_base_url 写入 adapter/velociraptor 两个 manifest 地址,由 agent 按需下载/刷新。
;   缺失不致命→agent 三层兜底(velo→builtin→in-process)。
Source: "..\..\build\Release\collector\forensic_collector.exe"; DestDir: "{app}\collector"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\build\Release\collector\forensic_collector_builtin.exe"; DestDir: "{app}\collector"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\build\Release\collector\*.LICENSE.txt"; DestDir: "{app}\collector"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\build\Release\collector\*.SOURCE.txt"; DestDir: "{app}\collector"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Parameters: "--config ""{app}\agent.toml"""
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Parameters: "--config ""{app}\agent.toml"""; Tasks: desktopicon

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\edr_install_wizard_enroll.ps1"" ""{tmp}\edr_wizard_enroll.json"" ""{app}\agent.toml"""; StatusMsg: "Registering with platform..."; Flags: waituntilterminated; Check: EnrollParamsFileExists
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""$app='{app}'; $cfg=Join-Path $app 'agent.toml'; $ex=Join-Path $app 'agent.toml.example'; if (-not (Test-Path -LiteralPath $cfg)) {{ if (Test-Path -LiteralPath $ex) {{ Copy-Item -LiteralPath $ex -Destination $cfg -Force }} else {{ throw 'agent.toml was not generated and agent.toml.example is missing' }} }}; if (-not (Test-Path -LiteralPath $cfg)) {{ throw 'agent.toml was not generated' }}; $takeown=Get-Command 'takeown.exe' -ErrorAction SilentlyContinue; if($takeown){{try{{& $takeown.Source /F $cfg /A | Out-Null}}catch{{}}}}; $icacls=Get-Command 'icacls.exe' -ErrorAction SilentlyContinue; if($icacls){{try{{& $icacls.Source $cfg /inheritance:r /grant:r '*S-1-5-18:F' /grant:r '*S-1-5-32-544:F' /C /Q | Out-Null}}catch{{}}}}; $raw=[System.IO.File]::ReadAllText($cfg); if([string]::IsNullOrWhiteSpace($raw)) {{ throw 'agent.toml is empty' }}; if($icacls){{try{{& $icacls.Source $cfg /inheritance:r /grant:r '*S-1-5-18:F' /grant:r '*S-1-5-32-544:F' /C /Q | Out-Null}}catch{{}}}}"""; StatusMsg: "Ensuring agent.toml..."; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Parameters: "--config ""{app}\agent.toml"""; WorkingDir: "{app}"; Description: "Start FDSecurity now (console window; skip if startup task is enabled)"; Flags: postinstall nowait skipifsilent; Check: ShouldPostinstallStartExe
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "{code:AutorunInstallPsParameters}"; StatusMsg: "Configuring startup task..."; Flags: waituntilterminated; Check: ShouldInstallAutorun

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\windows_service_install.ps1"" -Action Uninstall -InstallDir ""{app}"" -DataDir ""{app}"" -ExePath ""{app}\FDSensor.exe"" -ConfigPath ""{app}\agent.toml"""; RunOnceId: "EdrServiceRemove"; Flags: runhidden waituntilterminated; Check: ServiceScriptPresentForUninstall
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\edr_windows_autorun.ps1"" -Action Remove"; RunOnceId: "EdrAutorunRemove"; Flags: runhidden waituntilterminated; Check: AutorunScriptPresentForUninstall

[UninstallDelete]
Type: files; Name: "{app}\*.pid"
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
Type: filesandordirs; Name: "{localappdata}\FDSecurity\setup-ui"
Type: dirifempty; Name: "{localappdata}\FDSecurity"

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

function SaveEnrollParamsFileIfNeeded: Boolean;
var
  Path, U, T, Json: string;
  Insecure: Boolean;
begin
  Result := False;
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
  if (U = '') or (T = '') then
    Exit;

  Path := ExpandConstant('{tmp}\edr_wizard_enroll.json');
  Json := Chr(123) + Chr(34) + 'api_base' + Chr(34) + ':' + JsonEscape(U) + ',' + Chr(34) + 'token' + Chr(34) + ':' + JsonEscape(T) + ',' +
    Chr(34) + 'insecure_tls' + Chr(34) + ':';
  Insecure := EdrCmdInsecureTls or WizardIsTaskSelected('enrollinsecure');
  if Insecure then
    Json := Json + 'true' + Chr(125)
  else
    Json := Json + 'false' + Chr(125);

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
    + 'Stop-Service -Name ''FDSecurityAgent'' -Force -ErrorAction SilentlyContinue;'
    + 'Stop-Service -Name ''EdrAgent'' -Force -ErrorAction SilentlyContinue;'
    + 'Stop-Process -Name FDSensor -Force -ErrorAction SilentlyContinue;'
    + 'Stop-Process -Name edr_agent -Force -ErrorAction SilentlyContinue;'
    + 'Remove-Item -LiteralPath (Join-Path $d ''FDSensor.pid'') -Force -ErrorAction SilentlyContinue;'
    + 'Remove-Item -LiteralPath (Join-Path $d ''edr_agent.pid'') -Force -ErrorAction SilentlyContinue;'
    + 'Remove-Item -Path (Join-Path $d ''queue\edr_queue.db*'') -Force -ErrorAction SilentlyContinue;'
    + 'Remove-Item -Path (Join-Path $d ''evidence\local_evidence_cache.db*'') -Force -ErrorAction SilentlyContinue;'
    + '"';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Cmd, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Result := 'Failed to run EDR preflight cleanup before installing.';
end;

procedure InitializeWizard;
begin
  EnrollPage := CreateInputQueryPage(wpWelcome,
    'Platform enrollment',
    'Enter your platform REST base URL and enrollment token. Your administrator issues the token after creating the endpoint.',
    'When both fields are filled, the installer calls POST /api/v1/enroll and writes a complete agent.toml next to FDSensor.exe (bundled template + your server/tenant/endpoint). Leave both empty to skip and start from a copy of agent.toml.example instead.');
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
    if Result then
      SaveEnrollParamsFileIfNeeded;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  AppToml, ExToml: string;
begin
  if CurStep <> ssPostInstall then
    Exit;
  if SaveEnrollParamsFileIfNeeded then
    Exit;

  AppToml := ExpandConstant('{app}\agent.toml');
  ExToml := ExpandConstant('{app}\agent.toml.example');
  if (not FileExists(AppToml)) and FileExists(ExToml) then
  begin
    if not FileCopy(ExToml, AppToml, False) then
      Log('CurStepChanged: FileCopy agent.toml.example -> agent.toml failed');
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

function ServiceScriptPresentForUninstall: Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\windows_service_install.ps1'));
end;
