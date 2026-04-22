; Inno Setup 6 — Windows x64 安装向导骨架（选项 B）。
; 平台 setup_exe 默认对象键：installers/setup-exe/<os_type>/<agent_version>/EDRAgentSetup.exe
; 本地编译示例（在仓库根）：
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /DEDR_AGENT_EXE=edr-agent\build\Release\edr_agent.exe edr-agent\install\windows-inno\EDRAgentSetup.iss
;
; 可选：将内网测试用 enroll_test.env 打入安装包（勿把含 Token 的文件提交 git）：
;   1) 复制 compile-secrets.example.env 为 compile-secrets.local.env 并填写 Token
;   2) 在 windows-inno 目录执行 .\prepare_test_enroll_for_iscc.ps1
;   3) ISCC 增加参数: /DEDRCI_BUNDLE_TEST_ENROLL
;
; 安装目录含 edr_agent.exe + 注册脚本：安装完成后在「开始」菜单运行 PowerShell，
; 执行: cd "<安装目录>"; .\edr-terminal-install.ps1 -ApiBase ... -Token ...

#define MyAppName "EDR Agent"
#define MyAppPublisher "EDR"
#define MyAppExeName "edr_agent.exe"
#ifndef EDR_AGENT_EXE
  #define EDR_AGENT_EXE "..\..\build\Release\edr_agent.exe"
#endif

[Setup]
AppId={{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}}
AppName={#MyAppName}
AppVersion=1.0.0
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

[Files]
Source: "{#EDR_AGENT_EXE}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\scripts\edr_agent_install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\scripts\edr_agent_install.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\scripts\edr-terminal-install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\scripts\apply_bundled_test_enroll.ps1"; DestDir: "{app}"; Flags: ignoreversion

#ifdef EDRCI_BUNDLE_TEST_ENROLL
[Files]
Source: "build-ci-test-enroll.env"; DestDir: "{app}"; DestName: "enroll_test.env"; Flags: ignoreversion
#endif

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autoprograms}\{#MyAppName} Enroll"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\edr-terminal-install.ps1"""; WorkingDir: "{app}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

#ifdef EDRCI_BUNDLE_TEST_ENROLL
[Icons]
Name: "{autoprograms}\{#MyAppName} Test Enroll"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\apply_bundled_test_enroll.ps1"""; WorkingDir: "{app}"
#endif
