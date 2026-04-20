; Inno Setup 6 — Windows x64 安装向导骨架（选项 B）。
; 平台 setup_exe 默认对象键：installers/setup-exe/<os_type>/<agent_version>/EDRAgentSetup.exe
; 本地编译示例（在仓库根）：
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /DEDR_AGENT_EXE=edr-agent\build\Release\edr_agent.exe edr-agent\install\windows-inno\EDRAgentSetup.iss

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

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
