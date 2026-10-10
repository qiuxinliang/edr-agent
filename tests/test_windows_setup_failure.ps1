#Requires -Version 5.1
[CmdletBinding()]
param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('edr-setup-failure-' + [Guid]::NewGuid().ToString('N'))
$originalProgramData = $env:ProgramData
New-Item -ItemType Directory -Path $root | Out-Null
function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Invoke-FiniteProcess([string]$Path, [string[]]$Arguments) {
  $process = Start-Process -FilePath $Path -ArgumentList $Arguments -PassThru
  try {
    if (-not $process.WaitForExit(45000)) {
      Stop-Process -Id $process.Id -Force -ErrorAction Stop
      [void]$process.WaitForExit(5000)
      throw 'Installer failure fixture exceeded 45 seconds; silent failure must terminate'
    }
    return $process.ExitCode
  } finally { $process.Dispose() }
}
try {
  $inno = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
  if (-not (Test-Path -LiteralPath $inno -PathType Leaf)) {
    $command = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if (-not $command) { throw 'Inno Setup 6 is required for the native silent-failure regression' }
    $inno = $command.Source
  }
  $source = [IO.File]::ReadAllText((Join-Path $RepoRoot 'install/windows-inno/EDRAgentSetup.bundled.iss'))
  $owners = @()
  foreach ($declaration in @('procedure EdrAppendStageLog\(const Message: string\);',
      'procedure EdrAbortInstall;', 'function GetCustomSetupExitCode: Integer;')) {
    $matches = [regex]::Matches($source, '(?ms)^' + $declaration + '\r?\n.*?^end;')
    Assert-True ($matches.Count -eq 1) ('Missing unique installer owner: ' + $declaration)
    $owners += $matches[0].Value
  }
  # Isolate only rollback's external command. It cannot touch services/processes.
  $rollback = Join-Path $root 'RollbackFixture.exe'
  Add-Type -TypeDefinition 'public static class RollbackFixture { public static int Main(string[] args) { return 0; } }' `
    -OutputAssembly $rollback -OutputType ConsoleApplication
  $fixture = @'
#define MyServiceName "FixtureService"
#define MyLegacyServiceName "FixtureLegacyService"
#define MyLegacyProcessName "FixtureLegacyProcess"
[Setup]
AppName=Installer failure fixture
AppVersion=1.0.0
DefaultDirName={tmp}\edr-setup-failure-app
CreateAppDir=no
Uninstallable=no
PrivilegesRequired=lowest
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
UseSetupLdr=no
OutputBaseFilename=SetupFailureFixture
[Code]
var
  EdrInstallFailed, EdrHadExistingInstallation: Boolean;
  EdrCurrentStage, EdrFailureReason, EdrDiagnosticsBundle, EdrStageLog: string;
  EdrProgressPage: TOutputProgressWizardPage;
function EdrPowerShellPath: string;
begin
  Result := '@ROLLBACK@';
end;
function EdrPsSq(const S: string): string;
begin
  Result := S;
end;
procedure EdrCreateDiagnosticsBundle;
begin
  SaveStringToFile(EdrDiagnosticsBundle, 'diagnostics preserved', False);
  EdrAppendStageLog('diagnostics_bundle_written');
end;
@OWNERS@
procedure InitializeWizard;
begin
  EdrProgressPage := CreateOutputProgressPage('Fixture', 'Fixture');
end;
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep <> ssPostInstall then Exit;
  EdrStageLog := ExpandConstant('{param:STAGELOG}');
  EdrDiagnosticsBundle := EdrStageLog + '.diagnostics';
  if ExpandConstant('{param:FAILURE|1}') = '0' then Exit;
  EdrHadExistingInstallation := ExpandConstant('{param:EXISTING|0}') = '1';
  EdrCurrentStage := 'Start Agent runtime';
  EdrFailureReason := 'Start Agent runtime failed with exit code 5';
  EdrAbortInstall;
  EdrAppendStageLog('unexpected_failure_continuation');
end;
'@
  # EdrCreateDiagnosticsBundle calls the real logger; declare the logger first.
  $fixture = $fixture.Replace('procedure EdrCreateDiagnosticsBundle;', $owners[0] + "`r`nprocedure EdrCreateDiagnosticsBundle;")
  $fixture = $fixture.Replace('@ROLLBACK@', $rollback.Replace("'", "''")).Replace('@OWNERS@', ($owners[1..2] -join "`r`n"))
  $fixtureSource = Join-Path $root 'failure.iss'
  [IO.File]::WriteAllText($fixtureSource, $fixture, [Text.UTF8Encoding]::new($true))
  Assert-True ((Invoke-FiniteProcess $inno @('/Q', ('/O"{0}"' -f $root), ('"{0}"' -f $fixtureSource))) -eq 0) 'Failure fixture must compile'
  $setup = Join-Path $root 'SetupFailureFixture.exe'
  foreach ($silent in @('/VERYSILENT', '/SILENT')) {
    foreach ($existing in @(0, 1)) {
      $stageLog = Join-Path $root ('stage-{0}-{1}.log' -f $silent.TrimStart('/'), $existing)
      $setupLog = $stageLog + '.setup.log'
      $code = Invoke-FiniteProcess $setup @($silent, '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-',
        ('/STAGELOG="{0}"' -f $stageLog), ('/EXISTING={0}' -f $existing), ('/LOG="{0}"' -f $setupLog))
      Assert-True ($code -eq 4) 'Post-install failure must return installation error 4, never successful exit 0'
      $log = [IO.File]::ReadAllText($stageLog)
      Assert-True ($log.Contains('INSTALL_WORKFLOW_FAILED stage=Start Agent runtime reason=Start Agent runtime failed with exit code 5')) 'Original failed stage/reason must remain'
      $rollbackMarker = if ($existing) { 'previous_runtime_restart exit=0' } else { 'INSTALL_FAILURE_ROLLBACK completed' }
      Assert-True ($log.Contains($rollbackMarker)) 'The selected rollback/restart branch must finish before returning'
      Assert-True ($log.Contains('diagnostics_bundle_written') -and (Test-Path -LiteralPath ($stageLog + '.diagnostics'))) 'Diagnostics must survive failure'
      Assert-True (-not $log.Contains('unexpected_failure_continuation')) 'RaiseException must still stop the installer workflow'
    }
    $code = Invoke-FiniteProcess $setup @($silent, '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', '/FAILURE=0',
      ('/STAGELOG="{0}"' -f (Join-Path $root 'success.log')))
    Assert-True ($code -eq 0) 'A successful installer must retain exit 0'
  }
  # Exercise the actual CI catch with a diagnostic I/O failure. Preserve the
  # installer's original error and stage; do not inspect real ProgramData logs.
  $tokens = $null; $parseErrors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'scripts/windows_setup_exe_lifecycle_smoke.ps1'), [ref]$tokens, [ref]$parseErrors)
  Assert-True (@($parseErrors).Count -eq 0) 'Setup lifecycle source must parse'
  foreach ($name in @('Copy-InstallerDiagnostics', 'Add-Evidence')) {
    $node = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name })
    Assert-True ($node.Count -eq 1) ('Missing unique lifecycle owner: ' + $name)
    . ([scriptblock]::Create($node[0].Extent.Text))
  }
  $mainTry = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })
  Assert-True ($mainTry.Count -eq 1 -and $mainTry[0].CatchClauses.Count -eq 1) 'Lifecycle must have one terminal failure handler'
  $catchText = $mainTry[0].CatchClauses[0].Body.Extent.Text
  $catchBody = [scriptblock]::Create($catchText.Substring(1, $catchText.Length - 2))
  $env:ProgramData = $root
  $EvidenceDir = $root
  $events = New-Object System.Collections.Generic.List[object]
  $script:LastLifecycleStage = 'install-target-fresh'
  $script:LastSetupLog = $setupLog
  function Get-Content { [CmdletBinding()]param($LiteralPath, $Tail) throw [IO.IOException]::new('fixture diagnostic read failed') }
  $captured = $null
  try { throw [InvalidOperationException]::new('Setup EXE install-target-fresh failed with exit code 4') }
  catch { try { . $catchBody } catch { $captured = $_ } }
  Assert-True ($captured.Exception.Message -ceq 'Setup EXE install-target-fresh failed with exit code 4') 'Diagnostic collection must not replace the original installer error'
  Assert-True ($events.Count -eq 1 -and $events[0].stage -ceq 'lifecycle' -and $events[0].status -ceq 'failed' -and
    $events[0].detail -ceq $captured.Exception.Message -and $script:LastLifecycleStage -ceq 'install-target-fresh') 'CI failure evidence must retain the original stage and reason'
  Write-Host 'PASS: real Inno silent failure and successful exit; rollback/diagnostics; original CI failure survives diagnostic I/O errors'
} finally {
  $env:ProgramData = $originalProgramData
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
