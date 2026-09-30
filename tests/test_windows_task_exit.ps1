#Requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$RepositoryRoot,
      [Parameter(Mandatory=$true)][string]$Fixture)
$ErrorActionPreference = 'Stop'
$source = Join-Path $RepositoryRoot 'install/windows-inno/edr_windows_autorun.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Autorun source does not parse' }
# Use the production generator without installing a scheduled task or touching
# a real Agent. Each launcher owns only its temporary fixture process.
foreach ($name in @('Quote-ForSingleQuotedPowerShell', 'Write-TaskLauncher')) {
  $node = $ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name}, $true)
  if (-not $node) { throw "Missing production function: $name" }
  . ([scriptblock]::Create($node.Extent.Text))
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('edr-task-exit-' + [Guid]::NewGuid().ToString('N'))
try {
  foreach ($delay in @(100, 5500)) {
    foreach ($code in @('0', 'c0000005')) {
      $dir = Join-Path $root ("$delay-$code")
      [IO.Directory]::CreateDirectory($dir) | Out-Null
      $exe = Join-Path $dir 'fixture.exe'
      Copy-Item -LiteralPath $Fixture -Destination $exe
      $cfg = Join-Path $dir 'fixture.config'
      [IO.File]::WriteAllText($cfg, "$delay $code")
      $launcher = Write-TaskLauncher -Exe $exe -Config $cfg -Dir $dir
      $p = Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $launcher)
      ) -WindowStyle Hidden -PassThru
      try {
        $null = $p.Handle
        if (-not $p.WaitForExit(15000)) {
          $p.Kill() # Only our exact test launcher; its job owns the fixture.
          $null = $p.WaitForExit(2000)
          throw 'Test launcher exceeded 15 seconds'
        }
        $expected = if ($code -eq '0') { 0 } else { -1073741819 }
        $taskExit = if ($delay -lt 4000) { 4 } else { $expected }
        $log = [IO.File]::ReadAllText((Join-Path $dir 'logs/startup-task.log'))
        $event = if ($delay -lt 4000) { 'process_exited_early' } else { 'process_exit' }
        if ($null -eq $p.ExitCode -or $p.ExitCode -ne $taskExit -or
            $log -notmatch "$event exit_code=$expected(?:\s|$)") {
          throw "Wrong task exit receipt: delay=$delay code=$code actual=$($p.ExitCode) log=$log"
        }
      } finally { $p.Dispose() }
    }
  }
  Write-Host 'windows_task_exit: PASS (early/late success and native failure)'
} finally {
  if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
