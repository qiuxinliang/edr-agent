#Requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$RepositoryRoot)
$ErrorActionPreference = 'Stop'
$source = Join-Path $RepositoryRoot 'install/windows-inno/edr_windows_autorun.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Autorun source does not parse' }
# Generate the real task owner without installing a task or running an Agent.
foreach ($name in @('Quote-ForSingleQuotedPowerShell', 'Write-TaskLauncher')) {
  $node = $ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name}, $true)
  if (-not $node) { throw "Missing production function: $name" }
  . ([scriptblock]::Create($node.Extent.Text))
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('edr-task-trace-' + [Guid]::NewGuid().ToString('N'))
$names = @('EDR_VALIDATION_TRACE_PATH', 'EDR_VALIDATION_TRACE_IMAGE', 'EDR_VALIDATION_TRACE_PURPOSE')
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
function Read-MachineTraceValue([string]$Name) {
  if ($script:machine.ContainsKey($Name)) { return $script:machine[$Name] }
  return $null
}
try {
  [IO.Directory]::CreateDirectory($root) | Out-Null
  $launcher = Write-TaskLauncher -Exe (Join-Path $root 'not-executed.exe') -Config (Join-Path $root 'not-executed.config') -Dir $root
  $tokens = $null; $errors = $null
  $generated = [Management.Automation.Language.Parser]::ParseFile($launcher, [ref]$tokens, [ref]$errors)
  if ($errors.Count) { throw 'Generated launcher does not parse' }
  $refresh = @($generated.FindAll({param($n) $n -is [Management.Automation.Language.ForEachStatementAst] -and $n.Variable.VariablePath.UserPath -eq 'traceEnv'}, $true))
  if ($refresh.Count -ne 1) { throw 'Generated trace refresh owner must be unique' }
  # Replace only the external machine-environment read. The generated list,
  # iteration, value forwarding, and real process-environment writes execute.
  $read = '[Environment]::GetEnvironmentVariable($traceEnv, "Machine")'
  $body = $refresh[0].Extent.Text
  if (($body.Split(@($read), [StringSplitOptions]::None)).Count -ne 2) { throw 'Machine read boundary changed' }
  $run = [scriptblock]::Create($body.Replace($read, '(Read-MachineTraceValue $traceEnv)'))
  $cases = @(
    @{name='default'; values=@{}},
    @{name='parent_identity'; values=@{EDR_VALIDATION_TRACE_PATH='C:\fixture\parent.jsonl'; EDR_VALIDATION_TRACE_IMAGE='truth.exe'; EDR_VALIDATION_TRACE_PURPOSE='parent_identity'}},
    @{name='explicit_egress'; values=@{EDR_VALIDATION_TRACE_PATH='C:\fixture\egress.jsonl'; EDR_VALIDATION_TRACE_IMAGE='truth.exe'; EDR_VALIDATION_TRACE_PURPOSE='egress_validation'}},
    @{name='purpose_removed'; values=@{EDR_VALIDATION_TRACE_PATH='C:\fixture\default.jsonl'; EDR_VALIDATION_TRACE_IMAGE='truth.exe'}},
    @{name='all_removed'; values=@{}},
    @{name='invalid_purpose_forwarded'; values=@{EDR_VALIDATION_TRACE_PURPOSE='invalid_purpose'}}
  )
  $results = @()
  foreach ($case in $cases) {
    $script:machine = $case.values
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, 'stale_inherited_value', 'Process') }
    . $run
    foreach ($name in $names) {
      $expected = if ($script:machine.ContainsKey($name)) { $script:machine[$name] } else { $null }
      $actual = [Environment]::GetEnvironmentVariable($name, 'Process')
      if ($actual -cne $expected) { throw "Trace refresh mismatch: case=$($case.name) variable=$name" }
    }
    $results += @{case=$case.name; status='PASS'}
  }
  @{test='windows_task_trace_environment'; cases=$results; agent_executions=0; task_changes=0; machine_writes=0; substitution='Machine environment reads only; real generated process refresh executes'} | ConvertTo-Json -Depth 4 -Compress | Write-Host
} finally {
  foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
  if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
