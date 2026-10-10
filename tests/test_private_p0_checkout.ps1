#Requires -Version 7.0
# Real Windows ACL/process/cleanup tests; Git network I/O alone is isolated.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Private P0 checkout regression requires Windows' }
$path = Join-Path $PSScriptRoot '../scripts/checkout_private_p0_inputs.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Private P0 checkout helper parse failure' }
foreach ($fn in $ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
  . ([scriptblock]::Create($fn.Extent.Text))
}
$nativeGit = (Get-Item Function:Invoke-P0NativeGit).ScriptBlock
function Assert-Test([bool]$Condition, [string]$Cause) { if (-not $Condition) { throw $Cause } }
function Reject-Test([scriptblock]$Call, [string]$Cause) {
  $failed = $false
  try { & $Call } catch { $failed = $_.Exception.Message -like "*$Cause*" }
  Assert-Test $failed "Expected rejection: $Cause"
}
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
$savedTemp = $env:RUNNER_TEMP
$savedKey = $env:P0_TEST_INPUTS_SSH_KEY
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('edr p0 checkout test ' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
# Reproduce the shared runner's Authenticated Users inheritance without changing it.
$rootAcl = Get-Acl -LiteralPath $scratch
$rootAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
  [Security.Principal.SecurityIdentifier]::new('S-1-5-11'), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
Set-Acl -LiteralPath $scratch -AclObject $rootAcl
$rootSddl = (Get-Acl -LiteralPath $scratch).Sddl
$fixedRef = 'a' * 40
$script:calls = [Collections.Generic.List[object]]::new()
$script:delays = [Collections.Generic.List[int]]::new()
$script:credentials = [Collections.Generic.List[string]]::new()
$script:failFetches = 0
$script:failOperation = ''
function Start-Sleep { param([int]$Seconds) $script:delays.Add($Seconds) }
function Invoke-P0NativeGit {
  param([string]$GitExe, [string[]]$Arguments, [string]$SshCommand, [int]$TimeoutSeconds = 60)
  Assert-Test ($SshCommand -match " -i '([^']+)' ") 'Expected a quoted explicit SSH identity'
  $identity = $Matches[1]
  $credentialDirectory = Split-Path -Parent $identity
  $script:credentials.Add($credentialDirectory)
  Assert-P0PrivateAcl $credentialDirectory $owner
  foreach ($leaf in @('identity', 'known_hosts', 'ssh_config')) { Assert-P0PrivateAcl (Join-Path $credentialDirectory $leaf) $owner }
  Assert-Test ([IO.File]::ReadAllText($identity) -eq "synthetic-test-key`n") 'Fixture key normalization failed'
  Assert-Test ([IO.File]::ReadAllText((Join-Path $credentialDirectory 'known_hosts')).Trim() -eq
    'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl') 'Unexpected GitHub host pin'
  Assert-Test ([IO.File]::ReadAllText((Join-Path $credentialDirectory 'ssh_config')) -eq '') 'SSH config must be isolated'
  foreach ($option in @('IdentitiesOnly=yes', 'IdentityAgent=none', 'BatchMode=yes', 'StrictHostKeyChecking=yes',
                         'HostKeyAlgorithms=ssh-ed25519', 'UserKnownHostsFile=', 'GlobalKnownHostsFile=', 'ConnectionAttempts=1')) {
    Assert-Test ($SshCommand.Contains($option)) "Missing SSH constraint: $option"
  }
  $operation = $Arguments[6]
  $script:calls.Add([pscustomobject]@{ Operation = $operation; Arguments = $Arguments; Timeout = $TimeoutSeconds })
  if ($operation -eq 'fetch') {
    Assert-Test ($Arguments[-1] -ceq $fixedRef) 'Fetch must use the frozen full commit'
    if ($script:failFetches -gt 0) { $script:failFetches--; return [pscustomobject]@{ ExitCode = 128; TimedOut = $false; Detail = 'isolated fetch failure' } }
  }
  return [pscustomobject]@{ ExitCode = $(if ($operation -eq $script:failOperation) { 128 } else { 0 }); TimedOut = $false; Detail = 'isolated Git failure' }
}
function Assert-CredentialsClean {
  foreach ($directory in $script:credentials) { Assert-Test (-not (Test-Path -LiteralPath $directory)) 'Temporary credentials survived checkout' }
  Assert-Test (@(Get-ChildItem -LiteralPath $scratch -Filter 'edr-p0-ssh-*' -Force).Count -eq 0) 'Private credential directory survived failure'
  Assert-Test ((Get-Acl -LiteralPath $scratch).Sddl -eq $rootSddl) 'Shared temp ACL changed'
}
try {
  $env:RUNNER_TEMP = $scratch
  $env:P0_TEST_INPUTS_SSH_KEY = "synthetic-test-key`r`n"
  $success = Join-Path $scratch 'successful inputs'
  $script:failFetches = 2
  Invoke-P0PrivateCheckout $success $fixedRef
  Assert-Test ((@($script:calls | Where-Object Operation -eq 'fetch')).Count -eq 3) 'Fetch retries were not bounded to three'
  Assert-Test (($script:delays -join ',') -eq '2,4') 'Fetch retry backoff changed'
  Assert-Test ((@($script:calls | Where-Object Operation -eq 'checkout')).Count -eq 1) 'Successful fetch did not reach detached checkout'
  Assert-Test ((@($script:calls | Where-Object Operation -in @('init', 'remote') | Where-Object Timeout -ne 10)).Count -eq 0) 'Local init deadlines changed'
  Assert-Test ($script:calls[-1].Timeout -eq 15) 'Checkout deadline changed'
  Assert-P0PrivateAcl $success $owner
  Assert-CredentialsClean
  $script:calls.Clear(); $script:delays.Clear(); $script:failFetches = 9
  $failure = Join-Path $scratch 'failed inputs'
  Reject-Test { Invoke-P0PrivateCheckout $failure $fixedRef } 'fetch failed after 3 attempts'
  Assert-Test ((@($script:calls | Where-Object Operation -eq 'fetch')).Count -eq 3) 'Terminal fetch failure retried beyond its limit'
  Assert-Test ((@($script:calls | Where-Object Operation -eq 'checkout')).Count -eq 0) 'Failed fetch reached checkout'
  Assert-Test (-not (Test-Path -LiteralPath $failure)) 'Failed checkout left partial inputs'
  Assert-CredentialsClean
  foreach ($operation in @('init', 'checkout')) {
    $script:failFetches = 0; $script:failOperation = $operation
    Reject-Test { Invoke-P0PrivateCheckout $failure $fixedRef } 'isolated Git failure'
    Assert-Test (-not (Test-Path -LiteralPath $failure)) 'Local Git failure left partial inputs'
    Assert-CredentialsClean
  }
  $script:failOperation = ''
  Reject-Test { Invoke-P0PrivateCheckout $failure 'main' } 'fixed lowercase 40-hex'
  $env:P0_TEST_INPUTS_SSH_KEY = ''
  Reject-Test { Invoke-P0PrivateCheckout $failure $fixedRef } 'deploy key is required'
  $env:P0_TEST_INPUTS_SSH_KEY = 'synthetic-test-key'
  Reject-Test { Invoke-P0PrivateCheckout $success $fixedRef } 'must be absent'
  Assert-Test (Test-Path -LiteralPath $success) 'Existing checkout was removed'
  Assert-CredentialsClean
  $badKey = Join-Path $success 'synthetic identity'
  [IO.File]::WriteAllText($badKey, 'synthetic-test-key')
  Set-P0PrivateAcl $badKey $owner
  $badAcl = Get-Acl -LiteralPath $badKey
  $badAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-5-11'), 'Read', 'Allow'))
  Set-Acl -LiteralPath $badKey -AclObject $badAcl
  Reject-Test { Assert-P0PrivateAcl $badKey $owner } 'permits a non-owner'
  Set-P0PrivateAcl $badKey $owner
  Assert-P0PrivateAcl $badKey $owner
  Assert-Test ((Quote-P0SshArgument "C:\has space\owner's key") -ceq "'C:/has space/owner'\''s key'") 'SSH shell quoting changed'
  # Execute the real process owner to verify child-secret exclusion and cancellation.
  $pwsh = Join-Path $PSHOME 'pwsh.exe'
  $result = & $nativeGit $pwsh @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'if (Test-Path Env:P0_TEST_INPUTS_SSH_KEY) { exit 55 }; exit 0') 'synthetic-command' -TimeoutSeconds 10
  Assert-Test ($result.ExitCode -eq 0 -and -not $result.TimedOut) 'Git child inherited the private-key secret'
  $result = & $nativeGit $pwsh @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30') 'synthetic-command' -TimeoutSeconds 1
  Assert-Test ($result.TimedOut -and $result.Detail -like '*1-second deadline*') 'Native process timeout did not terminate the child'
  Assert-CredentialsClean
  Write-Host 'PASS: owner-only Windows ACLs, fixed identity/pin, bounded retries, credential cleanup and child process isolation'
} finally {
  $env:RUNNER_TEMP = $savedTemp
  $env:P0_TEST_INPUTS_SSH_KEY = $savedKey
  Remove-Item -LiteralPath $scratch -Recurse -Force
}
