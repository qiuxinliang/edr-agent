#Requires -Version 7.0
[CmdletBinding()]
param(
  [string]$Directory = '.p0-test-inputs',
  [string]$Ref = $env:P0_TEST_INPUTS_REF
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Set-P0PrivateAcl {
  param([string]$Path, [Security.Principal.SecurityIdentifier]$Owner, [switch]$Directory)
  $acl = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
  $acl.SetOwner($Owner)
  $acl.SetAccessRuleProtection($true, $false)
  if ($Directory) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($Owner, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
  } else {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($Owner, 'FullControl', 'Allow')
  }
  $acl.AddAccessRule($rule)
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-P0PrivateAcl {
  param([string]$Path, [Security.Principal.SecurityIdentifier]$Owner)
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Private P0 checkout path must not be a reparse point' }
  $acl = Get-Acl -LiteralPath $Path
  $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
  if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $Owner.Value -or $rules.Count -eq 0) {
    throw 'Private P0 checkout ACL must be protected and owned by the current SID'
  }
  foreach ($rule in $rules) {
    if ($rule.IdentityReference.Value -ne $Owner.Value -or $rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or
        ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) {
      throw 'Private P0 checkout ACL permits a non-owner or lacks full owner access'
    }
    if ($item.PSIsContainer -and ($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -eq 0) {
      throw 'Private P0 checkout directory ACL must inherit to child directories'
    }
    if ($item.PSIsContainer -and ($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit) -eq 0) {
      throw 'Private P0 checkout directory ACL must inherit to child files'
    }
    if ($rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
        (-not $item.PSIsContainer -and $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None)) {
      throw 'Private P0 checkout ACL has unexpected inheritance propagation'
    }
  }
}

function Quote-P0SshArgument {
  param([string]$Value)
  return "'" + $Value.Replace('\', '/').Replace("'", "'\''") + "'"
}

function Invoke-P0NativeGit {
  param([string]$GitExe, [string[]]$Arguments, [string]$SshCommand, [int]$TimeoutSeconds = 60)
  $process = [Diagnostics.Process]::new()
  $process.StartInfo.FileName = $GitExe
  $process.StartInfo.UseShellExecute = $false
  $process.StartInfo.RedirectStandardOutput = $true
  $process.StartInfo.RedirectStandardError = $true
  foreach ($argument in $Arguments) { $process.StartInfo.ArgumentList.Add($argument) }
  $process.StartInfo.Environment['GIT_SSH_COMMAND'] = $SshCommand
  $process.StartInfo.Environment['GIT_SSH_VARIANT'] = 'ssh'
  $process.StartInfo.Environment['GIT_TERMINAL_PROMPT'] = '0'
  [void]$process.StartInfo.Environment.Remove('P0_TEST_INPUTS_SSH_KEY')
  try {
    if (-not $process.Start()) { throw 'Private P0 Git process could not start' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
      $process.Kill($true)
      if (-not $process.WaitForExit(5000)) { throw 'Private P0 Git process did not stop after timeout' }
    }
    [void]$stdout.GetAwaiter().GetResult()
    $errorText = $stderr.GetAwaiter().GetResult()
    $detail = 'Git operation failed; check fixed repository/ref access and runner connectivity'
    if ($timedOut) { $detail = "Git operation exceeded its $TimeoutSeconds-second deadline" }
    elseif ($errorText -match 'Host key verification failed|REMOTE HOST IDENTIFICATION') { $detail = 'GitHub host-key pin verification failed' }
    elseif ($errorText -match 'Bad permissions|UNPROTECTED PRIVATE KEY|too open') { $detail = 'Native SSH rejected the temporary private-key ACL' }
    elseif ($errorText -match 'Permission denied.*publickey') { $detail = 'GitHub rejected the dedicated read-only deploy key' }
    return [pscustomobject]@{ ExitCode = $process.ExitCode; TimedOut = $timedOut; Detail = $detail }
  } finally { $process.Dispose() }
}

function Invoke-P0PrivateCheckout {
  param([string]$Directory, [string]$Ref)
  if ($env:OS -ne 'Windows_NT') { throw 'Private P0 checkout requires native Windows PowerShell 7' }
  if ($Ref -cnotmatch '^[0-9a-f]{40}$') { throw 'P0_TEST_INPUTS_REF must be a fixed lowercase 40-hex commit' }
  if ([string]::IsNullOrWhiteSpace($env:P0_TEST_INPUTS_SSH_KEY)) { throw 'P0_TEST_INPUTS_SSH_KEY dedicated read-only deploy key is required' }
  if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { throw 'RUNNER_TEMP is required for private P0 credentials' }
  $git = (Get-Command git.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
  $ssh = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
  if (-not (Test-Path -LiteralPath $ssh -PathType Leaf)) { throw 'Native Windows OpenSSH client is unavailable' }
  $directory = [IO.Path]::GetFullPath($Directory)
  if (Test-Path -LiteralPath $directory) { throw 'Private P0 test checkout directory must be absent before delivery' }
  $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $temporary = Join-Path $env:RUNNER_TEMP ('edr-p0-ssh-' + [Guid]::NewGuid().ToString('N'))
  $createdCheckout = $false
  $succeeded = $false
  try {
    New-Item -ItemType Directory -Path $temporary | Out-Null
    Set-P0PrivateAcl $temporary $owner -Directory
    Assert-P0PrivateAcl $temporary $owner
    New-Item -ItemType Directory -Path $directory | Out-Null
    $createdCheckout = $true
    Set-P0PrivateAcl $directory $owner -Directory
    Assert-P0PrivateAcl $directory $owner
    $key = Join-Path $temporary 'identity'
    $knownHosts = Join-Path $temporary 'known_hosts'
    $config = Join-Path $temporary 'ssh_config'
    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($key, $env:P0_TEST_INPUTS_SSH_KEY.Replace("`r`n", "`n").Trim() + "`n", $encoding)
    # Literal official GitHub pin; never trust runtime ssh-keyscan output.
    # https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
    [IO.File]::WriteAllText($knownHosts, "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl`n", $encoding)
    [IO.File]::WriteAllText($config, '', $encoding)
    foreach ($file in @($key, $knownHosts, $config)) { Set-P0PrivateAcl $file $owner; Assert-P0PrivateAcl $file $owner }
    $sshCommand = (Quote-P0SshArgument $ssh) + ' -F ' + (Quote-P0SshArgument $config) + ' -i ' + (Quote-P0SshArgument $key) +
      ' -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes -o StrictHostKeyChecking=yes -o CheckHostIP=no' +
      ' -o HostKeyAlgorithms=ssh-ed25519 -o ' + (Quote-P0SshArgument ('UserKnownHostsFile=' + $knownHosts)) +
      ' -o ' + (Quote-P0SshArgument ('GlobalKnownHostsFile=' + $config)) +
      ' -o ConnectTimeout=15 -o ConnectionAttempts=1 -o ServerAliveInterval=10 -o ServerAliveCountMax=2'
    $common = @('-c', 'core.autocrlf=false', '-c', 'credential.helper=', '-C', $directory)
    foreach ($operation in @(@('init', '--quiet'), @('remote', 'add', 'origin', 'git@github.com:qiuxinliang/EDRAI.git'))) {
      $result = Invoke-P0NativeGit $git ($common + $operation) $sshCommand -TimeoutSeconds 10
      if ($result.ExitCode -ne 0 -or $result.TimedOut) { throw "Private P0 checkout initialization failed: $($result.Detail)" }
    }
    for ($attempt = 1; $attempt -le 3; $attempt++) {
      $result = Invoke-P0NativeGit $git ($common + @('fetch', '--quiet', '--depth=1', '--no-tags', '--no-recurse-submodules', 'origin', $Ref)) $sshCommand
      if ($result.ExitCode -eq 0 -and -not $result.TimedOut) { break }
      if ($attempt -eq 3) { throw "Private P0 fetch failed after 3 attempts: $($result.Detail)" }
      Write-Host "Private P0 fetch attempt $attempt/3 failed; retrying with the same fixed commit and host pin"
      Start-Sleep -Seconds (2 * $attempt)
    }
    $result = Invoke-P0NativeGit $git ($common + @('checkout', '--quiet', '--detach', 'FETCH_HEAD')) $sshCommand -TimeoutSeconds 15
    if ($result.ExitCode -ne 0 -or $result.TimedOut) { throw "Private P0 checkout failed: $($result.Detail)" }
    $succeeded = $true
    Write-Host 'Private P0 test snapshot checked out; canonical identity verification follows'
  } finally {
    if (Test-Path -LiteralPath $temporary) {
      Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction Stop
      if (Test-Path -LiteralPath $temporary) { throw 'Private P0 credential cleanup did not complete' }
    }
    if (-not $succeeded -and $createdCheckout -and (Test-Path -LiteralPath $directory)) {
      Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction Stop
    }
  }
}

Invoke-P0PrivateCheckout -Directory $Directory -Ref $Ref
