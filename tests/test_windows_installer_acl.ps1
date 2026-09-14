#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string] $InstallerWorker)

$ErrorActionPreference = 'Stop'
$InstallerWorker = (Resolve-Path -LiteralPath $InstallerWorker).Path
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Installer ACL regression requires an elevated Windows test runner'
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('edr-installer-acl-' + [Guid]::NewGuid().ToString('N'))
$sensitive = @('certs', 'queue', 'evidence', 'state', 'logs', 'diagnostics', 'upload_outbox', 'forensic', 'collector', 'isolation')
$marker = [byte[]](77, 90, 1, 2)
$fullControl = [int][Security.AccessControl.FileSystemRights]::FullControl
function Assert-SensitiveFile([string] $Path, [byte[]] $Expected) {
  # Exit=0 from icacls is insufficient: exercise the same read as the PE verifier.
  $actual = [IO.File]::ReadAllBytes($Path)
  if ([Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($Expected)) {
    throw "Protected file contents changed: $Path"
  }
  $acl = Get-Acl -LiteralPath $Path
  $allowed = @{}
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    $sid = $rule.IdentityReference.Value
    if ($sid -notin @('S-1-5-18', 'S-1-5-32-544')) {
      throw "Sensitive file grants unexpected identity $sid access: $Path"
    }
    if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
        (([int]$rule.FileSystemRights -band $fullControl) -eq $fullControl)) {
      $allowed[$sid] = $true
    }
  }
  if (-not $allowed['S-1-5-18'] -or -not $allowed['S-1-5-32-544']) {
    throw "SYSTEM/Administrators file grants missing: $Path; SDDL=$($acl.Sddl)"
  }
}
try {
  foreach ($name in $sensitive) {
    $nested = Join-Path (Join-Path $root $name) 'nested'
    [IO.Directory]::CreateDirectory($nested) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $nested 'existing.bin'), $marker)
  }
  $collector = Join-Path $root 'collector/forensic_collector_builtin.exe'
  $pe = [IO.File]::ReadAllBytes($InstallerWorker)
  [IO.File]::WriteAllBytes($collector, $pe)
  foreach ($round in 1..2) {
    $process = Start-Process -FilePath $InstallerWorker -ArgumentList @(
      '--stage', 'harden-acl', '--install-dir', ('"{0}"' -f $root),
      '--log', ('"{0}"' -f (Join-Path $root 'worker.log'))
    ) -PassThru
    try {
      if (-not $process.WaitForExit(45000)) {
        $process.Kill()
        throw 'Installer ACL stage exceeded 45 seconds'
      }
      if ($process.ExitCode -ne 0) { throw "Installer ACL stage failed: exit=$($process.ExitCode)" }
    } finally { $process.Dispose() }
    Assert-SensitiveFile $collector $pe
    foreach ($name in $sensitive) {
      $nested = Join-Path (Join-Path $root $name) 'nested'
      Assert-SensitiveFile (Join-Path $nested 'existing.bin') $marker
      # Directory inheritance must still protect files created after hardening.
      $future = Join-Path $nested "future-$round.bin"
      [IO.File]::WriteAllBytes($future, $marker)
      Assert-SensitiveFile $future $marker
      if ($round -eq 2) { Assert-SensitiveFile (Join-Path $nested 'future-1.bin') $marker }
    }
  }
  Write-Host 'PASS: native installer ACLs preserve PE reads, restricted file grants, future inheritance and repeated hardening'
} finally {
  if (Test-Path -LiteralPath $root) {
    # Repair only this owned fixture for cleanup, even when testing a broken worker.
    & icacls.exe $root /grant '*S-1-5-18:F' '*S-1-5-32-544:F' /T /C /Q | Out-Null
    Remove-Item -LiteralPath $root -Recurse -Force
  }
}
