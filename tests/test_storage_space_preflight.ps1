#Requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$PreflightExe)
$ErrorActionPreference = 'Stop'
$PreflightExe = (Resolve-Path -LiteralPath $PreflightExe).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ('edr-preflight-native-' + [guid]::NewGuid().ToString('N'))
$stateDir = Join-Path $root 'state'
$state = Join-Path $stateDir 'command_state.jsonl'
$config = Join-Path $root 'agent.toml'
$junction = Join-Path $root 'linked-state'
$utf8 = New-Object Text.UTF8Encoding($false)
$savedEnv = @{}
foreach ($key in @('EDR_COMMAND_STATE_DB','EDR_STORAGE_MIN_FREE_MB','EDR_STORAGE_OWNER_PROTECTED_BYTES')) {
    $savedEnv[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
}
$null = New-Item -ItemType Directory -Path $root
$env:EDR_COMMAND_STATE_DB = $state
$env:EDR_STORAGE_MIN_FREE_MB = '999999'
$env:EDR_STORAGE_OWNER_PROTECTED_BYTES = 'unavailable'
$cases = @{Count = 0}
function Assert-Preflight([bool]$Condition, [string]$Cause) {
    if (-not $Condition) { throw $Cause }
}
function Set-PrivateFixtureAcl([string]$Path, [bool]$Unsafe = $false) {
    $acl = Get-Acl -LiteralPath $Path
    $sddl = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)'
    if ($Unsafe) { $sddl += '(A;;FA;;;WD)' }
    $acl.SetSecurityDescriptorSddlForm($sddl, [Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Get-OwnerSnapshot {
    $file = Get-Item -LiteralPath $state
    return ('{0}|{1}|{2}|{3}|{4}' -f
        (Get-FileHash -LiteralPath $state -Algorithm SHA256).Hash,
        $file.CreationTimeUtc.Ticks, $file.LastWriteTimeUtc.Ticks,
        (Get-Acl -LiteralPath $state).Sddl, (Get-Acl -LiteralPath $stateDir).Sddl)
}
function Invoke-Preflight([string]$Name, [string[]]$Cli, [int]$Expected = 0) {
    $output = Join-Path $root ($Name + '.floor')
    $all = @('--storage-space-preflight') + $Cli + @('--output', $output)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $PreflightExe
    # Synthetic paths contain no double quotes or trailing separators.
    $psi.Arguments = (($all | ForEach-Object { '"' + $_ + '"' }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $psi
    try {
        Assert-Preflight ($process.Start()) ($Name + ': process did not start')
        if (-not $process.WaitForExit(10000)) {
            $process.Kill()
            throw ($Name + ': preflight exceeded 10 seconds')
        }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        Assert-Preflight ($process.ExitCode -eq $Expected) ($Name + ': unexpected exit ' + $process.ExitCode + ': ' + $stderr)
        Assert-Preflight (-not $stdout) ($Name + ': unexpected stdout')
        if ($Expected -eq 7) {
            Assert-Preflight ($stderr.Trim() -eq 'storage preflight: owner_lock_timeout') ($Name + ': timeout cause missing')
        }
        $cases.Count++
        if ($Expected -ne 0) {
            Assert-Preflight (-not (Test-Path -LiteralPath $output)) ($Name + ': failure emitted a usable floor')
            return
        }
        $raw = [IO.File]::ReadAllText($output)
        Assert-Preflight ($raw -cmatch '^(0|[1-9][0-9]*)$') ($Name + ': output is not strict decimal')
        return [UInt64]::Parse($raw, [Globalization.CultureInfo]::InvariantCulture)
    } finally { $process.Dispose() }
}
try {
    [IO.File]::WriteAllText($config, "[offline]`ncommand_state_owner_budget_mb=1`nstorage_min_free_mb=0`n", $utf8)
    Assert-Preflight ((Invoke-Preflight 'defaults' @('--defaults')) -gt 24MB) 'default policy floor missing'
    Assert-Preflight (-not (Test-Path -LiteralPath $stateDir)) 'defaults created state directory'
    Invoke-Preflight 'missing-config' @('--config', (Join-Path $root 'missing.toml')) 3
    Assert-Preflight ((Invoke-Preflight 'no-parent' @('--config', $config)) -eq 27MB) 'no-parent floor mismatch'
    Assert-Preflight (-not (Test-Path -LiteralPath $stateDir)) 'inventory created missing state parent'
    $null = New-Item -ItemType Directory -Path $stateDir
    Set-PrivateFixtureAcl $stateDir
    $parentAcl = (Get-Acl -LiteralPath $stateDir).Sddl
    Assert-Preflight ((Invoke-Preflight 'empty-owner' @('--config', $config)) -eq 27MB) 'empty owner floor mismatch'
    Assert-Preflight (-not (Test-Path -LiteralPath $state)) 'inventory created owner database'
    Assert-Preflight ((Get-Acl -LiteralPath $stateDir).Sddl -eq $parentAcl) 'inventory changed parent ACL'
    $line = ([ordered]@{record='command_state';command_id='legacy-owner';final=0;detail=('x' * 65536)} | ConvertTo-Json -Compress) + "`n"
    [IO.File]::WriteAllText($state, ($line * 20), $utf8)
    Set-PrivateFixtureAcl $state
    $validBytes = [IO.File]::ReadAllBytes($state)
    $before = Get-OwnerSnapshot
    Assert-Preflight ((Invoke-Preflight 'legacy-owner' @('--config', $config)) -gt 27MB) 'legacy protected owner was not accounted'
    Assert-Preflight ((Get-OwnerSnapshot) -eq $before) 'inventory changed owner bytes, timestamps, or ACL'
    [IO.File]::WriteAllText($config, "[offline]`ncommand_state_owner_budget_mb=1`nstorage_min_free_mb=64`n", $utf8)
    Assert-Preflight ((Invoke-Preflight 'configured-floor' @('--config', $config)) -eq 64MB) 'configured floor did not override inherited environment'
    Assert-Preflight ((Get-OwnerSnapshot) -eq $before) 'configured inventory changed owner'
    [IO.File]::AppendAllText($state, '{torn', $utf8)
    $beforeCorrupt = Get-OwnerSnapshot
    Invoke-Preflight 'corrupt-owner' @('--config', $config) 4
    Assert-Preflight ((Get-OwnerSnapshot) -eq $beforeCorrupt) 'inventory repaired corrupt owner'
    [IO.File]::WriteAllBytes($state, $validBytes)
    Set-PrivateFixtureAcl $state $true
    $beforeUnsafe = Get-OwnerSnapshot
    Invoke-Preflight 'unsafe-owner-acl' @('--config', $config) 4
    Assert-Preflight ((Get-OwnerSnapshot) -eq $beforeUnsafe) 'inventory repaired unsafe owner ACL'
    Set-PrivateFixtureAcl $state
    Set-PrivateFixtureAcl $stateDir $true
    $beforeUnsafeParent = Get-OwnerSnapshot
    Invoke-Preflight 'unsafe-parent-acl' @('--config', $config) 4
    Assert-Preflight ((Get-OwnerSnapshot) -eq $beforeUnsafeParent) 'inventory repaired unsafe parent ACL'
    Set-PrivateFixtureAcl $stateDir
    $beforeLink = Get-OwnerSnapshot
    & cmd.exe /d /c "mklink /J `"$junction`" `"$stateDir`"" | Out-Null
    Assert-Preflight ($LASTEXITCODE -eq 0) 'cannot create synthetic junction fixture'
    $env:EDR_COMMAND_STATE_DB = Join-Path $junction 'command_state.jsonl'
    Invoke-Preflight 'reparse-parent' @('--config', $config) 4
    Assert-Preflight ((Get-OwnerSnapshot) -eq $beforeLink) 'reparse rejection changed target owner'
    Assert-Preflight (((Get-Item -LiteralPath $junction).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) 'inventory replaced junction'
    $env:EDR_COMMAND_STATE_DB = $state
    $lock = [IO.File]::Open(($state + '.lock'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    try {
        $lock.Lock(0, 1)
        Invoke-Preflight 'owner-lock-busy' @('--config', $config) 7
        $lock.Unlock(0, 1)
    } finally { $lock.Dispose() }
    $releasedOwner = Get-OwnerSnapshot
    Assert-Preflight ((Invoke-Preflight 'owner-lock-released' @('--config', $config)) -eq 64MB) 'released owner inventory did not recover'
    Assert-Preflight ((Get-OwnerSnapshot) -eq $releasedOwner) 'released inventory changed owner bytes, timestamps, or ACL'
    [IO.File]::WriteAllText($config, "[offline`n", $utf8)
    Invoke-Preflight 'corrupt-config' @('--config', $config) 3
    Invoke-Preflight 'ambiguous-config' @('--config', $config, '--defaults') 2
    Assert-Preflight ($cases.Count -eq 14) 'not all native preflight cases completed'
    [ordered]@{test='native_storage_space_preflight';cases=$cases.Count;owner_hash_timestamps_acl_unchanged=$true;unsafe_acl_and_reparse_rejected=$true;missing_parent_not_created=$true;lock_busy_rejected=$true;agent_started=$false} | ConvertTo-Json -Compress
} finally {
    foreach ($key in $savedEnv.Keys) { [Environment]::SetEnvironmentVariable($key, $savedEnv[$key], 'Process') }
    if (Test-Path -LiteralPath $junction) { & cmd.exe /d /c "rmdir `"$junction`"" | Out-Null }
    Remove-Item -LiteralPath $root -Recurse -Force
}
