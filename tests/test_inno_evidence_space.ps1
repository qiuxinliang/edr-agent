#Requires -Version 5.1
param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [Parameter(Mandatory=$true)][string]$PreflightExe,
    [string]$Inno = ''
)
$ErrorActionPreference = 'Stop'
if (-not $Inno) {
    $candidate = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
    if (Test-Path -LiteralPath $candidate) { $Inno = $candidate }
    else { $Inno = (Get-Command ISCC.exe -ErrorAction Stop).Source }
}
if (-not (Test-Path -LiteralPath $Inno)) { throw "Inno compiler unavailable: $Inno" }
function Write-SpaceFixtureLogTail([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    Write-Host "[inno-space] bounded log tail: $Path"
    try {
        Get-Content -LiteralPath $Path -Tail 40 | ForEach-Object {
            if ($_.Length -gt 1000) { Write-Host ($_.Substring(0,1000) + ' [truncated]') }
            else { Write-Host $_ }
        }
    } catch { Write-Host "[inno-space] cannot read diagnostic log: $($_.Exception.Message)" }
}
function Invoke-SpaceFixtureProcess([string]$Path, [string[]]$Arguments, [int]$TimeoutMs,
                                   [string]$Stage, [string]$LogPath) {
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    Write-Host "[inno-space] stage=$Stage start timeout_ms=$TimeoutMs executable=$([IO.Path]::GetFileName($Path))"
    $process = $null
    try {
        $process = Start-Process -FilePath $Path -ArgumentList $Arguments -PassThru
        $null = $process.Handle
        Write-Host "[inno-space] stage=$Stage started pid=$($process.Id) launch_ms=$($elapsed.ElapsedMilliseconds)"
        if (-not $process.WaitForExit($TimeoutMs)) {
            throw "space fixture process timed out: stage=$Stage pid=$($process.Id) elapsed_ms=$($elapsed.ElapsedMilliseconds) executable=$Path"
        }
        $process.Refresh()
        Write-Host "[inno-space] stage=$Stage exit=$($process.ExitCode) elapsed_ms=$($elapsed.ElapsedMilliseconds)"
        return $process.ExitCode
    } catch {
        Write-Host "[inno-space] stage=$Stage failed elapsed_ms=$($elapsed.ElapsedMilliseconds): $($_.Exception.Message)"
        if ($process -and -not $process.HasExited) {
            # Only the still-owned fixture PID and its descendants; never match
            # FDSensor or installer names belonging to an installed client.
            Write-Host "[inno-space] stage=$Stage terminating owned pid=$($process.Id) window=$($process.MainWindowTitle)"
            $killLog = $LogPath + '.cleanup.log'
            $killError = $LogPath + '.cleanup-error.log'
            $killer = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\taskkill.exe') `
                -ArgumentList @('/PID',[string]$process.Id,'/T','/F') -PassThru `
                -RedirectStandardOutput $killLog -RedirectStandardError $killError
            try {
                $null = $killer.Handle
                if (-not $killer.WaitForExit(5000)) {
                    $killer.Kill()
                    Write-Host '[inno-space] owned process-tree cleanup exceeded 5000ms'
                } else {
                    $killer.Refresh()
                    Write-Host "[inno-space] stage=$Stage cleanup_exit=$($killer.ExitCode)"
                }
            } finally { $killer.Dispose() }
            Write-SpaceFixtureLogTail $killLog
            Write-SpaceFixtureLogTail $killError
            if (-not $process.WaitForExit(2000)) {
                Write-Host "[inno-space] stage=$Stage ERROR owned root pid=$($process.Id) remains alive"
            }
        }
        Write-SpaceFixtureLogTail $LogPath
        throw
    } finally {
        $elapsed.Stop()
        if ($process) { $process.Dispose() }
    }
}
$root = Join-Path $env:TEMP ('edr-inno-space-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
$previousStateDb = $env:EDR_COMMAND_STATE_DB
$env:EDR_COMMAND_STATE_DB = Join-Path $root 'synthetic-owner\command_state.jsonl'
$retained = $false
try {
    $sources = Join-Path $root 'sources'
    $null = New-Item -ItemType Directory -Path (Join-Path $sources 'tree\nested') -Force
    Copy-Item -LiteralPath $PreflightExe -Destination (Join-Path $sources 'FDSensor.exe')
    # Actual built FDSensor plus its app-local dependencies, not a fake CLI.
    Get-ChildItem -LiteralPath (Split-Path -Parent $PreflightExe) -Filter '*.dll' -File | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $sources
    }
    $runtimeDllBytes = [Int64]0
    Get-ChildItem -LiteralPath $sources -Filter '*.dll' -File | ForEach-Object { $runtimeDllBytes += $_.Length }
    $expectedExpanded = 110592 + (Get-Item -LiteralPath $PreflightExe).Length + $runtimeDllBytes
    [IO.File]::WriteAllBytes((Join-Path $sources 'one.bin'), (New-Object byte[] 4096))
    [IO.File]::WriteAllBytes((Join-Path $sources 'keep.dll'), (New-Object byte[] 8192))
    [IO.File]::WriteAllBytes((Join-Path $sources 'exclude.dll'), (New-Object byte[] 16384))
    [IO.File]::WriteAllBytes((Join-Path $sources 'tree\rule.yar'), (New-Object byte[] 32768))
    [IO.File]::WriteAllBytes((Join-Path $sources 'tree\nested\rule.yar'), (New-Object byte[] 65536))
    $measure = Join-Path $RepoRoot 'install\windows-inno\EvidenceSpaceMeasure.iss'
    $guard = Join-Path $RepoRoot 'install\windows-inno\EvidenceSpaceGuard.iss'
    # Compile the exact production includes. The fixture has no EDR service,
    # enrollment, registry or uninstall operations and installs only to $root.
    $script = @'
#include "@MEASURE@"
[Setup]
AppName=EDR space contract fixture
AppVersion=1
DefaultDirName={tmp}\edr-space-fixture
PrivilegesRequired=lowest
Uninstallable=no
CreateAppDir=yes
DisableWelcomePage=yes
DisableDirPage=yes
DisableProgramGroupPage=yes
OutputDir=@ROOT@
OutputBaseFilename=space-fixture
Compression=none
[Files]
Source: "{#EdrSizedSource('@SOURCES@\FDSensor.exe')}"; DestDir: "{app}"
Source: "{#EdrSizedSource('sources\one.bin')}"; DestDir: "{app}"
#define EdrBeforeDllBytes EdrExpandedBytes
Source: "{#EdrSizedSource('@SOURCES@\*.dll', False, 'exclude.dll')}"; DestDir: "{app}"; Excludes: "exclude.dll"
#expr EdrPreflightDllBytes = EdrExpandedBytes - EdrBeforeDllBytes
Source: "{#EdrSizedSource('@SOURCES@\tree\*', True)}"; DestDir: "{app}\tree"; Flags: recursesubdirs
Source: "{#EdrSizedSource('@SOURCES@\absent.exe')}"; DestDir: "{app}"; Flags: skipifsourcedoesntexist
#if EdrExpandedBytes != @EXPECTED@
  #error "Measured size differs from actual single/wildcard/recursive/optional fixture files"
#endif
[Code]
#include "@GUARD@"
procedure Require(const Value: Boolean; const Message: string);
begin
  if not Value then RaiseException(Message);
end;
function InitializeSetup(): Boolean;
var
  Bytes, FreeBytes, TotalBytes: Int64;
  TempDir: string;
begin
  Log('EDR space fixture: InitializeSetup entered');
  Require(EdrParseSpaceFloor('0', Bytes) and (Bytes = 0), 'zero rejected');
  Require(EdrParseSpaceFloor('3298560049152', Bytes) and (Bytes = 3298560049152), 'large owner floor rejected');
  Require(EdrParseSpaceFloor('9007199254740991', Bytes) and (Bytes = 9007199254740991), 'maximum floor rejected');
  Require(not EdrParseSpaceFloor('9007199254740992', Bytes), 'overflow accepted');
  Require(not EdrParseSpaceFloor('-1', Bytes), 'negative accepted');
  Require(not EdrParseSpaceFloor('1e3', Bytes), 'exponent accepted');
  Require(not EdrParseSpaceFloor(' 1', Bytes), 'whitespace accepted');
  Require(not EdrParseSpaceFloor('', Bytes), 'empty accepted');
  Bytes := 9007199254740991;
  Require(not EdrAddSpaceBytes(Bytes, 1) and (Bytes = 9007199254740991), 'growth overflow mutated total');
  Bytes := 10;
  Require(not EdrAddSpaceBytes(Bytes, -1) and (Bytes = 10), 'negative growth accepted');
  Require(EdrAddSpaceBytes(Bytes, 20) and (Bytes = 30), 'valid growth rejected');
  TempDir := ExpandConstant('{tmp}');
  Require(GetSpaceOnDisk64(TempDir, FreeBytes, TotalBytes), 'native disk probe failed');
  Require(EdrCheckSpaceDirectory('unit', TempDir, 0, 1) = '', 'normal volume rejected');
  Require(EdrCheckSpaceDirectory('unit', TempDir, FreeBytes + 1073741824, 1) <> '', 'low volume accepted');
  Require(EdrCheckSpaceDirectory('unit', TempDir, FreeBytes, 1073741824) <> '', 'growth beyond remaining space accepted');
  Require(EdrCheckSpaceDirectory('unit', '', 0, 0) <> '', 'unmeasurable directory accepted');
  Require(EdrExistingSpaceDirectory(TempDir + '\missing-parent\child') = TempDir, 'existing parent probe wrong');
  Log('EDR space fixture: production parser and native directory checks passed');
  Result := True;
end;
function PrepareToInstall(var NeedsRestart: Boolean): string;
begin
  Log('EDR space fixture: PrepareToInstall entered');
  Result := EdrCheckInstallSpace(ExpandConstant('{app}'), ExpandConstant('{param:REQUIRED|0}') = '1');
  Log('EDR space fixture: PrepareToInstall returned: ' + Result);
  if Result <> '' then Exit;
  Require(SaveStringToFile(ExpandConstant('{param:MARKER}'), 'passed-before-copy', False), 'marker failed');
end;
'@
    $script = $script.Replace('@MEASURE@',$measure).Replace('@GUARD@',$guard).Replace('@ROOT@',$root).Replace('@SOURCES@',$sources.Replace("'","''")).Replace('@EXPECTED@',[string]$expectedExpanded)
    $scriptPath = Join-Path $root 'space-fixture.iss'
    [IO.File]::WriteAllText($scriptPath,$script,[Text.Encoding]::UTF8)
    $compileExit = Invoke-SpaceFixtureProcess $Inno @('/Qp', ('"' + $scriptPath + '"')) 45000 'compile' (Join-Path $root 'compile.log')
    if ($compileExit -ne 0) { throw "Inno fixture compilation failed: $compileExit" }
    $exe = Join-Path $root 'space-fixture.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw 'Inno did not emit fixture executable' }
    $cases = @(
        @{Name='first-install-default'; Arguments=@(); Pass=$true},
        @{Name='upgrade-zero'; Arguments=@('/REQUIRED=1','/EDR_MIN_FREE_BYTES=0'); Pass=$true},
        @{Name='upgrade-lifecycle'; Arguments=@('/REQUIRED=1','/EDR_MIN_FREE_BYTES=0'); Pass=$true; Lifecycle=$true},
        # Exact 673 full-installer contract: no new floor argument is sent.
        @{Name='legacy-673-upgrade'; Arguments=@('/REQUIRED=1','/EDR_UPGRADE_EXISTING=1'); Pass=$true},
        @{Name='legacy-673-repair'; Arguments=@('/REQUIRED=1','/EDR_REPAIR_BASELINE=1'); Pass=$true},
        @{Name='upgrade-prefix-not-key'; Arguments=@('/REQUIRED=1','/EDR_MIN_FREE_BYTES_SUFFIX=0'); Pass=$true},
        @{Name='local-floor-cannot-be-lowered'; Arguments=@('/REQUIRED=1','/EDR_MIN_FREE_BYTES=0'); Pass=$false; LargeFloor=$true},
        @{Name='empty'; Arguments=@('/EDR_MIN_FREE_BYTES='); Pass=$false},
        @{Name='malformed'; Arguments=@('/EDR_MIN_FREE_BYTES=1e3'); Pass=$false},
        @{Name='duplicate'; Arguments=@('/EDR_MIN_FREE_BYTES=0','/EDR_MIN_FREE_BYTES=1'); Pass=$false},
        @{Name='maximum-low-space'; Arguments=@('/EDR_MIN_FREE_BYTES=9007199254740991'); Pass=$false},
        @{Name='overflow'; Arguments=@('/EDR_MIN_FREE_BYTES=9007199254740992'); Pass=$false}
    )
    $baseGrowth = $null
    foreach ($case in $cases) {
        $dest = Join-Path $root $case.Name
        $marker = Join-Path $root ($case.Name + '.marker')
        $log = Join-Path $root ($case.Name + '.log')
        if ($case.Arguments -contains '/REQUIRED=1') {
            $null = New-Item -ItemType Directory -Path $dest -Force
            $ownerMb = if ($case.LargeFloor) { 1048576 } else { 1 }
            [IO.File]::WriteAllText((Join-Path $dest 'agent.toml'), "[offline]`ncommand_state_owner_budget_mb=$ownerMb`nstorage_min_free_mb=0`n")
        }
        if ($case.Lifecycle) {
            $null = New-Item -ItemType Directory -Path $dest -Force
            [IO.File]::WriteAllBytes((Join-Path $dest 'unins000.exe'), (New-Object byte[] 256))
            [IO.File]::WriteAllBytes((Join-Path $dest 'unins000.dat'), (New-Object byte[] 512))
            [IO.File]::WriteAllBytes((Join-Path $dest 'unins000.msg'), (New-Object byte[] 128))
        }
        $arguments = @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',('/DIR="' + $dest + '"'),('/LOG="' + $log + '"'),('/MARKER="' + $marker + '"')) + $case.Arguments
        $fixtureExit = Invoke-SpaceFixtureProcess $exe $arguments 30000 $case.Name $log
        $passed = $fixtureExit -eq 0
        if ($passed -ne $case.Pass) {
            Write-SpaceFixtureLogTail $log
            throw "unexpected fixture exit for $($case.Name): $fixtureExit; see $log"
        }
        if ((Test-Path -LiteralPath $marker) -ne $case.Pass) { throw "guard executed writes on rejection: $($case.Name)" }
        if ((Test-Path -LiteralPath (Join-Path $dest 'one.bin')) -ne $case.Pass) { throw "guard did not precede file copy: $($case.Name)" }
        $logText = [IO.File]::ReadAllText($log)
        if (-not $logText.Contains('production parser and native directory checks passed')) { throw 'fixture unit checks did not execute' }
        if ($case.Pass -and -not $logText.Contains("expanded_files=$expectedExpanded")) { throw 'measured source size missing from actual gate log' }
        if ($case.Pass) {
            $growthMatch = [regex]::Match($logText,"expanded_files=$expectedExpanded; installation_growth=(\d+); floor=(\d+)")
            if (-not $growthMatch.Success) { throw 'actual installation growth log missing' }
            if ([Int64]$growthMatch.Groups[2].Value -lt 27MB) { throw 'local floor was bypassed' }
            [Int64]$growth = $growthMatch.Groups[1].Value
            if ($null -eq $baseGrowth) { $baseGrowth = $growth }
            if ($case.Lifecycle -and $growth -ne ($baseGrowth + 896)) { throw 'old Inno lifecycle growth not included' }
        }
    }
    [ordered]@{test='inno_evidence_space';compiler=$Inno;cases=$cases.Count;compiled_production_includes=$true;real_inno_execution=$true;real_edr_installer_executed=$false;actual_disk_exhaustion=$false} | ConvertTo-Json -Compress
} catch {
    $retained = $true
    Write-Error "Inno space fixture failed; synthetic files and logs retained at $root. $_"
    throw
} finally {
    $env:EDR_COMMAND_STATE_DB = $previousStateDb
    if (-not $retained) { Remove-Item -LiteralPath $root -Recurse -Force }
}
