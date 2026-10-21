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
$previousEvidenceDb = $env:EDR_EVIDENCE_CACHE_PATH
$env:EDR_EVIDENCE_CACHE_PATH = Join-Path $root 'missing-evidence.db'
$previousFixtureMode = $env:EDR_INNO_PREFLIGHT_FIXTURE_MODE
$previousFixturePid = $env:EDR_INNO_PREFLIGHT_FIXTURE_PID
$env:EDR_COMMAND_STATE_DB = Join-Path $root 'synthetic-owner\command_state.jsonl'
$retained = $false
try {
    $sources = Join-Path $root 'sources'
    $null = New-Item -ItemType Directory -Path (Join-Path $sources 'tree\nested') -Force
    Copy-Item -LiteralPath $PreflightExe -Destination (Join-Path $sources 'FDSensor.exe')
    $expectedPreflightHash = (Get-FileHash -LiteralPath $PreflightExe -Algorithm SHA256).Hash.ToLowerInvariant()
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
; Production packages use x64os or arm64 for both directives. This shared
; fixture runs on either native runner, preserving its 64-bit system paths.
ArchitecturesAllowed=x64os arm64
ArchitecturesInstallIn64BitMode=x64os arm64
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
  Require(Is64BitInstallMode, 'production native install mode missing');
  Log('EDR space fixture: native PowerShell=' +
    ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'));
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
  if ExpandConstant('{param:LAUNCH_FAILURE|0}') = '1' then
  begin
    Require(not FileExists(ExpandConstant('{tmp}\missing-space-launcher.exe')), 'launch failure fixture already exists');
    Result := EdrExecSpacePreflight(ExpandConstant('{tmp}\missing-space-launcher.exe'), '', ExpandConstant('{tmp}'));
  end
  else Result := EdrCheckInstallSpace(ExpandConstant('{app}'), ExpandConstant('{param:REQUIRED|0}') = '1');
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
            if (-not $logText.Contains('EDR storage preflight: stage=child_exit; exit_code=0; reason=success')) { throw 'successful preflight exit was not logged' }
            if (-not $logText.Contains("EDR storage preflight image: sha256=$expectedPreflightHash")) { throw 'extracted preflight image hash was not attested' }
            $growthMatch = [regex]::Match($logText,"expanded_files=$expectedExpanded; installation_growth=(\d+); floor=(\d+)")
            if (-not $growthMatch.Success) { throw 'actual installation growth log missing' }
            if ([Int64]$growthMatch.Groups[2].Value -lt 27MB) { throw 'local floor was bypassed' }
            [Int64]$growth = $growthMatch.Groups[1].Value
            if ($null -eq $baseGrowth) { $baseGrowth = $growth }
            if ($case.Lifecycle -and $growth -ne ($baseGrowth + 896)) { throw 'old Inno lifecycle growth not included' }
        }
    }
    # Controlled failing child for the actual production Command and watchdog.
    # Existing cases above still use the supplied real Agent and its closure.
    $failureChild = Join-Path $root 'failure-child.exe'
    $failureSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
public static class SpacePreflightFailureFixture {
    public static int Main() {
        string mode = Environment.GetEnvironmentVariable("EDR_INNO_PREFLIGHT_FIXTURE_MODE");
        if (mode == "watchdog") {
            using (Process self = Process.GetCurrentProcess()) {
                File.WriteAllText(Environment.GetEnvironmentVariable("EDR_INNO_PREFLIGHT_FIXTURE_PID"),
                    self.Id.ToString() + " " + self.StartTime.ToUniversalTime().Ticks.ToString());
            }
            Thread.Sleep(30000);
            return 99;
        }
        int code;
        return Int32.TryParse(mode, out code) ? code : 99;
    }
}
'@
    Add-Type -TypeDefinition $failureSource -OutputAssembly $failureChild -OutputType ConsoleApplication
    $expectedFailureHash = (Get-FileHash -LiteralPath $failureChild -Algorithm SHA256).Hash.ToLowerInvariant()
    Copy-Item -LiteralPath $failureChild -Destination (Join-Path $sources 'FDSensor.exe') -Force
    $failureExpanded = 110592 + (Get-Item -LiteralPath $failureChild).Length + $runtimeDllBytes
    $failureScript = $script.Replace('OutputBaseFilename=space-fixture','OutputBaseFilename=space-failure-fixture').Replace("#if EdrExpandedBytes != $expectedExpanded","#if EdrExpandedBytes != $failureExpanded")
    $failureScriptPath = Join-Path $root 'space-failure-fixture.iss'
    [IO.File]::WriteAllText($failureScriptPath,$failureScript,[Text.Encoding]::UTF8)
    $compileExit = Invoke-SpaceFixtureProcess $Inno @('/Qp', ('"' + $failureScriptPath + '"')) 45000 'compile-failures' (Join-Path $root 'compile-failures.log')
    if ($compileExit -ne 0) { throw "Inno failure fixture compilation failed: $compileExit" }
    $failureExe = Join-Path $root 'space-failure-fixture.exe'
    $failureCases = @(
        @{Name='invalid-arguments'; Mode='2'; Code=2; Reason='invalid_arguments'},
        @{Name='configuration-unavailable'; Mode='3'; Code=3; Reason='configuration_unavailable'},
        @{Name='owner-unavailable'; Mode='4'; Code=4; Reason='owner_accounting_or_policy_unavailable'},
        @{Name='floor-output-failed'; Mode='5'; Code=5; Reason='floor_output_failed'},
        @{Name='owner-lock-timeout'; Mode='7'; Code=7; Reason='owner_lock_timeout'},
        @{Name='deadline-unavailable'; Mode='8'; Code=8; Reason='deadline_unavailable'},
        @{Name='owner-lock-granted-expired'; Mode='9'; Code=9; Reason='owner_lock_granted_expired'},
        @{Name='owner-lock-deadline-before-request'; Mode='10'; Code=10; Reason='owner_lock_deadline_before_request'},
        @{Name='evidence-schema-full'; Mode='11'; Code=11; Reason='evidence_schema_no_page_headroom'},
        @{Name='evidence-schema-unavailable'; Mode='12'; Code=12; Reason='evidence_schema_inspection_unavailable'},
        @{Name='child-watchdog'; Mode='watchdog'; Code=124; Reason='child_watchdog_timeout'},
        @{Name='launcher-unavailable'; Mode='7'; LaunchFailure=$true}
    )
    foreach ($case in $failureCases) {
        $dest = Join-Path $root $case.Name
        $marker = Join-Path $root ($case.Name + '.marker')
        $log = Join-Path $root ($case.Name + '.log')
        $pidFile = Join-Path $root ($case.Name + '.child')
        $env:EDR_INNO_PREFLIGHT_FIXTURE_MODE = $case.Mode
        $env:EDR_INNO_PREFLIGHT_FIXTURE_PID = $pidFile
        $arguments = @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',('/DIR="' + $dest + '"'),('/LOG="' + $log + '"'),('/MARKER="' + $marker + '"'))
        if ($case.LaunchFailure) { $arguments += '/LAUNCH_FAILURE=1' }
        $fixtureExit = Invoke-SpaceFixtureProcess $failureExe $arguments 30000 $case.Name $log
        if ($fixtureExit -ne 7) { throw "failure did not reject PrepareToInstall: $($case.Name) exit=$fixtureExit" }
        if ((Test-Path -LiteralPath $marker) -or (Test-Path -LiteralPath (Join-Path $dest 'one.bin'))) { throw "failure reached protected actions or file copy: $($case.Name)" }
        $logText = [IO.File]::ReadAllText($log)
        $diagnostics = @($logText -split '\r?\n' | Where-Object { $_.Contains('EDR storage preflight: ') })
        $imageDiagnostics = @($logText -split '\r?\n' | Where-Object { $_.Contains('EDR storage preflight image: ') })
        if ($diagnostics.Count -ne 1) { throw "preflight diagnostic was missing or unbounded: $($case.Name)" }
        if ($case.LaunchFailure) {
            if ($imageDiagnostics.Count -ne 0) { throw 'launcher-only fixture incorrectly attested an image' }
            if ($diagnostics[0] -notmatch 'EDR storage preflight: stage=launch_failed; win32_code=[23]$') { throw 'native Exec failure was not distinguished from child exit' }
        } else {
            if ($imageDiagnostics.Count -ne 1 -or -not $imageDiagnostics[0].EndsWith("EDR storage preflight image: sha256=$expectedFailureHash")) { throw "wrong extracted preflight image identity: $($case.Name)" }
            if (-not $diagnostics[0].EndsWith("EDR storage preflight: stage=child_exit; exit_code=$($case.Code); reason=$($case.Reason)")) { throw "wrong child failure classification: $($case.Name)" }
        }
        if ($case.Mode -eq 'watchdog') {
            if (-not (Test-Path -LiteralPath $pidFile)) { throw 'watchdog fixture child never started' }
            $identity = [IO.File]::ReadAllText($pidFile)
            if ($identity -notmatch '^([0-9]+) ([0-9]+)$') { throw 'invalid owned child identity' }
            $childPid = [int]$Matches[1]; $childBirth = [Int64]$Matches[2]
            $child = Get-Process -Id $childPid -ErrorAction SilentlyContinue
            if ($child) {
                try {
                    if ($child.StartTime.ToUniversalTime().Ticks -eq $childBirth -and -not $child.WaitForExit(2000)) {
                        throw 'watchdog left its own child running'
                    }
                }
                finally { $child.Dispose() }
            }
        }
    }
    [ordered]@{test='inno_evidence_space';compiler=$Inno;cases=($cases.Count+$failureCases.Count);real_preflight_cases=$cases.Count;synthetic_failure_cases=$failureCases.Count;compiled_production_includes=$true;real_inno_execution=$true;actual_15000ms_child_watchdog=$true;real_edr_installer_executed=$false;actual_disk_exhaustion=$false} | ConvertTo-Json -Compress
} catch {
    $retained = $true
    Write-Error "Inno space fixture failed; synthetic files and logs retained at $root. $_"
    throw
} finally {
    $env:EDR_COMMAND_STATE_DB = $previousStateDb
    $env:EDR_EVIDENCE_CACHE_PATH = $previousEvidenceDb
    $env:EDR_INNO_PREFLIGHT_FIXTURE_MODE = $previousFixtureMode
    $env:EDR_INNO_PREFLIGHT_FIXTURE_PID = $previousFixturePid
    if (-not $retained) { Remove-Item -LiteralPath $root -Recurse -Force }
}
