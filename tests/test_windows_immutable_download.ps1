# Exercise the actual workflow function without network, release mutations, or Pester.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
$workflow = Join-Path $PSScriptRoot '../.github/workflows/windows-install-upgrade-rollback.yml'
$source = Get-Content -LiteralPath $workflow -Raw
$match = [regex]::Match($source, '(?ms)^          function Download-ImmutableAsset\(.*?(?=^          \$targetRuntime = )')
if (-not $match.Success) { throw 'workflow download function not found' }
$functionSource = $match.Value -replace '(?m)^          ', ''
if ($functionSource -match 'SkipCertificateCheck|AllowInsecureRedirect|PreserveAuthorizationOnRedirect|ServerCertificateValidationCallback') {
  throw 'download must retain TLS and redirect credential protections'
}
. ([scriptblock]::Create($functionSource))

function Assert-DownloadTest([bool]$Condition, [string]$Message) {
  if (-not $Condition) { throw "download regression: $Message" }
}

function Get-ImmutableAsset([string]$Tag, [string]$Expected) {
  Assert-DownloadTest ($Tag -ceq 'win_3.2.426') 'tag changed'
  Assert-DownloadTest ($Expected -ceq $script:asset.name) 'asset name changed'
  return $script:asset
}

function Start-Sleep([int]$Seconds) { $script:delays += $Seconds }

function Invoke-WebRequest {
  [CmdletBinding()]
  param($Uri, $Headers, $OutFile, $ConnectionTimeoutSeconds, $OperationTimeoutSeconds)
  $script:attempts++
  Assert-DownloadTest ($Uri -ceq $script:asset.url) 'must reuse the immutable asset API URL'
  Assert-DownloadTest ($Headers.Authorization -ceq "Bearer $env:GH_TOKEN") 'authentication lost'
  Assert-DownloadTest ($Headers.Accept -ceq 'application/octet-stream') 'binary accept header lost'
  Assert-DownloadTest ($ConnectionTimeoutSeconds -eq 30 -and $OperationTimeoutSeconds -eq 60) 'timeouts missing'
  Assert-DownloadTest (-not (Test-Path -LiteralPath $OutFile)) 'partial file survived to next attempt'
  Assert-DownloadTest ((Get-Content -LiteralPath $script:destinationPath -Raw) -ceq 'previous-verified') 'destination replaced before verification'
  [IO.File]::WriteAllBytes($OutFile, [byte[]](1, 2, 3))
  if ($script:attempts -le $script:case.failures) {
    if ($script:case.status) {
      $httpError = [System.Net.Http.HttpRequestException]::new('HTTP failure')
      $response = [pscustomobject]@{ StatusCode = [int]$script:case.status }
      Add-Member -InputObject $httpError -NotePropertyName Response -NotePropertyValue $response
      throw $httpError
    }
    if ($script:case.kind -eq 'local') { throw [System.UnauthorizedAccessException]::new('local disk denied') }
    $inner = [System.Security.Authentication.AuthenticationException]::new("TLS peer closed; https://asset.example/file?sig=signed-secret token=$env:GH_TOKEN")
    throw [System.Net.Http.HttpRequestException]::new('The SSL connection could not be established, see inner exception.', $inner)
  }
  if ($script:case.kind -eq 'size') { return }
  $bytes = if ($script:case.kind -eq 'digest') { [byte[]](255..0) } else { $script:payload }
  [IO.File]::WriteAllBytes($OutFile, $bytes)
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('edr-immutable-download-' + [guid]::NewGuid().ToString('N'))
$originalToken = $env:GH_TOKEN
try {
  New-Item -ItemType Directory -Path $testRoot | Out-Null
  $env:GH_TOKEN = 'download-test-secret'
  $script:payload = [byte[]](0..255)
  $payloadPath = Join-Path $testRoot 'payload.bin'
  [IO.File]::WriteAllBytes($payloadPath, $script:payload)
  $hash = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash
  $script:asset = [pscustomobject]@{
    name = 'edr-agent-win_3.2.426-windows-amd64-exe.zip'
    url = 'https://api.github.com/repos/test/agent/releases/assets/426'
    size = $script:payload.Length
    digest = "sha256:$hash"
  }
  $cases = @(
    @{ name = 'success'; failures = 0; attempts = 1; kind = ''; error = '' },
    @{ name = 'tls-recovery'; failures = 2; attempts = 3; kind = ''; error = '' },
    @{ name = 'tls-exhausted'; failures = 4; attempts = 4; kind = ''; error = 'after 4 attempt\(s\).*AuthenticationException' },
    @{ name = 'http-503'; failures = 1; attempts = 2; status = 503; error = '' },
    @{ name = 'http-429'; failures = 1; attempts = 2; status = 429; error = '' },
    @{ name = 'http-401'; failures = 4; attempts = 1; status = 401; error = 'HTTP 401' },
    @{ name = 'http-403'; failures = 4; attempts = 1; status = 403; error = 'HTTP 403' },
    @{ name = 'http-404'; failures = 4; attempts = 1; status = 404; error = 'HTTP 404' },
    @{ name = 'local-error'; failures = 4; attempts = 1; kind = 'local'; error = 'local disk denied' },
    @{ name = 'size-mismatch'; failures = 0; attempts = 1; kind = 'size'; error = 'size mismatch' },
    @{ name = 'digest-mismatch'; failures = 0; attempts = 1; kind = 'digest'; error = 'SHA-256 mismatch' },
    @{ name = 'legacy-without-digest'; failures = 0; attempts = 1; kind = 'legacy'; error = '' }
  )
  foreach ($script:case in $cases) {
    $caseDir = Join-Path $testRoot $script:case.name
    New-Item -ItemType Directory -Path $caseDir | Out-Null
    $script:destinationPath = Join-Path $caseDir $script:asset.name
    [IO.File]::WriteAllText($script:destinationPath, 'previous-verified')
    $script:asset.digest = if ($script:case.kind -eq 'legacy') { '' } else { "sha256:$hash" }
    $script:attempts = 0
    $script:delays = @()
    $warnings = @()
    $failure = ''
    try {
      Download-ImmutableAsset 'win_3.2.426' $script:asset.name $caseDir 3>&1 |
        ForEach-Object { $warnings += "$_" }
    } catch { $failure = $_.Exception.Message }
    $name = $script:case.name
    Assert-DownloadTest ($script:attempts -eq $script:case.attempts) "$name attempt count: $script:attempts ($failure)"
    Assert-DownloadTest ($script:delays.Count -eq $script:attempts - 1) "$name retry count"
    for ($i = 0; $i -lt $script:delays.Count; $i++) {
      Assert-DownloadTest ($script:delays[$i] -eq [Math]::Pow(2, $i + 1)) "$name bounded backoff"
    }
    Assert-DownloadTest (-not (Test-Path -LiteralPath "$script:destinationPath.partial")) "$name partial file leaked"
    if ($script:case.error) {
      Assert-DownloadTest ($failure -match $script:case.error) "$name missing expected failure: $failure"
      Assert-DownloadTest ((Get-Content -LiteralPath $script:destinationPath -Raw) -ceq 'previous-verified') "$name destroyed previous verified file"
    } else {
      Assert-DownloadTest (-not $failure) "$name unexpected failure: $failure"
      Assert-DownloadTest ((Get-FileHash -LiteralPath $script:destinationPath -Algorithm SHA256).Hash -ceq $hash) "$name published corrupt bytes"
    }
    $diagnostic = "$failure $($warnings -join ' ')"
    Assert-DownloadTest ($diagnostic -notmatch 'download-test-secret|signed-secret|https://asset.example') "$name leaked credentials"
    Write-Host "PASS $name"
  }
  Write-Host "Passed $($cases.Count) immutable download cases"
} finally {
  $env:GH_TOKEN = $originalToken
  if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
